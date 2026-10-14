import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import command, envelope  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.protocol import b64, devauth  # noqa: E402


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.key, cls.dev = cls.env.pair_device(cls.c)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def test_static_and_headers(self):
        c = self.env.client()
        st, _, r = c.call("GET", "/healthz")
        self.assertEqual(st, 200)
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(c.call("GET", "/nada")[0], 404)
        self.assertEqual(c.call("POST", "/healthz", {})[0], 404)

    def test_requires_login_and_origin(self):
        c = self.env.client()
        self.assertEqual(c.call("GET", "/v1/devices")[0], 401)
        self.assertEqual(c.call("GET", "/v1/me")[0], 401)
        st, _, _ = self.c.call("POST", "/v1/pairings", {"kind": "device"}, origin=False)
        self.assertEqual(st, 403)

    def test_login_with_passkey(self):
        c = self.env.client()
        st, o, _ = c.call("POST", "/v1/auth/options", {})
        self.assertEqual(st, 200)
        asn = self.a.assert_(b64.dec(o["publicKey"]["challenge"]))
        st, v, _ = c.call("POST", "/v1/auth/verify", {"challengeId": o["challengeId"], **asn})
        self.assertEqual(st, 200, v)
        self.assertEqual(c.call("GET", "/v1/me")[1]["guardian"]["id"], self.gid)
        # o desafio é de uso único
        self.assertEqual(c.call("POST", "/v1/auth/verify", {"challengeId": o["challengeId"], **asn})[0], 400)
        c.call("POST", "/v1/auth/logout", {})
        self.assertEqual(c.call("GET", "/v1/me")[0], 401)

    def test_login_with_unknown_passkey_fails(self):
        c = self.env.client()
        st, o, _ = c.call("POST", "/v1/auth/options", {})
        stranger = self.env.auth()
        asn = stranger.assert_(b64.dec(o["publicKey"]["challenge"]))
        self.assertEqual(c.call("POST", "/v1/auth/verify", {"challengeId": o["challengeId"], **asn})[0], 401)

    def test_invite_is_single_use(self):
        from guardian.gateway.server import create_invite
        token = create_invite(self.env.store, "new_guardian", None, "Bia", 3600)
        c, a = self.env.client(), self.env.auth()
        st, o, _ = c.call("POST", "/v1/register/options", {"invite": token})
        reg = a.register(b64.dec(o["publicKey"]["challenge"]))
        self.assertEqual(c.call("POST", "/v1/register/verify", {"challengeId": o["challengeId"], **reg})[0], 200)
        self.assertEqual(c.call("POST", "/v1/register/options", {"invite": token})[0], 400)
        self.assertEqual(self.env.client().call("POST", "/v1/register/options", {"invite": "lixo"})[0], 400)

    def test_pairing_and_device_report(self):
        st, l, _ = self.c.call("GET", "/v1/devices")
        self.assertEqual(st, 200)
        self.assertIn(self.dev, [d["id"] for d in l["devices"]])
        client = self.env.client()
        st, _, _ = client.signed(self.key, "POST", f"/v1/devices/{self.dev}/report",
                                 {"filterActive": True, "ctrs": {}, "executed": [{"type": "approve_app", "ok": True, "msg": "x"}]})
        self.assertEqual(st, 200)
        dev = [d for d in self.c.call("GET", "/v1/devices")[1]["devices"] if d["id"] == self.dev][0]
        self.assertTrue(dev["report"]["filterActive"])
        self.assertNotIn("executed", dev["report"])
        audit = self.c.call("GET", "/v1/audit")[1]["items"]
        self.assertTrue(any(i["kind"] == "executed" and "approve_app ok" in i["text"] for i in audit))

    def test_pairing_token_single_use_and_wrong_key(self):
        st, p, _ = self.c.call("POST", "/v1/pairings", {"kind": "device"})
        key = devauth.new_private_key()
        spki = devauth.spki_of(key)
        body = {"pairing": p["token"], "pubkey": b64.enc(spki), "name": "X", "kind": "device"}
        other = devauth.new_private_key()
        self.assertEqual(self.env.client().signed(other, "POST", "/v1/devices/register", body)[0], 401)  # sem posse da chave
        self.assertEqual(self.env.client().signed(key, "POST", "/v1/devices/register", body)[0], 200)
        body2 = dict(body, pubkey=b64.enc(devauth.spki_of(devauth.new_private_key())))
        k3 = devauth.new_private_key()
        body2["pubkey"] = b64.enc(devauth.spki_of(k3))
        self.assertEqual(self.env.client().signed(k3, "POST", "/v1/devices/register", body2)[0], 403)  # token já usado
        bad = dict(body, pairing="inexistente", pubkey=b64.enc(devauth.spki_of(k3)))
        self.assertEqual(self.env.client().signed(k3, "POST", "/v1/devices/register", bad)[0], 403)

    def test_device_auth_failures(self):
        c = self.env.client()
        path = f"/v1/devices/{self.dev}/commands?after=0&wait=0"
        self.assertEqual(c.call("GET", path)[0], 401)
        self.assertEqual(c.signed(devauth.new_private_key(), "GET", path)[0], 401)  # outra chave
        self.assertEqual(c.signed(self.key, "GET", path, nonce="repetido-123")[0], 200)
        self.assertEqual(c.signed(self.key, "GET", path, nonce="repetido-123")[0], 401)  # replay
        old = devauth.headers(self.key, "GET", path, b"", int(time.time()) - 4000, "nonce-antigo-1")
        self.assertEqual(c.call("GET", path, headers=old)[0], 401)  # relógio fora da janela
        self.assertEqual(c.signed(self.key, "GET", "/v1/devices/aaaaaaaaaaaaaaaaaaaa/commands")[0], 404)

    def test_command_flow_and_longpoll(self):
        c = self.env.client()
        base = f"/v1/devices/{self.dev}/commands"
        (st, r, _), p = self.env.sign_post(self.c, self.a, self.gid, self.dev, "approve_app", {"pkg": "com.x"})
        self.assertEqual(st, 200, r)
        st, got, _ = c.signed(self.key, "GET", f"{base}?after=0&wait=0")
        ids = [x["id"] for x in got["commands"]]
        self.assertIn(r["id"], ids)
        last = got["next"]
        # long-poll acorda quando entra comando novo
        out = {}

        def poll():
            out["r"] = self.env.client().signed(self.key, "GET", f"{base}?after={last}&wait=10")

        t = threading.Thread(target=poll)
        t.start()
        time.sleep(0.5)
        t0 = time.time()
        (st2, r2, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, "approve_app", {"pkg": "com.y"})
        t.join(8)
        self.assertEqual(st2, 200)
        self.assertLess(time.time() - t0, 5)
        self.assertEqual([x["id"] for x in out["r"][1]["commands"]], [r2["id"]])

    def test_command_rejections(self):
        n = self.c.call("GET", f"/v1/devices/{self.dev}/ctr")[1]["next"]
        path = f"/v1/devices/{self.dev}/commands"
        p = command(self.dev, self.gid, n, "approve_app")
        # tipo que não existe / destino errado / autor errado / sem assinatura / assinatura de outro
        for payload, sigs in (
            (command(self.dev, self.gid, n, "apagar_tudo"), None),
            (command("aaaaaaaaaaaaaaaaaaaa", self.gid, n, "approve_app"), None),
            (command(self.dev, "g_outro", n, "approve_app"), None),
        ):
            sig = [self.a.sign_command(self.gid, payload)]
            self.assertEqual(self.c.call("POST", path, envelope(payload, *sig))[0], 400)
        self.assertEqual(self.c.call("POST", path, envelope(p))[0], 400)
        stranger = self.env.auth()
        self.assertEqual(self.c.call("POST", path, envelope(p, stranger.sign_command(self.gid, p)))[0], 400)
        # tipo do executor não vale para aparelho
        pe = command(self.dev, self.gid, n, "pihole_allow", {"domain": "a.com"})
        self.assertEqual(self.c.call("POST", path, envelope(pe, self.a.sign_command(self.gid, pe)))[0], 400)
        # ok e depois replay do contador
        self.assertEqual(self.c.call("POST", path, envelope(p, self.a.sign_command(self.gid, p)))[0], 200)
        self.assertEqual(self.c.call("POST", path, envelope(p, self.a.sign_command(self.gid, p)))[0], 409)

    def test_two_signature_command_with_cosign(self):
        from guardian.gateway.server import create_invite
        c2, a2, g2 = self.env.register_guardian("Bia")
        key, dev = self.env.pair_device(self.c, name="Celular")
        trust = self.c.call("GET", "/v1/me")[1]["trust"]
        self.assertIn(g2, trust)
        (st, r, _), p = self.env.sign_post(self.c, self.a, self.gid, dev, "remove_guardian", {"id": g2})
        self.assertEqual((st, r["status"]), (200, "awaiting"), r)
        cl = self.env.client()
        self.assertEqual(cl.signed(key, "GET", f"/v1/devices/{dev}/commands?after=0&wait=0")[1]["commands"], [])
        aw = c2.call("GET", "/v1/commands/awaiting")[1]["commands"]
        mine = [x for x in aw if x["id"] == r["id"]][0]
        self.assertTrue(mine["can_cosign"])
        self.assertFalse([x for x in self.c.call("GET", "/v1/commands/awaiting")[1]["commands"] if x["id"] == r["id"]][0]["can_cosign"])
        # quem já assinou não co-assina; assinatura errada não vale
        self.assertEqual(self.c.call("POST", f"/v1/commands/{r['id']}/cosign", {"sig": self.a.sign_command(self.gid, p)})[0], 400)
        self.assertEqual(c2.call("POST", f"/v1/commands/{r['id']}/cosign", {"sig": self.env.auth().sign_command(g2, p)})[0], 400)
        self.assertEqual(c2.call("POST", f"/v1/commands/{r['id']}/cosign", {"sig": a2.sign_command(g2, p)})[0], 200)
        got = cl.signed(key, "GET", f"/v1/devices/{dev}/commands?after=0&wait=0")[1]["commands"]
        self.assertEqual([x["id"] for x in got], [r["id"]])
        self.assertEqual(len(got[0]["envelope"]["sigs"]), 2)

    def test_executor_kind_gets_executor_commands(self):
        ekey, edev = self.env.pair_device(self.c, kind="executor", name="Pi")
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, edev, "pihole_allow", {"domain": "ok.example"})
        self.assertEqual(st, 200, r)
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, edev, "approve_app", {"pkg": "x"})
        self.assertEqual(st, 400)

    def test_limits(self):
        c = self.env.client()
        big = b"x" * (20 * 1024)
        self.assertEqual(self.c.call("POST", f"/v1/devices/{self.dev}/commands", raw=big)[0], 413)
        self.assertEqual(c.call("POST", "/v1/auth/options", raw=b"{", headers={"Transfer-Encoding": "chunked"})[0], 411)
        self.assertEqual(c.call("PUT", "/v1/devices")[0], 405)
        self.assertEqual(c.call("POST", "/v1/register/options", raw=b"[]")[0], 400)

    def test_rate_limits_with_real_values(self):
        env = Env(limit_scale=1.0)
        try:
            c = env.client()
            codes = [c.call("POST", "/v1/auth/options", {})[0] for _ in range(30)]
            self.assertEqual(codes[0], 200)
            self.assertIn(429, codes)
            # a tentativa de login não derruba as rotas já limitadas por outro balde: o IP segue limitado
            codes = [env.client().call("GET", "/healthz")[0] for _ in range(80)]
            self.assertIn(429, codes)
        finally:
            env.close()

    def test_user_requests(self):
        st, _, _ = self.env.client().signed(self.key, "POST", f"/v1/devices/{self.dev}/requests",
                                            {"kind": "domain", "text": "exemplo.com"})
        self.assertEqual(st, 200)
        items = self.c.call("GET", "/v1/requests")[1]["items"]
        self.assertTrue(any(i["text"] == "exemplo.com" for i in items))
        self.assertEqual(self.c.call("POST", f"/v1/requests/{items[0]['id']}/dismiss", {})[0], 200)
        self.assertEqual(self.env.client().signed(self.key, "POST", f"/v1/devices/{self.dev}/requests",
                                                  {"kind": "x", "text": "y"})[0], 400)


if __name__ == "__main__":
    unittest.main()
