import datetime
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import FakeAuthenticator, command, envelope  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.gateway.server import create_invite, describe_window  # noqa: E402
from guardian.protocol import b64, webauthn  # noqa: E402
from guardian.protocol.commands import (  # noqa: E402
    CommandError, Consumer, Guardian, Trust, check_window, in_window, verify_envelope)

RP, ORIGIN = "localhost", "http://localhost"
WORK = {"days": [0, 1, 2, 3, 4], "from": 12 * 60, "to": 17 * 60, "utc_offset_min": -180}


def at(y, m, d, h, mi=0, offset=-180):
    """Instante Unix de uma hora local (UTC-3 por padrão)."""
    return datetime.datetime(y, m, d, h, mi, tzinfo=datetime.timezone(datetime.timedelta(minutes=offset))).timestamp()


class WindowMath(unittest.TestCase):
    def test_work_hours(self):
        # 2026-10-14 é quarta-feira
        self.assertTrue(in_window(WORK, at(2026, 10, 14, 12, 0)))
        self.assertTrue(in_window(WORK, at(2026, 10, 14, 16, 59)))
        self.assertFalse(in_window(WORK, at(2026, 10, 14, 11, 59)))
        self.assertFalse(in_window(WORK, at(2026, 10, 14, 17, 0)))
        self.assertFalse(in_window(WORK, at(2026, 10, 14, 22, 30)))   # à noite, em casa
        self.assertFalse(in_window(WORK, at(2026, 10, 17, 14, 0)))    # sábado
        self.assertFalse(in_window(WORK, at(2026, 10, 18, 14, 0)))    # domingo
        self.assertTrue(in_window(None, at(2026, 10, 18, 3, 0)))      # sem janela: sempre

    def test_offset_is_applied(self):
        # 15h em Brasília (UTC-3) = 18h UTC: vale mesmo que o relógio do computador esteja em UTC
        self.assertTrue(in_window(WORK, at(2026, 10, 14, 18, 0, offset=0)))
        self.assertTrue(in_window(WORK, at(2026, 10, 14, 15, 0, offset=0)))   # 15h UTC = 12h em Brasília
        self.assertFalse(in_window(WORK, at(2026, 10, 14, 12, 0, offset=0)))  # 12h UTC = 9h em Brasília

    def test_validation(self):
        self.assertEqual(check_window(WORK), WORK)
        self.assertIsNone(check_window(None))
        for bad in ({}, {"days": [], "from": 0, "to": 10, "utc_offset_min": 0}, {"days": [7], "from": 0, "to": 10, "utc_offset_min": 0},
                    {"days": [1], "from": 600, "to": 600, "utc_offset_min": 0}, {"days": [1], "from": 0, "to": 1441, "utc_offset_min": 0},
                    {"days": [True], "from": 0, "to": 10, "utc_offset_min": 0}, {"days": [1], "from": 0, "to": 10, "utc_offset_min": 9999},
                    "x", {"days": "12345", "from": 0, "to": 10, "utc_offset_min": 0}):
            with self.assertRaises(CommandError, msg=repr(bad)):
                check_window(bad)

    def test_describe(self):
        self.assertEqual(describe_window(WORK), "seg–sex, 12h às 17h")


class ConsumerPolicy(unittest.TestCase):
    def setUp(self):
        self.mor, self.dom = FakeAuthenticator(RP, ORIGIN), FakeAuthenticator(RP, ORIGIN)
        self.sync = FakeAuthenticator(RP, ORIGIN, backup_eligible=True)
        self.trust = Trust(RP, ORIGIN, {
            "mor": Guardian("Allan", {self.mor.cred_id_b64: b64.enc(self.mor.spki)}, "admin", allow_sync=False, window=WORK),
            "ana": Guardian("Ana", {self.dom.cred_id_b64: b64.enc(self.dom.spki)}, "domains"),
        })

    def env(self, who, auth, type_="approve_app", args=None, ctr=1):
        p = command("dev1", who, ctr, type_, args or {"pkg": "x"})
        return envelope(p, auth.sign_command(who, p))

    def test_window_uses_the_consumers_clock(self):
        c = Consumer("dev1", self.trust)
        c.accept(self.env("mor", self.mor), now=at(2026, 10, 14, 14, 0))
        with self.assertRaisesRegex(CommandError, "janela"):
            c.accept(self.env("mor", self.mor, ctr=2), now=at(2026, 10, 14, 22, 0))     # à noite
        with self.assertRaisesRegex(CommandError, "janela"):
            c.accept(self.env("mor", self.mor, ctr=2), now=at(2026, 10, 17, 14, 0))     # sábado
        c.accept(self.env("ana", self.dom, "pihole_allow", {"domain": "a.example"}), now=at(2026, 10, 14, 23, 0))  # sem janela: sempre
        self.assertEqual(c.last_ctr.get("mor"), 1)  # o contador não anda quando recusa

    def test_synced_passkey_refused_when_guardian_is_device_only(self):
        # a mesma chave, mas o autenticador diz "posso ser copiado": recusada mesmo com assinatura perfeita
        self.sync.key, self.sync.cred_id = self.mor.key, self.mor.cred_id
        with self.assertRaisesRegex(CommandError, "sincroniz"):
            verify_envelope(self.trust, self.env("mor", self.sync), now=at(2026, 10, 14, 14, 0))
        verify_envelope(self.trust, self.env("mor", self.mor), now=at(2026, 10, 14, 14, 0))
        # quem permite sincronizar aceita as duas
        self.trust.guardians["mor"].allow_sync = True
        verify_envelope(self.trust, self.env("mor", self.sync), now=at(2026, 10, 14, 14, 0))

    def test_policy_roundtrips_and_is_set_only_when_the_guardian_is_added(self):
        c = Consumer("dev1", self.trust)
        j = json.loads(json.dumps(c.to_json()))
        t2 = Consumer.from_json(j).trust
        self.assertEqual((t2.guardians["mor"].allow_sync, t2.guardians["mor"].window), (False, WORK))
        self.assertEqual((t2.guardians["ana"].allow_sync, t2.guardians["ana"].window), (True, None))
        del j["trust"]["guardians"]["mor"]["allow_sync"], j["trust"]["guardians"]["mor"]["window"]  # pareamento antigo
        old = Consumer.from_json(j).trust.guardians["mor"]
        self.assertEqual((old.allow_sync, old.window), (True, None))
        new = FakeAuthenticator(RP, ORIGIN)
        args = {"id": "novo", "name": "Novo", "cred": new.cred_id_b64, "spki": b64.enc(new.spki), "role": "domains", "allow_sync": False, "window": WORK}
        c.apply_trust({"type": "add_guardian", "args": args})
        self.assertEqual((c.trust.guardians["novo"].allow_sync, c.trust.guardians["novo"].window), (False, WORK))
        for bad in ({**args, "id": "n2", "allow_sync": "no"}, {**args, "id": "n3", "window": {"days": []}}, {k: v for k, v in args.items() if k != "allow_sync"}):
            with self.assertRaises(CommandError):
                c.apply_trust({"type": "add_guardian", "args": bad})
        with self.assertRaises(CommandError):  # não existe comando para mudar a regra de um guardião que já existe
            c.apply_trust({"type": "add_guardian", "args": {**args, "allow_sync": True, "window": None}})

    def test_remove_credential(self):
        extra = FakeAuthenticator(RP, ORIGIN)
        c = Consumer("dev1", self.trust)
        c.apply_trust({"type": "add_credential", "args": {"id": "mor", "cred": extra.cred_id_b64, "spki": b64.enc(extra.spki)}})
        self.assertEqual(len(c.trust.guardians["mor"].creds), 2)
        c.apply_trust({"type": "remove_credential", "args": {"id": "mor", "cred": self.mor.cred_id_b64}})
        self.assertEqual(list(c.trust.guardians["mor"].creds), [extra.cred_id_b64])
        for bad in ({"id": "mor", "cred": extra.cred_id_b64}, {"id": "mor", "cred": "nao-existe"}, {"id": "ninguem", "cred": "x"}):
            with self.assertRaises(CommandError):  # a última passkey fica; o resto não existe
                c.apply_trust({"type": "remove_credential", "args": bad})
        # a passkey removida deixa de assinar
        with self.assertRaises(CommandError):
            verify_envelope(c.trust, self.env("mor", self.mor), now=at(2026, 10, 14, 14, 0))


class GatewayPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Allan")   # primeiro guardião-mor, sem regras

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def register(self, token, auth):
        c = self.env.client()
        st, o, _ = c.call("POST", "/v1/register/options", {"invite": token})
        if st != 200:
            return st, o, c
        reg = auth.register(b64.dec(o["publicKey"]["challenge"]))
        st, v, _ = c.call("POST", "/v1/register/verify", {"challengeId": o["challengeId"], **reg})
        return st, v, c

    def invite(self, **body):
        st, r, _ = self.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Trabalho", "role": "admin", **body})
        self.assertEqual(st, 200, r)
        return r["token"]

    def test_01_device_only_guardian_rejects_a_synced_passkey_and_keeps_the_invite(self):
        tok = self.invite(allow_sync=False, window=WORK)
        st, o, _ = self.env.client().call("POST", "/v1/register/options", {"invite": tok})
        self.assertEqual((st, o["allow_sync"], o["publicKey"]["hints"]), (200, False, ["client-device"]))
        st, v, _ = self.register(tok, FakeAuthenticator(RP, self.env.cfg.origin, backup_eligible=True))
        self.assertEqual(st, 400)
        self.assertIn("sincronizada", v["error"])
        st, v, wc = self.register(tok, FakeAuthenticator(RP, self.env.cfg.origin))   # o convite continua valendo
        self.assertEqual(st, 200, v)
        me = self.c.call("GET", "/v1/me")[1]
        g = me["trust"][v["guardian"]["id"]]
        self.assertEqual((g["allow_sync"], g["window"], g["role"]), (False, WORK, "admin"))
        self.assertFalse(any(i["be"] for c, i in me["cred_info"].items() if c in g["creds"]))

    def test_02_invite_validation(self):
        for bad in ({"allow_sync": "nao"}, {"window": {"days": []}}, {"window": {"days": [1], "from": 700, "to": 600, "utc_offset_min": 0}}):
            st, r, _ = self.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "X", **bad})
            self.assertEqual(st, 400, bad)

    def test_03_synced_guardian_accepts_synced_and_new_passkeys_inherit_the_rule(self):
        st, v, wc = self.register(self.invite(allow_sync=True), FakeAuthenticator(RP, self.env.cfg.origin, backup_eligible=True))
        self.assertEqual(st, 200, v)
        me = self.c.call("GET", "/v1/me")[1]
        self.assertTrue(me["cred_info"][v["cred"]]["be"])
        # passkey extra de um guardião "só neste aparelho" também precisa ser presa ao aparelho
        st, v2, wc2 = self.register(self.invite(allow_sync=False), FakeAuthenticator(RP, self.env.cfg.origin))
        self.assertEqual(st, 200, v2)
        st, inv, _ = wc2.call("POST", "/v1/invites", {"kind": "add_passkey"})
        self.assertEqual(st, 200, inv)
        st, r, _ = self.register(inv["token"], FakeAuthenticator(RP, self.env.cfg.origin, backup_eligible=True))
        self.assertEqual(st, 400)

    def test_04_login_and_requests_only_inside_the_window(self):
        today = datetime.datetime.now(datetime.timezone.utc).weekday()
        never = {"days": [(today + 3) % 7], "from": 0, "to": 1440, "utc_offset_min": 0}
        always = {"days": list(range(7)), "from": 0, "to": 1440, "utc_offset_min": 0}
        auth = FakeAuthenticator(RP, self.env.cfg.origin)
        st, v, wc = self.register(self.invite(window=never), auth)   # registrar não exige a janela
        self.assertEqual(st, 200, v)
        st, me, _ = wc.call("GET", "/v1/me")
        self.assertEqual(st, 403)
        self.assertIn("janela", me["error"])
        c2 = self.env.client()
        st, o, _ = c2.call("POST", "/v1/auth/options", {})
        st, r, _ = c2.call("POST", "/v1/auth/verify", {"challengeId": o["challengeId"], **auth.assert_(b64.dec(o["publicKey"]["challenge"]))})
        self.assertEqual(st, 403)
        self.assertIn("janela", r["error"])
        st, v, wc = self.register(self.invite(window=always), FakeAuthenticator(RP, self.env.cfg.origin))
        self.assertEqual(st, 200, v)
        self.assertEqual(wc.call("GET", "/v1/me")[0], 200)

    def test_05_window_closing_ends_the_session_and_blocks_commands(self):
        always = {"days": list(range(7)), "from": 0, "to": 1440, "utc_offset_min": 0}
        today = datetime.datetime.now(datetime.timezone.utc).weekday()
        never = {"days": [(today + 3) % 7], "from": 0, "to": 1440, "utc_offset_min": 0}
        a1 = FakeAuthenticator(RP, self.env.cfg.origin)
        st, v, c1 = self.register(self.invite(window=always), a1)
        gid = v["guardian"]["id"]
        key, dev = self.env.pair_device(c1, kind="executor", name="Pi-hole")
        (st, r, _), _ = self.env.sign_post(c1, a1, gid, dev, "pihole_allow", {"domain": "ok.example"})
        self.assertEqual((st, r.get("status")), (200, "ready"))
        self.env.srv.gw.store.x("UPDATE guardians SET window=? WHERE id=?", (json.dumps(never), gid))  # "a janela fechou"
        self.assertEqual(c1.call("GET", "/v1/me")[0], 403)
        self.assertEqual(c1.call("GET", "/v1/devices")[0], 403)
        self.assertEqual(c1.call("POST", f"/v1/devices/{dev}/commands", {})[0], 403)

    def test_06_remove_credential_endpoint(self):
        a1 = FakeAuthenticator(RP, self.env.cfg.origin)
        st, v, c1 = self.register(self.invite(role="domains"), a1)
        gid = v["guardian"]["id"]
        st, inv, _ = c1.call("POST", "/v1/invites", {"kind": "add_passkey"})
        a2 = FakeAuthenticator(RP, self.env.cfg.origin)
        self.assertEqual(self.register(inv["token"], a2)[0], 200)
        path = f"/v1/guardians/{gid}/credentials/remove"
        self.assertEqual(c1.call("POST", path, {"cred": a1.cred_id_b64})[0], 403)           # só o guardião-mor
        self.assertEqual(self.c.call("POST", path, {"cred": "nao-existe"})[0], 400)
        self.assertEqual(self.c.call("POST", path, {"cred": a1.cred_id_b64})[0], 200)
        self.assertEqual(self.c.call("POST", path, {"cred": a2.cred_id_b64})[0], 400)      # a última fica
        creds = self.c.call("GET", "/v1/me")[1]["trust"][gid]["creds"]
        self.assertEqual(list(creds), [a2.cred_id_b64])


if __name__ == "__main__":
    unittest.main()
