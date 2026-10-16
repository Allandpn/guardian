import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from gwharness import Env  # noqa: E402
from guardian.gateway.server import create_invite  # noqa: E402
from guardian.protocol import b64  # noqa: E402


def register(env, token):
    a, c = env.auth(), env.client()
    st, o, _ = c.call("POST", "/v1/register/options", {"invite": token})
    assert st == 200, o
    reg = a.register(b64.dec(o["publicKey"]["challenge"]))
    st, v, _ = c.call("POST", "/v1/register/verify", {"challengeId": o["challengeId"], **reg})
    assert st == 200, v
    return c, a, v["guardian"]["id"]


class Roles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        # o primeiro guardião é sempre guardião-mor, mesmo com convite de outro papel
        cls.c, cls.a, cls.gid = register(cls.env, create_invite(cls.env.store, "new_guardian", None, "Allan", 3600, "domains"))
        st, inv, _ = cls.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Ana"})  # padrão: domínios
        assert st == 200, inv
        cls.dc, cls.da, cls.dgid = register(cls.env, inv["token"])
        cls.devkey, cls.dev = cls.env.pair_device(cls.c)
        cls.exkey, cls.ex = cls.env.pair_device(cls.c, kind="executor", name="Pi-hole")
        cls.env.client().signed(cls.devkey, "POST", f"/v1/devices/{cls.dev}/report", {
            "kind": "device", "filterActive": True, "snapshot": {"x": "1"}, "pendingApps": [{"pkg": "p"}], "trust": {}, "ctrs": {}})

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def test_01_roles_in_me_and_trust(self):
        me = self.c.call("GET", "/v1/me")[1]
        self.assertEqual(me["guardian"]["role"], "admin")
        self.assertEqual(me["trust"][self.dgid]["role"], "domains")
        dme = self.dc.call("GET", "/v1/me")[1]
        self.assertEqual(dme["guardian"]["role"], "domains")
        self.assertEqual(dme["guardian"]["see"], {"devices": False, "rules": False, "apps": False, "history": False})

    def test_02_domain_guardian_cannot_administer(self):
        self.assertEqual(self.dc.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "X"})[0], 403)
        self.assertEqual(self.dc.call("POST", "/v1/invites", {"kind": "add_passkey"})[0], 200)  # passkey para si
        self.assertEqual(self.dc.call("POST", "/v1/pairings", {"kind": "device"})[0], 403)
        self.assertEqual(self.dc.call("POST", f"/v1/devices/{self.dev}/forget", {})[0], 403)
        self.assertEqual(self.dc.call("POST", f"/v1/guardians/{self.gid}/remove", {})[0], 403)
        self.assertEqual(self.dc.call("GET", "/v1/commands/awaiting")[1]["commands"], [])
        (st, r, _), _ = self.env.sign_post(self.dc, self.da, self.dgid, self.dev, "approve_app", {"pkg": "x"})
        self.assertEqual((st, r.get("status")), (200, "ready"))  # aprovar app: o guardião comum também pode
        (st, r, _), _ = self.env.sign_post(self.dc, self.da, self.dgid, self.dev, "revoke_app", {"pkg": "x"})
        self.assertEqual(st, 403, r)  # revogar continua só do guardião-mor
        (st, r, _), _ = self.env.sign_post(self.dc, self.da, self.dgid, self.ex, "pihole_allow", {"domain": "a.com"})
        self.assertEqual((st, r.get("status")), (200, "ready"))

    def test_03_visibility_is_set_by_admin(self):
        def dev_view():
            return next(d for d in self.dc.call("GET", "/v1/devices")[1]["devices"] if d["id"] == self.dev)
        self.assertNotIn("snapshot", dev_view()["report"] or {})  # sem liberação: só os apps pendentes (o guardião aprova e recusa)
        self.assertNotIn("filterActive", dev_view()["report"] or {})
        self.assertEqual(self.dc.call("POST", f"/v1/guardians/{self.dgid}/see", {"devices": True})[0], 403)
        self.assertEqual(self.c.call("POST", f"/v1/guardians/{self.gid}/see", {"devices": True})[0], 404)  # admin vê tudo
        self.assertEqual(self.c.call("POST", f"/v1/guardians/{self.dgid}/see", {"devices": True})[0], 200)
        r = dev_view()["report"]
        self.assertTrue(r["filterActive"])
        self.assertNotIn("snapshot", r)
        self.c.call("POST", f"/v1/guardians/{self.dgid}/see", {"devices": True, "rules": True, "apps": True})
        r = dev_view()["report"]
        self.assertIn("snapshot", r)
        self.assertIn("pendingApps", r)
        self.assertNotIn("trust", r)
        ex = next(d for d in self.dc.call("GET", "/v1/devices")[1]["devices"] if d["id"] == self.ex)
        self.assertEqual(ex["kind"], "executor")

    def test_03b_guardian_refuses_and_reconsiders_a_pending_app(self):
        def refuse(body, who=None):
            return (who or self.dc).call("POST", f"/v1/devices/{self.dev}/apps/refuse", body)
        def refused():
            return next(d for d in self.dc.call("GET", "/v1/devices")[1]["devices"] if d["id"] == self.dev)["refused"]
        self.assertEqual(refuse({"pkg": "com.exemplo.jogo"})[0], 200)
        self.assertEqual(refused(), ["com.exemplo.jogo"])
        self.assertEqual(refuse({"pkg": "../x"})[0], 400)
        self.assertEqual(refuse({"pkg": "com.exemplo.jogo", "undo": True})[0], 200)
        self.assertEqual(refused(), [])
        self.assertEqual(self.env.client().call("POST", f"/v1/devices/{self.dev}/apps/refuse", {"pkg": "a.b"})[0], 401)
        self.assertEqual(self.dc.call("POST", f"/v1/devices/{self.ex}/apps/refuse", {"pkg": "a.b"})[0], 404)  # só aparelho, não o executor

    def test_04_history_filtered_unless_allowed(self):
        self.c.call("POST", f"/v1/guardians/{self.dgid}/see", {"history": False})
        rows = self.dc.call("GET", "/v1/audit")[1]["items"]
        self.assertTrue(rows)
        self.assertTrue(all(r["dev"] == self.ex or r["kind"] == "request" for r in rows), rows)
        self.c.call("POST", f"/v1/guardians/{self.dgid}/see", {"history": True})
        self.assertTrue(any(r["dev"] == self.dev for r in self.dc.call("GET", "/v1/audit")[1]["items"]))

    def test_05_admin_removes_domain_guardian_and_never_himself(self):
        self.assertEqual(self.c.call("POST", f"/v1/guardians/{self.gid}/remove", {})[0], 400)
        self.assertEqual(self.c.call("POST", f"/v1/guardians/{self.dgid}/remove", {})[0], 200)
        self.assertEqual(self.dc.call("GET", "/v1/me")[0], 401)  # sessão derrubada na hora
        self.assertNotIn(self.dgid, self.c.call("GET", "/v1/me")[1]["trust"])


if __name__ == "__main__":
    unittest.main()
