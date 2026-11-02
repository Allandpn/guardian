"""Apresentar o mestre a um aparelho que ainda não conhece mestre nenhum (o caso do ALLANPC que "ainda não confia em Gandalf").

Depois que existe um mestre, só ele inclui guardiões. Mas o aparelho que não o conhece recusa o comando dele, e o guardião-mor era
barrado no gateway: ninguém levava o mestre até o aparelho. Agora o guardião-mor que o aparelho conhece pode apresentá-lo, e só isso.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import command, envelope  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.protocol import commands as cmds  # noqa: E402


class IntroduceMaster(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.c, self.a, self.h = self.env.register_guardian("Heimdall")        # guardião-mor, conhecido pelo PC
        self.c2, self.a2, self.g = self.env.register_guardian("Gandalf")
        self.env.store.set_role(self.g, "master")                               # mestre no gateway, desconhecido pelo PC
        self.key, self.dev = self.env.pair_device(self.c, name="ALLANPC")
        self.trust = self.c.call("GET", "/v1/me")[1]["trust"]
        self.report(trust={self.h: list(self.trust[self.h]["creds"])}, roles={self.h: "admin"})

    def tearDown(self):
        self.env.close()

    def report(self, **kw):
        st, r, _ = self.env.client().signed(self.key, "POST", f"/v1/devices/{self.dev}/report",
                                            {"kind": "device", "platform": "windows", "ts": int(time.time()), **kw})
        self.assertEqual(st, 200, r)

    def args(self, **over):
        g = self.trust[self.g]
        cred = next(iter(g["creds"]))
        return {"id": self.g, "name": g["name"], "cred": cred, "spki": g["creds"][cred], "role": "master",
                "allow_sync": g["allow_sync"], "window": g["window"], **over}

    def post(self, args, client=None, auth=None, gid=None, type_="add_guardian"):
        (st, r, _), _ = self.env.sign_post(client or self.c, auth or self.a, gid or self.h, self.dev, type_, args)
        return st, r

    def test_01_the_admin_the_device_knows_introduces_the_master(self):
        st, r = self.post(self.args())
        self.assertEqual((st, r.get("status")), (200, "ready"), r)

    def test_02_only_exactly_the_master_as_the_gateway_knows_him(self):
        g = self.trust[self.g]
        other = next(iter(self.trust[self.h]["creds"]))
        for over in ({"role": "admin"}, {"name": "Outro"}, {"window": {"days": [0], "from": 0, "to": 60, "utc_offset_min": 0}},
                     {"allow_sync": not g["allow_sync"]}, {"cred": other, "spki": self.trust[self.h]["creds"][other]},
                     {"spki": "QUFBQQ"}, {"id": self.h}):
            st, r = self.post(self.args(**over))
            self.assertEqual(st, 403, (over, r))

    def test_03_not_when_the_device_already_knows_a_master(self):
        self.report(trust={self.h: list(self.trust[self.h]["creds"]), "g_00000000": ["x"]}, roles={self.h: "admin", "g_00000000": "master"})
        st, r = self.post(self.args())
        self.assertEqual(st, 403, r)

    def test_04_not_by_someone_the_device_does_not_know_nor_for_other_guardians(self):
        self.report(trust={}, roles={})                                         # o PC não conhece o Heimdall
        self.assertEqual(self.post(self.args())[0], 403)
        self.report(trust={self.h: list(self.trust[self.h]["creds"])}, roles={self.h: "admin"})
        c3, a3, x = self.env.register_guardian("Comum")                        # incluir outro guardião continua só do mestre
        t3 = self.c.call("GET", "/v1/me")[1]["trust"][x]
        cred = next(iter(t3["creds"]))
        st, r = self.post({"id": x, "name": t3["name"], "cred": cred, "spki": t3["creds"][cred], "role": "admin",
                           "allow_sync": t3["allow_sync"], "window": t3["window"]})
        self.assertEqual(st, 403, r)

    def test_05_device_without_reported_roles_is_not_assumed_masterless(self):
        self.report(trust={self.h: list(self.trust[self.h]["creds"])})
        self.assertEqual(self.post(self.args())[0], 403)

    def test_06_the_device_accepts_it_and_then_obeys_the_master(self):
        """Do lado do aparelho (a mesma lógica no agente, no executor e no app): o guardião-mor apresenta, o mestre passa a mandar."""
        tr = cmds.Trust(self.env.cfg.rp_id, self.env.cfg.origin,
                        {self.h: cmds.Guardian("Heimdall", dict(self.trust[self.h]["creds"]), cmds.ROLE_ADMIN)})
        dev = cmds.Consumer(self.dev, tr)
        p = command(self.dev, self.h, 1, "add_guardian", self.args())
        v = dev.accept(envelope(p, self.a.sign_command(self.h, p)))
        dev.apply_trust(v.cmd)
        self.assertEqual(dev.trust.guardians[self.g].role, cmds.ROLE_MASTER)
        g2 = self.trust[self.g]
        cred2 = "Y3JlZDI"
        p = command(self.dev, self.g, 1, "add_credential", {"id": self.g, "cred": cred2, "spki": next(iter(g2["creds"].values()))})
        dev.apply_trust(dev.accept(envelope(p, self.a2.sign_command(self.g, p))).cmd)   # agora o mestre leva as outras passkeys
        self.assertIn(cred2, dev.trust.guardians[self.g].creds)
        p = command(self.dev, self.h, 2, "add_guardian", {**self.args(), "id": "g_11111111"})
        with self.assertRaises(cmds.CommandError):                               # e o guardião-mor volta a não incluir ninguém
            dev.accept(envelope(p, self.a.sign_command(self.h, p)))


if __name__ == "__main__":
    unittest.main()
