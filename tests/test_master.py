import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from gwharness import Env  # noqa: E402


class MasterRole(unittest.TestCase):
    """Guardião-mestre no gateway: nasce por promoção (modo antigo, duas assinaturas) e depois só ele mexe em guardiões."""

    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Allan")
        cls.c2, cls.a2, cls.g2 = cls.env.register_guardian("Gandalf")
        cls.devkey, cls.dev = cls.env.pair_device(cls.c, name="Tablet")
        cls.exkey, cls.ex = cls.env.pair_device(cls.c, kind="executor", name="Pi-hole")

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def role_of(self, client, gid):
        return client.call("GET", "/v1/me")[1]["trust"][gid]["role"]

    def test_01_promotion_then_only_the_master_manages_guardians(self):
        self.assertEqual(self.role_of(self.c, self.g2), "admin")
        # sem mestre, o modo antigo: convidar vale para o guardião-mor
        self.assertEqual(self.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Teste"})[0], 200)
        # o primeiro mestre nasce com uma assinatura
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, "set_role", {"id": self.g2, "role": "master"})
        self.assertEqual((st, r["status"]), (200, "ready"), r)
        self.assertEqual(self.role_of(self.c, self.g2), "master")
        # o mesmo pedido para o outro destino (que ainda não aplicou) continua valendo, mesmo com o gateway já promovido
        (st, r2, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.ex, "set_role", {"id": self.g2, "role": "master"})
        self.assertEqual((st, r2["status"]), (200, "ready"), r2)

        # agora o guardião-mor não convida, não remove e não manda comando de guardiões
        self.assertEqual(self.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "X"})[0], 403)
        self.assertEqual(self.c.call("POST", f"/v1/guardians/{self.g2}/remove", {})[0], 403)
        self.assertEqual(self.c.call("POST", f"/v1/guardians/{self.g2}/credentials/remove", {"cred": "x"})[0], 403)
        for t, args in (("remove_guardian", {"id": self.g2}), ("add_guardian", {"id": "g_00000000", "name": "Z", "cred": "c", "spki": "s", "role": "admin", "allow_sync": True}),
                        ("set_role", {"id": self.gid, "role": "master"})):
            (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, t, args)
            self.assertEqual(st, 403, (t, r))
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, "remove_guardian", {"id": self.g2}, extra_signers=[(self.g2, self.a2)])
        self.assertEqual(st, 403, r)  # nem com a assinatura do mestre junto
        self.assertEqual(self.c.call("POST", "/v1/pairings", {"kind": "device"})[0], 200)  # o resto continua dele
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, "set_config", {"patch": {}})
        self.assertEqual((st, r["status"]), (200, "ready"), r)

        # o mestre convida (inclusive outro mestre) e remove sozinho, mas não a si mesmo
        self.assertEqual(self.c2.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Reserva", "role": "master"})[0], 200)
        self.assertEqual(self.c2.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Mor", "role": "admin"})[0], 200)
        self.assertEqual(self.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "M", "role": "master"})[0], 403)
        (st, r, _), _ = self.env.sign_post(self.c2, self.a2, self.g2, self.dev, "remove_guardian", {"id": self.gid})
        self.assertEqual((st, r["status"]), (200, "ready"), r)  # uma assinatura basta
        self.assertEqual(self.c2.call("POST", f"/v1/guardians/{self.g2}/remove", {})[0], 400)  # nem o último mestre
        self.assertEqual(self.c2.call("POST", f"/v1/guardians/{self.gid}/remove", {})[0], 200)

    def test_02_master_demotes_but_never_the_last_master(self):
        c3, a3, g3 = self.env.register_guardian("Reserva")  # entra como guardião-mor (convite padrão)
        # o mestre (Gandalf) rebaixa um guardião-mor a guardião, sozinho
        (st, r, _), _ = self.env.sign_post(self.c2, self.a2, self.g2, self.dev, "set_role", {"id": g3, "role": "domains"})
        self.assertEqual((st, r["status"]), (200, "ready"), r)
        self.assertEqual(self.role_of(self.c2, g3), "domains")
        self.assertEqual(c3.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "X"})[0], 403)
        # promove de volta e rebaixa o mestre a guardião-mor: o último mestre fica
        for role in ("admin", "master"):
            (st, r, _), _ = self.env.sign_post(self.c2, self.a2, self.g2, self.dev, "set_role", {"id": g3, "role": role})
            self.assertEqual(st, 200, r)
        self.assertEqual(self.role_of(self.c2, g3), "master")
        (st, r, _), _ = self.env.sign_post(self.c2, self.a2, self.g2, self.dev, "set_role", {"id": self.g2, "role": "admin"})
        self.assertEqual(st, 200, r)  # existem dois mestres: pode
        self.assertEqual(self.role_of(c3, self.g2), "admin")
        (st, r, _), _ = self.env.sign_post(c3, a3, g3, self.dev, "set_role", {"id": g3, "role": "domains"})
        self.assertEqual(st, 200, r)  # o mestre que sobrou tenta se rebaixar: o gateway não aplica
        self.assertEqual(self.role_of(c3, g3), "master")


if __name__ == "__main__":
    unittest.main()
