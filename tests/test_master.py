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
        # a promoção pede duas assinaturas
        (st, r, _), p = self.env.sign_post(self.c, self.a, self.gid, self.dev, "set_role", {"id": self.g2, "role": "master"})
        self.assertEqual((st, r["status"]), (200, "awaiting"), r)
        self.assertEqual(self.role_of(self.c, self.g2), "admin")  # ainda não
        self.assertEqual(self.c2.call("POST", f"/v1/commands/{r['id']}/cosign", {"sig": self.a2.sign_command(self.g2, p)})[0], 200)
        self.assertEqual(self.role_of(self.c, self.g2), "master")
        # o mesmo pedido para o outro destino (já em andamento) continua valendo, mesmo com o gateway já promovido
        (st, r2, _), p2 = self.env.sign_post(self.c, self.a, self.gid, self.ex, "set_role", {"id": self.g2, "role": "master"})
        self.assertEqual((st, r2["status"]), (200, "awaiting"), r2)
        self.assertEqual(self.c2.call("POST", f"/v1/commands/{r2['id']}/cosign", {"sig": self.a2.sign_command(self.g2, p2)})[0], 200)

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


if __name__ == "__main__":
    unittest.main()
