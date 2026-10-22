import unittest

from guardian.executor.veto import Veto


class HidesTest(unittest.TestCase):
    def test_unreadable_gravity_refuses_release_but_hides_nothing(self):
        v = Veto("/nao/existe/gravity.db", ["reddit.com"])
        self.assertTrue(v.reason("exemplo.com"))        # liberar: recusa às cegas
        self.assertFalse(v.hides("exemplo.com"))        # lista de bloqueados: continua mostrando
        self.assertTrue(v.hides("old.reddit.com"))      # veto do mestre não depende do índice


if __name__ == "__main__":
    unittest.main()
