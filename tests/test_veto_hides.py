import unittest

from guardian.executor.veto import Veto


class MasterParentTest(unittest.TestCase):
    def test_master_parent_does_not_depend_on_the_gravity_index(self):
        v = Veto("/nao/existe/gravity.db", ["reddit.com"])
        self.assertTrue(v.reason("exemplo.com"))                      # liberar: sem índice, recusa às cegas
        self.assertEqual(v.master_parent("old.reddit.com"), "reddit.com")
        self.assertEqual(v.master_parent("reddit.com"), "reddit.com")
        self.assertIsNone(v.master_parent("exemplo.com"))
        self.assertIsNone(v.master_parent("notreddit.com"))


if __name__ == "__main__":
    unittest.main()
