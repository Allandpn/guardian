import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from gwharness import Env  # noqa: E402


class BlockedEachDevice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.k1, cls.d1 = cls.env.pair_device(cls.c)
        cls.k2, cls.d2 = cls.env.pair_device(cls.c)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def test_a_noisy_device_does_not_push_the_others_out(self):
        now = int(time.time())
        row = lambda i, n: {"domain": f"d{i}.{n}.example", "src": "own", "list": "", "cname": 0, "count": 1, "first": now - i, "last": now - i}
        self.env.store.merge_blocked(self.d1, [row(i, "barulho") for i in range(900)])
        self.env.store.merge_blocked(self.d2, [row(i + 1000, "quieto") for i in range(5)])  # mais antigos que os do outro
        st, r, _ = self.c.call("GET", "/v1/blocked")
        self.assertEqual(st, 200)
        by = {}
        for i in r["items"]:
            by[i["dev"]] = by.get(i["dev"], 0) + 1
        self.assertEqual(by[self.d2], 5)             # o quieto aparece inteiro
        self.assertEqual(by[self.d1], 300)           # o barulhento é limitado por aparelho
        st, r, _ = self.c.call("GET", f"/v1/blocked?dev={self.d2}")
        self.assertEqual(len(r["items"]), 5)


if __name__ == "__main__":
    unittest.main()
