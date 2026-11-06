import json
import os
import subprocess
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from gwharness import Env  # noqa: E402

BLOB = {"v": 1, "kdf": "PBKDF2-SHA256", "it": 600000, "salt": "c2FsdA", "iv": "aXZpdml2aXZpdg", "ct": "Y2lwaGVydGV4dA"}


class Vault(unittest.TestCase):
    """Cofre: o gateway só guarda o envelope cifrado pelo navegador, e só o mestre lê ou grava."""

    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.m, _, cls.mid = cls.env.register_guardian("Gandalf")
        cls.env.store.set_role(cls.mid, "master")
        cls.o, _, cls.oid = cls.env.register_guardian("Outro")
        cls.m2, _, cls.m2id = cls.env.register_guardian("Saruman")
        cls.env.store.set_role(cls.m2id, "master")

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def test_01_master_writes_and_reads_back_with_versions(self):
        st, r, _ = self.m.call("GET", "/v1/vault")
        self.assertEqual((st, r["ver"], r["blob"]), (200, 0, None))
        st, r, _ = self.m.call("POST", "/v1/vault", {"base": 0, "blob": BLOB})
        self.assertEqual((st, r["ver"]), (200, 1))
        st, r, _ = self.m.call("GET", "/v1/vault")
        self.assertEqual((r["ver"], r["blob"]), (1, BLOB))
        self.assertEqual(self.m.call("POST", "/v1/vault", {"base": 0, "blob": BLOB})[0], 409)  # outro navegador gravou antes
        self.assertEqual(self.m.call("POST", "/v1/vault", {"base": 1, "blob": {**BLOB, "ct": "bm92bw"}})[1]["ver"], 2)

    def test_01b_every_master_shares_the_same_vault(self):
        st, r, _ = self.m2.call("GET", "/v1/vault")
        self.assertEqual((st, r["ver"], r["blob"]), (200, 2, {**BLOB, "ct": "bm92bw"}))
        self.assertEqual(self.m2.call("POST", "/v1/vault", {"base": 2, "blob": BLOB})[1]["ver"], 3)
        self.assertEqual(self.m.call("GET", "/v1/vault")[1]["ver"], 3)
        self.assertEqual(self.m.call("POST", "/v1/vault", {"base": 2, "blob": BLOB})[0], 409)  # o primeiro mestre estava desatualizado
        self.assertEqual(self.m.call("POST", "/v1/vault", {"base": 3, "blob": BLOB})[1]["ver"], 4)

    def test_02_only_the_master(self):
        self.assertEqual(self.o.call("GET", "/v1/vault")[0], 403)
        self.assertEqual(self.o.call("POST", "/v1/vault", {"base": 0, "blob": BLOB})[0], 403)
        self.assertEqual(self.env.client().call("GET", "/v1/vault")[0], 401)

    def test_03_rejects_malformed_envelopes(self):
        for bad in ({**BLOB, "kdf": "MD5"}, {**BLOB, "it": 10}, {**BLOB, "v": 2}, {k: v for k, v in BLOB.items() if k != "iv"},
                    {**BLOB, "ct": ""}, {**BLOB, "ct": 5}, "texto", None):
            self.assertEqual(self.m.call("POST", "/v1/vault", {"base": 4, "blob": bad})[0], 400, bad)
        self.assertEqual(self.m.call("POST", "/v1/vault", {"base": True, "blob": BLOB})[0], 400)
        self.assertEqual(self.m.call("POST", "/v1/vault", {"base": 4, "blob": {**BLOB, "ct": "A" * (300 * 1024)}})[0], 413)

    def test_04_audit_never_holds_content(self):
        rows = [r["text"] for r in self.env.store.audit_list(50) if r["kind"] == "vault"]
        self.assertTrue(rows)
        self.assertFalse(any(BLOB["ct"] in t or BLOB["salt"] in t for t in rows))

    @unittest.skipUnless(shutil.which("node"), "node não instalado")
    def test_05_browser_crypto_roundtrip_wrong_phrase_and_tamper(self):
        out = subprocess.run(["node", os.path.join(os.path.dirname(__file__), "vault_cli.mjs")], capture_output=True, text=True, check=True, timeout=60).stdout
        r = json.loads(out)
        self.assertTrue(r["roundtrip"] and r["nfkc"] and r["freshIv"] and r["gen"] and r["openWith"])
        self.assertEqual((r["openWithOtherSalt"], r["openWithWrongKey"]), ("frase errada", "frase errada"))
        self.assertEqual((r["wrong"], r["tamper"], r["plainLeak"]), ("frase errada", "frase errada", False))


if __name__ == "__main__":
    unittest.main()
