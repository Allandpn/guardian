import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.executor import domains  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, pair  # noqa: E402
from test_executor import pairing_string  # noqa: E402


class RegexShape(unittest.TestCase):
    def test_roundtrip_and_only_the_domain_and_its_subdomains_match(self):
        r = domains.to_regex("API.itau.com.br")
        self.assertEqual(r, r"^([a-zA-Z0-9-]+\.)*api\.itau\.com\.br$")
        self.assertEqual(domains.from_regex(r), "api.itau.com.br")
        rx = re.compile(r)
        for ok in ("api.itau.com.br", "x.api.itau.com.br", "a.b.api.itau.com.br", "X-1.api.itau.com.br"):
            self.assertTrue(rx.match(ok), ok)
        for no in ("itau.com.br", "www.itau.com.br", "apixitau.com.br", "evil-api.itau.com.br", "api.itau.com.br.evil.com", "api.itau.combr"):
            self.assertFalse(rx.match(no), no)

    def test_hand_written_rules_are_never_recognized(self):
        for r in (r"^([a-zA-Z0-9-]+\.)*itau.com.br", r"^([a-zA-Z0-9-]+\.)*itau\.com\.br", r".*", r"^([a-zA-Z0-9-]+\.)*itau\.com\.br$$",
                  r"^([a-zA-Z0-9-]+\.)*\.\.com$", r"(^([a-zA-Z0-9-]+\.)*itau\.com\.br$)", "", None, 5):
            self.assertIsNone(domains.from_regex(r), r)


class RegexAllow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.fake = FakePihole()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cfg = ExecConfig(cls.tmp.name, cls.fake.url, "senha-app", "canario.exemplo.com", allow_mode="regex")
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "executor"})
        pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]))
        cls.now = [1_000_000.0]
        cls.ex = Executor(cls.cfg, now=lambda: cls.now[0])
        cls.dev = cls.ex.dev
        cls.mine = r"^([a-zA-Z0-9-]+\.)*itau.com.br"   # regra do próprio usuário (à mão): nunca é tocada
        cls.fake.regex["deny"][cls.mine] = "meu"

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.fake.close()
        cls.tmp.cleanup()

    def send(self, type_, args=None):
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, type_, args)
        self.assertEqual(st, 200, r)
        self.ex.step(wait_s=0)

    def test_01_allow_is_stored_as_regex_and_listed_as_plain_domain(self):
        self.send("pihole_allow", {"domain": "api.itau.com.br"})
        self.assertEqual(self.fake.lists["allow"], {})
        self.assertIn(r"^([a-zA-Z0-9-]+\.)*api\.itau\.com\.br$", self.fake.regex["allow"])
        self.ex.report()
        rep = next(d for d in self.c.call("GET", "/v1/devices")[1]["devices"] if d["id"] == self.dev)["report"]
        self.assertEqual(rep["allow"], ["api.itau.com.br"])
        self.assertEqual(list(rep["allow_by"]), ["api.itau.com.br"])
        self.assertEqual(self.fake.regex["deny"], {self.mine: "meu"})

    def test_02_batch_with_ttl_and_expiry_removes_the_regex(self):
        self.send("pihole_batch", {"items": [{"domain": "cdn.itau.com.br", "ttl_s": 3600}, {"domain": "static.itau.com.br"}]})
        self.assertEqual(len(self.fake.regex["allow"]), 3)
        self.now[0] += 3601
        self.ex.expire_temp()
        self.assertEqual(sorted(domains.from_regex(r) for r in self.fake.regex["allow"]), ["api.itau.com.br", "static.itau.com.br"])

    def test_03_remove_and_deny_clean_both_forms_and_spare_hand_written_rules(self):
        self.fake.lists["allow"]["velho.itau.com.br"] = "guardian:x"  # liberação antiga, na forma exata
        self.send("pihole_remove", {"list": "allow", "domain": "velho.itau.com.br"})
        self.assertNotIn("velho.itau.com.br", self.fake.lists["allow"])
        self.send("pihole_deny", {"domain": "static.itau.com.br"})
        self.assertNotIn("static.itau.com.br", [domains.from_regex(r) for r in self.fake.regex["allow"]])
        self.assertIn(domains.to_regex("static.itau.com.br"), self.fake.regex["deny"])
        self.assertEqual(self.fake.regex["deny"][self.mine], "meu")

    def test_04_release_that_would_cover_the_canary_is_refused(self):
        self.send("pihole_allow", {"domain": "exemplo.com"})
        self.assertNotIn(domains.to_regex("exemplo.com"), self.fake.regex["allow"])
        self.send("pihole_allow", {"domain": "canario.exemplo.com"})
        self.assertNotIn(domains.to_regex("canario.exemplo.com"), self.fake.regex["allow"])
        self.send("pihole_allow", {"domain": "outro.exemplo.com"})  # irmão do canário: pode
        self.assertIn(domains.to_regex("outro.exemplo.com"), self.fake.regex["allow"])


if __name__ == "__main__":
    unittest.main()
