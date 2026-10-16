import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import command, envelope  # noqa: E402
from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.executor import domains  # noqa: E402
from guardian.executor.pihole import Pihole, PiholeError  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, pair, parse_pairing  # noqa: E402
from guardian.protocol import b64  # noqa: E402


def pairing_string(env, c, token, gid_trust=None):
    me = c.call("GET", "/v1/me")[1]
    return b64.enc(json.dumps({"v": 1, "url": env.cfg.origin, "rp": env.cfg.rp_id, "token": token,
                               "guardians": me["trust"]}).encode())


class DomainTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(domains.normalize("  Exemplo.COM. "), "exemplo.com")
        for bad in ("", "a", "*.exemplo.com", "-a.com", "a-.com", "a..com", "exemplo.com/x", "ex emplo.com", "1.2.3.4",
                    "exemplo.com;rm", "ação.com", "a" * 64 + ".com", ("a." * 130) + "com", None, 5, "--x.com", ".com"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                domains.normalize(bad)


class PiholeClientTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakePihole()

    def tearDown(self):
        self.fake.close()

    def test_roundtrip_and_relogin(self):
        p = Pihole(self.fake.url, "senha-app")
        p.put_domain("allow", "a.example", "c")
        self.assertEqual(p.list_domains("allow"), ["a.example"])
        self.fake.sessions_valid = False  # sessão expirou
        p.put_domain("deny", "b.example")
        self.assertEqual(self.fake.logins, 2)
        p.delete_domain("allow", "a.example")
        p.delete_domain("allow", "a.example")  # 404 é aceito
        self.assertEqual(p.list_domains("allow"), [])

    def test_bad_password_and_down(self):
        with self.assertRaises(PiholeError):
            Pihole(self.fake.url, "errada").list_domains("allow")
        self.fake.down = True
        with self.assertRaises(PiholeError):
            Pihole(self.fake.url, "senha-app").list_domains("allow")
        with self.assertRaises(PiholeError):
            Pihole("http://127.0.0.1:1", "x", timeout=1).list_domains("allow")

    def test_only_exact_and_regex_kinds(self):
        with self.assertRaises(PiholeError):
            Pihole(self.fake.url, "x")._p("allow", "wildcard")
        self.assertEqual(Pihole(self.fake.url, "x")._p("deny", "regex"), "/api/domains/deny/regex")


class ExecutorEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.fake = FakePihole()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cfg = ExecConfig(cls.tmp.name, cls.fake.url, "senha-app", "canario.example")
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "executor"})
        cls.fp = pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]))
        cls.now = [1_000_000.0]
        cls.ex = Executor(cls.cfg, now=lambda: cls.now[0])
        cls.dev = cls.ex.dev

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.fake.close()
        cls.tmp.cleanup()

    def send(self, type_, args=None):
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, type_, args)
        self.assertEqual(st, 200, r)

    def results(self):
        self.ex.step(wait_s=0)
        items = self.c.call("GET", "/v1/audit")[1]["items"]
        return [i["text"] for i in items if i["kind"] == "executed"]

    def test_01_paired_and_listed(self):
        self.assertRegex(self.fp, r"^[a-z2-7]{4}(-[a-z2-7]{4}){4}$")
        devs = self.c.call("GET", "/v1/devices")[1]["devices"]
        self.assertEqual([d["kind"] for d in devs if d["id"] == self.dev], ["executor"])

    def test_02_allow_deny_remove(self):
        self.send("pihole_allow", {"domain": "Liberado.Example"})
        self.send("pihole_deny", {"domain": "bloqueado.example"})
        self.ex.step(wait_s=0)
        self.assertIn("liberado.example", self.fake.lists["allow"])
        self.assertIn("bloqueado.example", self.fake.lists["deny"])
        self.assertTrue(self.fake.lists["allow"]["liberado.example"].startswith("guardian:"))
        self.send("pihole_remove", {"list": "allow", "domain": "liberado.example"})
        self.ex.step(wait_s=0)
        self.assertNotIn("liberado.example", self.fake.lists["allow"])

    def test_03_deny_removes_allow(self):
        self.send("pihole_allow", {"domain": "troca.example"})
        self.send("pihole_deny", {"domain": "troca.example"})
        self.ex.step(wait_s=0)
        self.assertNotIn("troca.example", self.fake.lists["allow"])
        self.assertIn("troca.example", self.fake.lists["deny"])

    def test_04_canary_is_protected(self):
        for t, a in (("pihole_allow", {"domain": "canario.example"}), ("pihole_remove", {"list": "deny", "domain": "CANARIO.example"}),
                     ("pihole_deny", {"domain": "canario.example"})):
            self.send(t, a)
        self.fake.lists["deny"]["canario.example"] = "admin"
        out = self.results()
        self.assertTrue(sum("domínio-canário" in x for x in out) >= 3, out)
        self.assertIn("canario.example", self.fake.lists["deny"])
        self.assertNotIn("canario.example", self.fake.lists["allow"])

    def test_05_invalid_inputs_rejected(self):
        for a in ({"domain": "*.x.com"}, {"domain": "1.2.3.4"}, {"domain": "ok.example", "ttl_s": 5},
                  {"domain": "ok.example", "ttl_s": 99999999}, {"domain": "ok.example", "ttl_s": "60"}):
            self.send("pihole_allow", a)
        self.ex.step(wait_s=0)
        self.assertNotIn("ok.example", self.fake.lists["allow"])

    def test_06_temporary_allow_expires_and_survives_restart(self):
        self.send("pihole_allow", {"domain": "temp.example", "ttl_s": 3600})
        self.ex.step(wait_s=0)
        self.assertIn("temp.example", self.fake.lists["allow"])
        ex2 = Executor(self.cfg, now=lambda: self.now[0])  # "reinício"
        self.assertEqual(len(ex2.state.data["temp"]), 1)
        self.now[0] += 1800
        ex2.expire_temp()
        self.assertIn("temp.example", self.fake.lists["allow"])
        self.now[0] += 2000
        self.fake.down = True
        ex2.expire_temp()  # Pi-hole fora: mantém para tentar de novo
        self.assertEqual(len(ex2.state.data["temp"]), 1)
        self.fake.down = False
        ex2.expire_temp()
        self.assertNotIn("temp.example", self.fake.lists["allow"])
        self.assertEqual(ex2.state.data["temp"], [])
        self.ex = ex2  # segue com a instância nova

    def test_07_replay_and_forged_commands_rejected(self):
        ex = self.ex
        p = command(self.dev, self.gid, 1, "pihole_allow", {"domain": "replay.example"})
        env = envelope(p, self.a.sign_command(self.gid, p))
        ex.handle(env)
        self.assertFalse(ex.executed[-1]["ok"])  # ctr 1 já foi usado
        stranger = self.env.auth()
        n = max(ex.consumer.last_ctr.values()) + 1
        p2 = command(self.dev, self.gid, n, "pihole_allow", {"domain": "forjado.example"})
        ex.handle(envelope(p2, stranger.sign_command(self.gid, p2)))
        self.assertIn("recusado", ex.executed[-1]["msg"])
        self.assertNotIn("forjado.example", self.fake.lists["allow"])

    def test_08_report_visible_to_guardian(self):
        self.ex.report()
        d = [x for x in self.c.call("GET", "/v1/devices")[1]["devices"] if x["id"] == self.dev][0]
        self.assertTrue(d["report"]["pihole_ok"])
        self.assertIn("bloqueado.example", d["report"]["deny"])
        self.assertIn(self.gid, d["report"]["trust"])

    def test_09_pihole_down_is_reported_not_crashing(self):
        self.fake.down = True
        self.send("pihole_allow", {"domain": "fora.example"})
        out = self.results()
        self.fake.down = False
        self.assertTrue(any("pihole_allow FALHOU" in x for x in out), out)
        self.assertNotIn("fora.example", self.fake.lists["allow"])

    def test_10_trust_add_guardian_and_unknown_guardian(self):
        c2, a2, g2 = self.env.register_guardian("Bia")
        me = c2.call("GET", "/v1/me")[1]["trust"][g2]
        cred, spki = next(iter(me["creds"].items()))
        self.send("add_guardian", {"id": g2, "name": "Bia", "cred": cred, "spki": spki, "role": "domains", "allow_sync": True})
        self.ex.step(wait_s=0)
        self.assertIn(g2, self.ex.consumer.trust.guardians)
        (st, r, _), _ = self.env.sign_post(c2, a2, g2, self.dev, "pihole_allow", {"domain": "bia.example"})
        self.assertEqual(st, 200)
        self.ex.step(wait_s=0)
        self.assertIn("bia.example", self.fake.lists["allow"])

    def test_11_window_uses_the_executors_clock(self):
        import datetime
        wk = {"days": [0, 1, 2, 3, 4], "from": 720, "to": 1020, "utc_offset_min": -180}
        c2, a2, g2 = self.env.register_guardian("Trabalho")
        me = c2.call("GET", "/v1/me")[1]["trust"][g2]
        cred, spki = next(iter(me["creds"].items()))
        self.send("add_guardian", {"id": g2, "name": "Trabalho", "cred": cred, "spki": spki, "role": "domains", "allow_sync": True, "window": wk})
        self.ex.step(wait_s=0)
        self.assertEqual(self.ex.consumer.trust.guardians[g2].window, wk)
        tz = datetime.timezone(datetime.timedelta(hours=-3))
        n = max(self.ex.consumer.last_ctr.values()) + 1
        for hour, ok in ((14, True), (22, False)):
            self.now[0] = datetime.datetime(2026, 10, 14, hour, 0, tzinfo=tz).timestamp()   # quarta-feira
            p = command(self.dev, g2, n + hour, "pihole_allow", {"domain": f"h{hour}.example"})
            self.ex.handle(envelope(p, a2.sign_command(g2, p)))
            self.assertEqual(self.ex.executed[-1]["ok"], ok, self.ex.executed[-1])
            self.assertEqual(f"h{hour}.example" in self.fake.lists["allow"], ok)
        self.assertIn("janela", self.ex.executed[-1]["msg"])
        self.now[0] = 1_000_000.0

    def test_pairing_string_validation(self):
        for bad in ("", "###", b64.enc(b"{}"), b64.enc(b'{"v":2}')):
            with self.assertRaises(ValueError):
                parse_pairing(bad)


if __name__ == "__main__":
    unittest.main()
