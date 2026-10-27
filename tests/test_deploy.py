import datetime
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.deployer.core import Deployer  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, pair  # noqa: E402
from guardian.protocol import commands as cmds  # noqa: E402
from test_executor import pairing_string  # noqa: E402

NOW = float(int(time.time()))
C40 = "a" * 40


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=Dev", "-c", "user.email=d@x", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class DeployArgs(unittest.TestCase):
    def test_args_are_checked(self):
        cmds.check_deploy_args({"project": "guardian", "commit": C40})
        cmds.check_deploy_args({"project": "estudos-app", "commit": C40, "sensitive_ok": True})
        for bad in ({"project": "Guardian", "commit": C40}, {"project": "g", "commit": "abc123"}, {"project": "g"}, {"commit": C40},
                    {"project": "g", "commit": C40, "sensitive_ok": "sim"}, {"project": "g", "commit": C40, "extra": 1},
                    {"project": "../x", "commit": C40}, {"project": "g", "commit": C40.upper()}):
            with self.assertRaises(cmds.CommandError, msg=bad):
                cmds.check_deploy_args(bad)

    def test_only_the_master_may_deploy_and_only_inside_his_window(self):
        win = {"days": [1, 2, 3], "from": 12 * 60, "to": 16 * 60, "utc_offset_min": -180}
        trust = cmds.Trust("rp", "https://rp", {
            "m": cmds.Guardian("Gandalf", {}, cmds.ROLE_MASTER, True, win), "a": cmds.Guardian("Mor", {}, cmds.ROLE_ADMIN),
            "d": cmds.Guardian("Guardião", {}, cmds.ROLE_DOMAINS)})
        cmd = lambda g: {"guardian": g, "type": cmds.T_DEPLOY, "args": {"project": "guardian", "commit": C40}}
        tz = datetime.timezone(datetime.timedelta(hours=-3))
        tue_noon = datetime.datetime(2026, 10, 27, 12, 30, tzinfo=tz).timestamp()   # terça
        tue_night = datetime.datetime(2026, 10, 27, 21, 0, tzinfo=tz).timestamp()
        mon_noon = datetime.datetime(2026, 10, 26, 12, 30, tzinfo=tz).timestamp()
        self.assertEqual(cmds.check_author(trust, cmd("m"), tue_noon).name, "Gandalf")
        for when in (tue_night, mon_noon):
            with self.assertRaisesRegex(cmds.CommandError, "janela"):
                cmds.check_author(trust, cmd("m"), when)
        for g in ("a", "d"):
            with self.assertRaises(cmds.CommandError):
                cmds.check_author(trust, cmd(g), tue_noon)


class DeployerFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.origin, self.work, self.state = os.path.join(t, "origin"), os.path.join(t, "work"), os.path.join(t, "state")
        os.makedirs(self.origin)
        git(self.origin, "init", "-q", "-b", "main")
        self._commit("app.txt", "ok v1", "primeira")
        git(self.origin, "tag", "release/1")
        git(t, "clone", "-q", self.origin, self.work)
        git(self.work, "checkout", "-q", "--detach", "release/1")
        self.marker = os.path.join(t, "ran")
        self.reg = {"demo": {"repo": self.origin, "workdir": self.work, "tag_prefix": "release/",
                             "sensitive": ["sec/*", "deploy/*"],
                             "steps": [["sh", "-c", "cat app.txt > " + self.marker]],
                             "health": [["sh", "-c", "grep -q ok " + self.marker]], "health_timeout_s": 0}}
        self.d = Deployer(self.reg, self.state, sleep=lambda s: None)

    def tearDown(self):
        self.tmp.cleanup()

    def _commit(self, path, content, msg):
        full = os.path.join(self.origin, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        git(self.origin, "add", "-A")
        git(self.origin, "commit", "-q", "-m", msg)
        return git(self.origin, "rev-parse", "HEAD")

    def test_01_offers_show_only_minimal_info_and_flag_sensitive_files(self):
        self._commit("app.txt", "ok normal", "ajuste simples")
        git(self.origin, "tag", "release/2")
        sens = self._commit("sec/regras.py", "x", "mexe em segurança")
        git(self.origin, "tag", "release/3")
        offers = {o["tag"]: o for o in self.d.refresh_offers()}
        self.assertEqual(sorted(offers), ["release/2", "release/3"])         # a que já está no ar não é oferta
        self.assertEqual(offers["release/2"]["sensitive_n"], 0)
        self.assertEqual(offers["release/3"]["sensitive"], ["sec/regras.py"])
        self.assertEqual(offers["release/3"]["commit"], sens)
        self.assertEqual(offers["release/3"]["subject"], "mexe em segurança")
        data = json.load(open(os.path.join(self.state, "offers.json")))
        self.assertEqual(len(data["offers"]), 2)

    def test_02_deploys_only_tagged_commits(self):
        untagged = self._commit("app.txt", "ok", "sem etiqueta")
        r = self.d.deploy({"project": "demo", "commit": untagged, "guardian": "g"})
        self.assertFalse(r["ok"])
        self.assertIn("etiqueta", r["msg"])
        r = self.d.deploy({"project": "nao-existe", "commit": untagged})
        self.assertIn("não cadastrado", r["msg"])

    def test_03_good_version_goes_live_and_runs_the_steps(self):
        c = self._commit("app.txt", "ok v2", "v2")
        git(self.origin, "tag", "release/2")
        r = self.d.deploy({"project": "demo", "commit": c, "guardian": "g_gandalf"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(git(self.work, "rev-parse", "HEAD"), c)
        self.assertEqual(open(self.marker).read(), "ok v2")
        self.assertEqual(r["by"], "g_gandalf")

    def test_04_sensitive_version_needs_the_masters_confirmation(self):
        c = self._commit("sec/x.py", "ok", "mexe em segurança")
        git(self.origin, "tag", "release/2")
        before = git(self.work, "rev-parse", "HEAD")
        r = self.d.deploy({"project": "demo", "commit": c})
        self.assertFalse(r["ok"])
        self.assertIn("áreas de segurança", r["msg"])
        self.assertEqual(git(self.work, "rev-parse", "HEAD"), before)       # nada mudou
        self.assertTrue(self.d.deploy({"project": "demo", "commit": c, "sensitive_ok": True})["ok"])

    def test_05_failed_health_rolls_back_without_a_signature(self):
        good = git(self.work, "rev-parse", "HEAD")
        c = self._commit("app.txt", "quebrado", "v2 ruim")      # o passo grava "quebrado": a checagem espera "ok"
        git(self.origin, "tag", "release/2")
        r = self.d.deploy({"project": "demo", "commit": c})
        self.assertFalse(r["ok"])
        self.assertTrue(r["rolled_back"], r)
        self.assertIn("revertido", r["msg"])
        self.assertEqual(git(self.work, "rev-parse", "HEAD"), good)

    def test_06_inbox_request_runs_once_and_lands_in_history(self):
        c = self._commit("app.txt", "ok v2", "v2")
        git(self.origin, "tag", "release/2")
        with open(os.path.join(self.state, "inbox", "1-1-demo.json"), "w") as f:
            json.dump({"project": "demo", "commit": c, "sensitive_ok": False, "guardian": "g"}, f)
        with open(os.path.join(self.state, "inbox", "2-2-lixo.json"), "w") as f:
            f.write("não é json")
        res = self.d.process_inbox()
        self.assertEqual([r["ok"] for r in res], [True, False])
        self.assertEqual(os.listdir(os.path.join(self.state, "inbox")), [])    # nada se repete
        st = json.load(open(os.path.join(self.state, "status.json")))
        self.assertEqual(len(st["history"]), 2)
        self.assertEqual(self.d.process_inbox(), [])


class ExecutorQueuesDeploy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.fake = FakePihole()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dd = os.path.join(cls.tmp.name, "deploy")
        os.makedirs(os.path.join(cls.dd, "inbox"))
        cls.cfg = ExecConfig(cls.tmp.name, cls.fake.url, "senha-app", "canario.example", allow_mode="regex", deploy_dir=cls.dd)
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "executor"})
        pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]))
        cls.ex = Executor(cls.cfg, now=lambda: NOW)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.fake.close()
        cls.tmp.cleanup()

    def cmd(self, args):
        return {"type": cmds.T_DEPLOY, "args": args, "guardian": self.gid, "ctr": 7}

    def test_01_queues_a_request_for_the_root_deployer(self):
        out = self.ex.apply(self.cmd({"project": "guardian", "commit": C40, "sensitive_ok": True}))
        self.assertIn("deploy pedido", out)
        (fn,) = os.listdir(os.path.join(self.dd, "inbox"))
        req = json.load(open(os.path.join(self.dd, "inbox", fn)))
        self.assertEqual((req["project"], req["commit"], req["sensitive_ok"], req["guardian"]), ("guardian", C40, True, self.gid))

    def test_02_bad_args_and_no_deployer_are_refused(self):
        with self.assertRaises(ValueError):
            self.ex.apply(self.cmd({"project": "guardian", "commit": "curto"}))
        cfg2 = ExecConfig(self.tmp.name, self.fake.url, "s", "c.example")
        ex2 = Executor(cfg2, now=lambda: NOW)
        with self.assertRaisesRegex(ValueError, "deployer"):
            ex2.apply(self.cmd({"project": "guardian", "commit": C40}))

    def test_03_report_carries_offers_and_status(self):
        with open(os.path.join(self.dd, "offers.json"), "w") as f:
            json.dump({"ts": 1, "offers": [{"project": "guardian", "tag": "release/2", "commit": C40}], "current": {}}, f)
        self.assertEqual(self.ex._deploy_report()["offers"]["offers"][0]["tag"], "release/2")
        self.assertIsNone(self.ex._deploy_report()["status"])


if __name__ == "__main__":
    unittest.main()
