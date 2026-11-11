"""O deployer (root) confere ele mesmo a assinatura do mestre: um executor comprometido não coloca versão no ar sozinho."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import FakeAuthenticator, command, envelope  # noqa: E402
from guardian.deployer import signed  # noqa: E402
from guardian.deployer.__main__ import main as deployer_main  # noqa: E402
from guardian.deployer.core import Deployer  # noqa: E402
from guardian.protocol import b64  # noqa: E402
from guardian.protocol import commands as cmds  # noqa: E402

RP, ORIGIN, DEV = "guardian.example", "https://guardian.example", "exec0000000000000000"
NOW = 1_800_000_000.0   # uma sexta-feira, 08:00 UTC


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=Dev", "-c", "user.email=d@x", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class SignedDeploy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.origin, self.work, self.state = os.path.join(t, "origin"), os.path.join(t, "work"), os.path.join(t, "state")
        os.makedirs(self.origin)
        git(self.origin, "init", "-q", "-b", "main")
        self.v1 = self._release("app.txt", "ok v1", "release/1")
        git(t, "clone", "-q", self.origin, self.work)
        git(self.work, "checkout", "-q", "--detach", "release/1")
        self.v2 = self._release("app.txt", "ok v2", "release/2")
        self.v3 = self._release("sec/regra.py", "x", "release/3")          # mexe em segurança
        self.reg = {"demo": {"repo": self.origin, "workdir": self.work, "tag_prefix": "release/", "sensitive": ["sec/*"], "steps": [], "health": []}}
        self.master, self.mor = FakeAuthenticator(RP, ORIGIN), FakeAuthenticator(RP, ORIGIN)
        trust = cmds.Trust(RP, ORIGIN, {
            "g_master": cmds.Guardian("Gandalf", {self.master.cred_id_b64: b64.enc(self.master.spki)}, cmds.ROLE_MASTER,
                                      window={"days": [4], "from": 7 * 60, "to": 9 * 60, "utc_offset_min": 0}),
            "g_mor": cmds.Guardian("Mor", {self.mor.cred_id_b64: b64.enc(self.mor.spki)}, cmds.ROLE_ADMIN)})
        os.makedirs(self.state)
        self.trust_path = os.path.join(self.state, "trust.json")
        with open(self.trust_path, "w") as f:
            json.dump(cmds.Consumer(DEV, trust).to_json(), f)
        self.now = NOW
        self.d = Deployer(self.reg, self.state, sleep=lambda s: None, now=lambda: self.now, trust_path=self.trust_path)
        self.ctr = 0

    def tearDown(self):
        self.tmp.cleanup()

    def _release(self, path, content, tag):
        full = os.path.join(self.origin, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").write(content)
        git(self.origin, "add", "-A")
        git(self.origin, "commit", "-q", "-m", tag)
        git(self.origin, "tag", tag)
        return git(self.origin, "rev-parse", "HEAD")

    def env(self, args, type_=cmds.T_DEPLOY, who="g_master", auth=None, ctr=None, dev=DEV):
        self.ctr += 1
        p = command(dev, who, ctr or self.ctr, type_, args)
        return envelope(p, (auth or self.master).sign_command(who, p))

    def drop(self, req, name="1-x.json"):
        with open(os.path.join(self.state, "inbox", name), "w") as f:
            json.dump(req, f)
        (res,) = self.d.process_inbox()
        return res

    def live(self):
        return git(self.work, "rev-parse", "HEAD")

    def test_01_signed_by_the_master_goes_live(self):
        res = self.drop({"project": "demo", "commit": self.v2, "envelope": self.env({"project": "demo", "commit": self.v2})})
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["by"], "g_master")
        self.assertEqual(self.live(), self.v2)

    def test_02_without_a_signature_nothing_happens(self):
        res = self.drop({"project": "demo", "commit": self.v2, "sensitive_ok": True, "guardian": "g_master"})
        self.assertFalse(res["ok"])
        self.assertIn("envelope", res["msg"])
        self.assertEqual(self.live(), self.v1)

    def test_03_forged_or_not_from_the_master_is_refused(self):
        stranger = FakeAuthenticator(RP, ORIGIN)
        for env in (self.env({"project": "demo", "commit": self.v2}, auth=stranger),                 # chave que o deployer não conhece
                    self.env({"project": "demo", "commit": self.v2}, who="g_mor", auth=self.mor),     # guardião-mor não coloca no ar
                    self.env({"project": "demo", "commit": self.v2}, dev="outro000000000000000")):  # comando de outro destino
            res = self.drop({"project": "demo", "commit": self.v2, "envelope": env})
            self.assertFalse(res["ok"], res)
            self.assertIn("assinatura recusada", res["msg"])
        self.assertEqual(self.live(), self.v1)

    def test_04_the_same_signed_command_does_not_run_twice(self):
        env = self.env({"project": "demo", "commit": self.v2})
        self.assertTrue(self.drop({"envelope": env}, "1-a.json")["ok"])
        res = self.drop({"envelope": env}, "2-b.json")
        self.assertFalse(res["ok"])
        self.assertIn("replay", res["msg"])

    def test_05_outside_the_masters_window_is_refused_by_the_deployer_clock(self):
        self.now = NOW + 3 * 3600   # 11:00, depois da janela das 7h às 9h
        res = self.drop({"envelope": self.env({"project": "demo", "commit": self.v2})})
        self.assertFalse(res["ok"])
        self.assertIn("janela", res["msg"])
        self.assertEqual(self.live(), self.v1)

    def test_06_what_counts_is_inside_the_signature_not_what_the_executor_wrote(self):
        """O executor escreve commit e sensitive_ok ao lado: um executor comprometido trocaria por outra versão ou pularia o aviso."""
        env = self.env({"project": "demo", "commit": self.v3})             # o mestre NÃO confirmou o aviso de segurança
        res = self.drop({"project": "demo", "commit": self.v3, "sensitive_ok": True, "envelope": env})
        self.assertFalse(res["ok"])
        self.assertIn("áreas de segurança", res["msg"])
        env = self.env({"project": "demo", "commit": self.v2})
        res = self.drop({"project": "demo", "commit": self.v3, "sensitive_ok": True, "envelope": env})
        self.assertTrue(res["ok"])
        self.assertEqual(self.live(), self.v2)                              # a versão assinada, não a escrita ao lado

    def test_07_new_master_passkey_reaches_the_deployer_by_signed_command(self):
        new = FakeAuthenticator(RP, ORIGIN)
        res = self.drop({"envelope": self.env({"project": "demo", "commit": self.v2}, auth=new)}, "1-a.json")
        self.assertFalse(res["ok"])                                          # passkey nova ainda desconhecida
        add = self.env({"id": "g_master", "cred": new.cred_id_b64, "spki": b64.enc(new.spki)}, type_=cmds.T_ADD_CREDENTIAL)
        res = self.drop({"kind": "trust", "envelope": add}, "2-b.json")
        self.assertTrue(res["ok"], res)
        res = self.drop({"envelope": self.env({"project": "demo", "commit": self.v2}, auth=new)}, "3-c.json")
        self.assertTrue(res["ok"], res)
        saved = json.load(open(self.trust_path))
        self.assertIn(new.cred_id_b64, saved["trust"]["guardians"]["g_master"]["creds"])
        self.assertEqual(oct(os.stat(self.trust_path).st_mode & 0o777), "0o600")

    def test_08_unsigned_trust_change_is_refused(self):
        res = self.drop({"kind": "trust", "guardian": "g_master"})
        self.assertFalse(res["ok"])

    def test_09_project_add_also_needs_the_masters_signature(self):
        res = self.drop({"kind": "project_add", "name": "triagem", "github": "Allan/Triagem", "pkg": "com.allan.triagem", "guardian": "g_master"})
        self.assertFalse(res["ok"])
        self.assertIn("assinatura recusada", res["msg"])

    def test_pi_run_only_with_the_masters_signature(self):
        calls = []
        real = self.d.run

        def fake_run(argv, cwd=None, env=None, timeout=600):
            if argv[0] != "/bin/bash":
                return real(argv, cwd=cwd, env=env, timeout=timeout)   # o git do deployer segue normal
            calls.append((argv, timeout, open(argv[1]).read()))
            return 0, "olá do Pi"
        self.d.run = fake_run
        args = {"script": "echo oi\n", "name": "teste", "timeout_s": 30}
        # sem envelope: recusado, nada roda
        res = self.drop({"kind": "pi_run", "script": "rm -rf /", "name": "x", "timeout_s": 30}, "1-a.json")
        self.assertFalse(res["ok"])
        self.assertEqual(calls, [])
        # guardião-mor não assina script no Pi (é do mestre)
        res = self.drop({"envelope": self.env(args, cmds.T_PI_RUN, "g_mor", self.mor)}, "2-b.json")
        self.assertFalse(res["ok"], res)
        self.assertEqual(calls, [])
        # o mestre assina: roda o script que está DENTRO da assinatura, não o que o executor escreveu ao lado
        res = self.drop({"kind": "pi_run", "script": "rm -rf /", "envelope": self.env(args, cmds.T_PI_RUN)}, "3-c.json")
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], 30)
        self.assertEqual(calls[0][2], "echo oi\n")
        self.assertEqual(res["out"], "olá do Pi")
        self.assertEqual(res["project"], "script")
        self.assertFalse(os.path.exists(calls[0][0][1]))   # o arquivo temporário não fica

    def test_pi_run_failure_and_timeout_are_reported(self):
        real = self.d.run
        self.d.run = lambda argv, cwd=None, env=None, timeout=600: (3, "deu ruim") if argv[0] == "/bin/bash" else real(argv, cwd=cwd, env=env, timeout=timeout)
        res = self.drop({"envelope": self.env({"script": "exit 3"}, cmds.T_PI_RUN)}, "1-a.json")
        self.assertFalse(res["ok"])
        self.assertIn("código 3", res["msg"])

        def slow(argv, cwd=None, env=None, timeout=600):
            if argv[0] != "/bin/bash":
                return real(argv, cwd=cwd, env=env, timeout=timeout)   # o git do deployer segue normal
            raise subprocess.TimeoutExpired(argv, timeout, output="parcial")
        self.d.run = slow
        res = self.drop({"envelope": self.env({"script": "sleep 99", "timeout_s": 5}, cmds.T_PI_RUN)}, "2-b.json")
        self.assertFalse(res["ok"])
        self.assertIn("tempo limite", res["msg"])
        self.assertEqual(res["out"], "parcial")

    def test_pi_run_keeps_output_only_for_the_latest_runs(self):
        real = self.d.run
        self.d.run = lambda argv, cwd=None, env=None, timeout=600: (0, "x" * 5000) if argv[0] == "/bin/bash" else real(argv, cwd=cwd, env=env, timeout=timeout)
        for i in range(5):
            self.drop({"envelope": self.env({"script": f"echo {i}"}, cmds.T_PI_RUN)}, f"{i}-r.json")
        hist = [x for x in self.d.status["history"] if x["project"] == "script"]
        self.assertEqual(len(hist), 5)
        self.assertEqual([len(x.get("out", "")) for x in hist], [1500, 1500, 1500, 0, 0])

    def test_the_deployer_announces_pi_run_so_the_site_can_tell_old_from_new(self):
        self.d.refresh_offers()
        with open(os.path.join(self.state, "offers.json")) as f:
            self.assertIn("pi_run", json.load(f)["features"])

    def test_pi_run_args_are_checked(self):
        for bad in ({"script": ""}, {"script": "x" * 6001}, {"script": "a\x00b"}, {"script": "ok", "timeout_s": 1}, {"script": "ok", "extra": 1}, {"script": 5}):
            with self.assertRaises(cmds.CommandError):
                cmds.check_pi_run_args(bad)
        cmds.check_pi_run_args({"script": "echo ok", "name": "a", "timeout_s": 600})

    def test_10_without_trust_file_every_request_is_refused(self):
        os.remove(self.trust_path)
        d = Deployer(self.reg, self.state, sleep=lambda s: None, now=lambda: self.now, trust_path=self.trust_path)
        with open(os.path.join(self.state, "inbox", "1-x.json"), "w") as f:
            json.dump({"envelope": self.env({"project": "demo", "commit": self.v2})}, f)
        (res,) = d.process_inbox()
        self.assertFalse(res["ok"])
        self.assertIn("install-deployer", res["msg"])


class InitTrust(unittest.TestCase):
    def test_copies_the_executor_trust_once(self):
        with tempfile.TemporaryDirectory() as t:
            a = FakeAuthenticator(RP, ORIGIN)
            consumer = cmds.Consumer(DEV, cmds.Trust(RP, ORIGIN, {"g1": cmds.Guardian("Gandalf", {a.cred_id_b64: b64.enc(a.spki)}, cmds.ROLE_MASTER)}),
                                     {"g1": 41})
            ex = os.path.join(t, "state.json")
            json.dump({"consumer": consumer.to_json(), "gateway": "x"}, open(ex, "w"))
            self.assertEqual(deployer_main(["init-trust", "--state", t, "--from", ex]), 0)
            box = signed.SignedInbox(os.path.join(t, "trust.json"))
            self.assertEqual(box.consumer.last_ctr, {"g1": 41})               # comandos já vistos pelo executor não valem de novo
            self.assertEqual(box.consumer.dev, DEV)
            self.assertEqual(deployer_main(["init-trust", "--state", t, "--from", ex]), 1)   # não troca sem --force
            json.dump({"consumer": None}, open(ex, "w"))
            with self.assertRaises(ValueError):
                signed.init_trust(os.path.join(t, "outro.json"), ex)


class InstalledLayout(unittest.TestCase):
    """Como o install-deployer.sh monta: guardian_deployer/ com protocol/ dentro, sem o repositório no caminho."""
    def test_package_copied_like_the_install_script_imports_and_runs(self):
        src = os.path.join(os.path.dirname(__file__), "..", "src", "guardian")
        script = open(os.path.join(os.path.dirname(__file__), "..", "deploy", "install-deployer.sh")).read()
        with tempfile.TemporaryDirectory() as t:
            pkg = os.path.join(t, "lib", "guardian_deployer")
            os.makedirs(os.path.join(pkg, "protocol"))
            for sub, dest in (("deployer", pkg), ("protocol", os.path.join(pkg, "protocol"))):
                for f in os.listdir(os.path.join(src, sub)):
                    if f.endswith(".py") and f"src/guardian/{sub}/{f}" in script:   # só o que o script copia
                        with open(os.path.join(src, sub, f)) as a, open(os.path.join(dest, f), "w") as b:
                            b.write(a.read())
            a = FakeAuthenticator(RP, ORIGIN)
            ex = os.path.join(t, "state.json")
            consumer = cmds.Consumer(DEV, cmds.Trust(RP, ORIGIN, {"g1": cmds.Guardian("Gandalf", {a.cred_id_b64: b64.enc(a.spki)}, cmds.ROLE_MASTER)}))
            json.dump({"consumer": consumer.to_json()}, open(ex, "w"))
            r = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); from guardian_deployer.__main__ import main; "
                                "sys.exit(main(sys.argv[2:]))", os.path.join(t, "lib"), "init-trust", "--state", t, "--from", ex],
                               capture_output=True, text=True, cwd=t)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("Gandalf (master)", r.stdout)


if __name__ == "__main__":
    unittest.main()
