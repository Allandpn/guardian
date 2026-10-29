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
from guardian.deployer import policy  # noqa: E402
from guardian.deployer.core import Deployer, _run  # noqa: E402
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

    def test_03b_older_versions_are_not_offered_and_not_installed(self):
        c = self._commit("app.txt", "ok v2", "v2")
        git(self.origin, "tag", "release/2")
        self.assertTrue(self.d.deploy({"project": "demo", "commit": c})["ok"])
        self.assertEqual([o["tag"] for o in self.d.refresh_offers() if "commit" in o], [])      # release/1 ficou para trás
        first = git(self.origin, "rev-parse", "release/1^{commit}")
        r = self.d.deploy({"project": "demo", "commit": first})
        self.assertFalse(r["ok"])
        self.assertIn("mais antiga", r["msg"])
        self.assertEqual(git(self.work, "rev-parse", "HEAD"), c)

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


class ComposePolicy(unittest.TestCase):
    P = "/tmp/proj"

    def cfg(self, **svc):
        return {"services": {"app": svc}}

    def test_normal_project_passes(self):
        cfg = {"services": {"app": {"image": "x", "volumes": [{"type": "bind", "source": "/mnt/ssd/dados", "target": "/d"},
                                                                {"type": "bind", "source": "/tmp/proj/conf", "target": "/c"},
                                                                {"type": "volume", "source": "dados", "target": "/v"}],
                                    "build": {"context": "/tmp/proj"}, "env_file": [{"path": "/tmp/proj/.env"}]}},
               "volumes": {"dados": {"name": "p_dados"}}, "networks": {"default": {"name": "p_default"}}}
        self.assertEqual(policy.violations(cfg, self.P, ["/mnt/ssd"]), [])

    def test_each_escape_hatch_is_a_violation(self):
        bad = [dict(privileged=True), dict(cap_add=["SYS_ADMIN"]), dict(devices=["/dev/mem:/dev/mem"]), dict(network_mode="host"),
               dict(pid="host"), dict(ipc="host"), dict(userns_mode="host"), dict(security_opt=["seccomp=unconfined"]),
               dict(group_add=["docker"]), dict(volumes_from=["x"]), dict(runtime="runc"),
               dict(volumes=[{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}]),
               dict(volumes=[{"type": "bind", "source": "/opt/guardian", "target": "/g"}]),
               dict(volumes=[{"type": "bind", "source": "/mnt/ssd/../etc", "target": "/g"}]),
               dict(env_file=[{"path": "/etc/guardian-executor.env"}]),
               dict(build={"context": "/etc"}), dict(build={"context": "/tmp/proj", "privileged": True})]
        for svc in bad:
            self.assertTrue(policy.violations(self.cfg(**svc), self.P, ["/mnt/ssd"]), svc)

    def test_external_volumes_and_networks_are_refused(self):
        for top in ({"volumes": {"gw": {"external": True, "name": "deploy_gateway-data"}}},
                    {"networks": {"g": {"external": True, "name": "guardian_net"}}},
                    {"volumes": {"v": {"driver_opts": {"type": "none", "o": "bind", "device": "/etc"}}}},
                    {"secrets": {"s": {"file": "/etc/shadow"}}}):
            self.assertTrue(policy.violations({"services": {"app": {"image": "x"}}, **top}, self.P), top)

    def test_allowed_context_and_network_none(self):
        cfg = self.cfg(build={"context": "/opt/outro"}, network_mode="none")
        self.assertEqual(policy.violations(cfg, self.P, [], ["/opt/outro"]), [])
        self.assertTrue(policy.violations(cfg, self.P, [], []))


class DeployerCompose(unittest.TestCase):
    """O deployer recusa, antes de instalar, uma versão cujo compose viola a política (o `docker compose config` é simulado)."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.origin, self.work, self.state = os.path.join(t, "o"), os.path.join(t, "w"), os.path.join(t, "s")
        os.makedirs(self.origin)
        git(self.origin, "init", "-q", "-b", "main")
        open(os.path.join(self.origin, "docker-compose.yml"), "w").write("services: {}\n")
        git(self.origin, "add", "-A")
        git(self.origin, "commit", "-q", "-m", "v1")
        git(self.origin, "tag", "release/1")
        git(t, "clone", "-q", self.origin, self.work)
        self.bad = False

        def run(argv, cwd=None, env=None, timeout=600):
            if argv[0] == "docker" and "config" in argv:
                svc = {"image": "x", "privileged": True} if self.bad else {"image": "x"}
                return 0, json.dumps({"services": {"app": svc}})
            if argv[0] == "docker":
                return 0, ""
            return _run(argv, cwd, env, timeout)
        self.reg = {"p": {"repo": self.origin, "workdir": self.work, "type": "compose", "steps": [["docker", "compose", "up", "-d"]],
                          "health": [], "tag_prefix": "release/"}}
        self.d = Deployer(self.reg, self.state, run=run, sleep=lambda s: None)

    def tearDown(self):
        self.tmp.cleanup()

    def test_violating_version_is_flagged_in_the_offer_and_refused(self):
        open(os.path.join(self.origin, "x.txt"), "w").write("2")
        git(self.origin, "add", "-A")
        git(self.origin, "commit", "-q", "-m", "v2 com privileged")
        c = git(self.origin, "rev-parse", "HEAD")
        git(self.origin, "tag", "release/2")
        self.bad = True
        (offer,) = [o for o in self.d.refresh_offers() if o.get("commit") == c]
        self.assertEqual(offer["policy_n"], 1)
        self.assertIn("privileged", offer["policy"][0])
        before = git(self.work, "rev-parse", "HEAD")
        r = self.d.deploy({"project": "p", "commit": c, "sensitive_ok": True})
        self.assertFalse(r["ok"])
        self.assertIn("política de isolamento", r["msg"])
        self.assertEqual(git(self.work, "rev-parse", "HEAD"), before)       # nada foi instalado
        self.bad = False
        self.assertTrue(self.d.deploy({"project": "p", "commit": c})["ok"])


class FakeGitHub:
    def __init__(self, releases, blobs):
        self.rels, self.blobs, self.downloads = releases, blobs, 0

    def releases(self, repo):
        return self.rels

    def download(self, repo, asset_id, dest, max_bytes=0):
        import hashlib
        self.downloads += 1
        data = self.blobs[asset_id]
        with open(dest, "wb") as f:
            f.write(data)
        return hashlib.sha256(data).hexdigest(), len(data)


class AppOffers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.origin, self.state = os.path.join(t, "o"), os.path.join(t, "s")
        os.makedirs(self.origin)
        git(self.origin, "init", "-q", "-b", "main")
        for path, content, tag in (("a.txt", "1", "v1.0"), ("sec/policy.kt", "2", "v1.1")):
            full = os.path.join(self.origin, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").write(content)
            git(self.origin, "add", "-A")
            git(self.origin, "commit", "-q", "-m", "c " + tag)
            git(self.origin, "tag", tag)
        rel = lambda tag, aid, ts: {"tag_name": tag, "name": "Versão " + tag, "body": "notas\nlinha 2", "draft": False, "prerelease": False,
                                    "published_at": ts, "author": {"login": "allan"}, "assets": [{"id": aid, "name": "app.apk", "size": 10}]}
        self.gh = FakeGitHub([rel("v1.1", 12, "2026-10-27T10:00:00Z"), rel("v1.0", 11, "2026-10-20T10:00:00Z"),
                              {**rel("v0.9", 10, "2026-10-01T10:00:00Z"), "prerelease": True}],
                             {11: b"apk-um", 12: b"apk-dois"})
        self.reg = {"filtro": {"type": "android_app", "github": "o/filtro", "repo": self.origin, "tag_prefix": "v", "pkg": "com.exemplo.filtro",
                               "sensitive": ["sec/*"]}}
        self.d = Deployer(self.reg, self.state, sleep=lambda s: None, github=lambda token: self.gh)

    def tearDown(self):
        self.tmp.cleanup()

    def test_01_releases_become_offers_with_hash_and_risk(self):
        offers = {o["tag"]: o for o in self.d.refresh_app_offers(force=True)}
        self.assertEqual(sorted(offers), ["v1.0", "v1.1"])              # pré-lançamento fica de fora
        import hashlib
        self.assertEqual(offers["v1.1"]["sha256"], hashlib.sha256(b"apk-dois").hexdigest())
        self.assertEqual(offers["v1.1"]["size"], 8)
        self.assertEqual(offers["v1.1"]["pkg"], "com.exemplo.filtro")
        self.assertEqual(offers["v1.1"]["sensitive"], ["sec/policy.kt"])    # mexe em arquivo de segurança em relação à v1.0
        self.assertEqual(offers["v1.1"]["subject"], "Versão v1.1")
        self.assertEqual(offers["v1.1"]["author"], "allan")
        self.assertGreater(offers["v1.1"]["ts"], 0)
        self.assertEqual(offers["v1.0"]["sensitive_n"], 1)               # a primeira não tem com o que comparar: sempre exige atenção
        for o in offers.values():
            self.assertTrue(os.path.isfile(os.path.join(self.state, "apks", o["sha256"] + ".apk")))
        data = json.load(open(os.path.join(self.state, "apk-offers.json")))
        self.assertEqual(len(data["offers"]), 2)

    def test_02_does_not_download_again_and_is_throttled(self):
        self.d.refresh_app_offers(force=True)
        n = self.gh.downloads
        self.d.refresh_app_offers(force=True)
        self.assertEqual(self.gh.downloads, n)                            # já tinha o arquivo
        self.assertEqual(self.d.refresh_app_offers(), [])                 # sem force, dentro do intervalo: não consulta

    def test_03_errors_are_reported_not_raised(self):
        class Boom(FakeGitHub):
            def releases(self, repo):
                raise OSError("sem rede")
        self.d.github = lambda token: Boom([], {})
        self.d.refresh_app_offers(force=True)
        data = json.load(open(os.path.join(self.state, "apk-offers.json")))
        self.assertEqual(data["errors"][0]["app"], "filtro")
        self.assertIn("sem rede", data["errors"][0]["error"])

    def test_03b_local_directory_source(self):
        d = os.path.join(self.tmp.name, "local")
        os.makedirs(d)
        open(os.path.join(d, "nottoday-0.2.1.apk"), "wb").write(b"apk local")
        open(os.path.join(d, "leia-me.txt"), "w").write("ignorado")
        self.d.reg["nt"] = {"type": "android_app", "source": "dir", "dir": d, "pkg": "com.allan.nottoday"}
        offers = [o for o in self.d.refresh_app_offers(force=True) if o["app"] == "nt"]
        self.assertEqual(len(offers), 1)
        import hashlib
        self.assertEqual(offers[0]["sha256"], hashlib.sha256(b"apk local").hexdigest())
        self.assertEqual((offers[0]["tag"], offers[0]["pkg"], offers[0]["author"], offers[0]["sensitive_n"]), ("nottoday-0.2.1", "com.allan.nottoday", "local", 1))
        self.assertTrue(os.path.isfile(os.path.join(self.state, "apks", offers[0]["sha256"] + ".apk")))

    def test_03c_private_https_repo_uses_the_token_for_git(self):
        tf = os.path.join(self.tmp.name, "tok")
        open(tf, "w").write("ghp_segredo\n")
        env = self.d._env({"repo": "https://github.com/x/y.git", "token_file": tf})
        self.assertIn("Authorization: Basic ", env["GIT_CONFIG_VALUE_0"])
        self.assertNotIn("ghp_segredo", env["GIT_CONFIG_VALUE_0"])        # vai em base64, não em texto
        env2 = self.d._env({"repo": "git@github.com:x/y.git", "token_file": tf})
        self.assertNotIn("GIT_CONFIG_VALUE_0", env2)                      # ssh usa a chave, não o token

    def test_04_android_app_entries_are_not_treated_as_code_projects(self):
        self.assertEqual(self.d.refresh_offers(), [])                     # sem workdir nem passos: não quebra
        self.assertEqual(json.load(open(os.path.join(self.state, "offers.json")))["current"], {})


class ProjectAdd(unittest.TestCase):
    """O mestre cadastra um app novo pelo site: só app Android de repositório público de um dono permitido, nunca com passos no Pi."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.regfile, self.policy, self.state = os.path.join(t, "projects.json"), os.path.join(t, "policy.json"), os.path.join(t, "s")
        self.reg = {"guardian": {"repo": "/x", "workdir": "/y", "steps": [], "pkg": "com.guardian.x"}}
        json.dump(self.reg, open(self.regfile, "w"))
        json.dump({"allowed_owners": ["Allan"]}, open(self.policy, "w"))
        self.gh = FakeGitHub([], {})
        self.d = Deployer(self.reg, self.state, github=lambda token: self.gh, registry_path=self.regfile, policy_path=self.policy)

    def tearDown(self):
        self.tmp.cleanup()

    def req(self, **kw):
        return {"kind": "project_add", "name": "triagem", "github": "Allan/Triagem", "pkg": "com.allan.triagem", "guardian": "g1", "ts": 1, **kw}

    def test_01_registers_an_android_app_and_persists_it(self):
        res = self.d.project_add(self.req())
        self.assertTrue(res["ok"], res)
        saved = json.load(open(self.regfile))
        e = saved["triagem"]
        self.assertEqual((e["type"], e["github"], e["pkg"], e["tag_prefix"]), ("android_app", "Allan/Triagem", "com.allan.triagem", "v"))
        self.assertNotIn("steps", e)                       # nunca roda nada no Pi
        self.assertNotIn("workdir", e)
        self.assertNotIn("token_file", e)                  # só repositório público
        self.assertIn("triagem", self.d.reg)
        self.assertIn(".github/workflows/*", e["sensitive"])

    def test_02_refusals(self):
        for kw, why in (({"github": "Outro/App"}, "dono"), ({"name": "guardian"}, "nome"), ({"pkg": "com.guardian.x"}, "pacote"),
                        ({"github": "allan/triagem", "name": "outro", "pkg": "com.allan.outro"}, "repositório")):
            if why == "repositório":
                self.d.project_add(self.req())
            res = self.d.project_add(self.req(**kw))
            self.assertFalse(res["ok"], (kw, res))
            self.assertIn(why, res["msg"])

    def test_03_private_or_missing_repository_is_refused(self):
        def boom(token):
            raise RuntimeError("HTTP 404")
        d = Deployer(self.reg, self.state, github=boom, registry_path=self.regfile, policy_path=self.policy)
        res = d.project_add(self.req())
        self.assertFalse(res["ok"])
        self.assertIn("token", res["msg"])                  # sem token no Pi, a mensagem manda configurar o token
        self.assertNotIn("triagem", json.load(open(self.regfile)))

    def test_03b_private_repository_uses_the_pi_token(self):
        tok = os.path.join(self.tmp.name, "github_token")
        open(tok, "w").write("segredo\n")
        json.dump({"allowed_owners": ["Allan"], "token_file": tok}, open(self.policy, "w"))
        seen = []

        def gh(token):
            seen.append(token)
            if token is None:
                raise RuntimeError("HTTP 404")             # sem token o repositório não existe: é privado
            return self.gh
        d = Deployer(self.reg, self.state, github=gh, registry_path=self.regfile, policy_path=self.policy)
        res = d.project_add(self.req())
        self.assertTrue(res["ok"], res)
        self.assertIn("privado", res["msg"])
        self.assertEqual(seen, [None, "segredo"])           # tenta sem segredo primeiro
        self.assertEqual(json.load(open(self.regfile))["triagem"]["token_file"], tok)

    def test_03c_private_repository_the_token_cannot_see_is_refused(self):
        tok = os.path.join(self.tmp.name, "github_token")
        open(tok, "w").write("segredo")
        json.dump({"allowed_owners": ["Allan"], "token_file": tok}, open(self.policy, "w"))

        def gh(token):
            raise RuntimeError("HTTP 404")
        d = Deployer(self.reg, self.state, github=gh, registry_path=self.regfile, policy_path=self.policy)
        res = d.project_add(self.req())
        self.assertFalse(res["ok"])
        self.assertIn("token", res["msg"])
        self.assertNotIn("triagem", json.load(open(self.regfile)))

    def test_04_without_a_policy_file_nobody_is_allowed(self):
        d = Deployer(self.reg, self.state, github=lambda token: self.gh, registry_path=self.regfile, policy_path=os.path.join(self.tmp.name, "nao-existe.json"))
        self.assertFalse(d.project_add(self.req())["ok"])

    def test_05_inbox_request_is_processed_once_and_recorded(self):
        with open(os.path.join(self.state, "inbox", "1-1-add-triagem.json"), "w") as f:
            json.dump(self.req(), f)
        (res,) = self.d.process_inbox()
        self.assertTrue(res["ok"], res)
        self.assertEqual(self.d.status["history"][0]["project"], "triagem")
        self.assertEqual(os.listdir(os.path.join(self.state, "inbox")), [])
        bad = {"kind": "project_add", "name": "x", "github": "Allan/x.git", "pkg": "com.a.b"}
        with open(os.path.join(self.state, "inbox", "2-2-add-x.json"), "w") as f:
            json.dump(bad, f)
        (res2,) = self.d.process_inbox()
        self.assertFalse(res2["ok"])
        self.assertNotIn("x", json.load(open(self.regfile)))


class DeployDirOwnership(unittest.TestCase):
    """O deploy roda git e docker como root dentro da pasta do projeto: pasta que um usuário comum escreve não é confiável."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = os.path.realpath(self.tmp.name)
        self.wd = os.path.join(t, "proj")
        os.makedirs(os.path.join(self.wd, ".git"))
        open(os.path.join(self.wd, "a.txt"), "w").write("x")
        os.chmod(t, 0o755)
        self.reg = {"p": {"repo": "/x", "workdir": self.wd, "steps": []}}

    def tearDown(self):
        self.tmp.cleanup()

    def dep(self, uid):
        return Deployer(self.reg, os.path.join(self.tmp.name, "s"), trusted_uid=uid)

    def test_owner_other_than_trusted_is_refused(self):
        why = self.dep(os.getuid() + 1)._unsafe_project_dirs("p")     # as pastas são do usuário dos testes, não do "root" esperado
        self.assertIn("não é só do root", why)

    def test_trusted_owner_with_safe_modes_is_accepted(self):
        self.assertIsNone(self.dep(os.getuid())._unsafe_project_dirs("p"))

    def test_group_or_world_writable_is_refused(self):
        os.chmod(self.wd, 0o777)
        self.assertIsNotNone(self.dep(os.getuid())._unsafe_project_dirs("p"))
        os.chmod(self.wd, 0o755)
        os.chmod(os.path.join(self.wd, "a.txt"), 0o666)
        self.assertIn("a.txt", self.dep(os.getuid())._unsafe_project_dirs("p"))

    def test_unwritable_parent_chain_matters(self):
        os.chmod(os.path.dirname(self.wd), 0o777)                     # quem escreve no diretório de cima pode trocar a pasta inteira
        self.assertIsNotNone(self.dep(os.getuid())._unsafe_project_dirs("p"))

    def test_a_refused_directory_stops_the_deploy_before_any_git(self):
        calls = []
        d = Deployer(self.reg, os.path.join(self.tmp.name, "s"), trusted_uid=os.getuid() + 1, run=lambda *a, **k: calls.append(a) or (0, ""))
        res = d.deploy({"project": "p", "commit": "a" * 40})
        self.assertFalse(res["ok"])
        self.assertIn("isolamento", res["msg"])
        self.assertEqual(calls, [])


class ExecutorQueuesProjectAdd(unittest.TestCase):
    def test_args_and_executor_queue(self):
        ok = {"name": "triagem", "github": "Allan/Triagem", "pkg": "com.allan.triagem"}
        cmds.check_project_add_args(ok)
        for bad in ({**ok, "extra": 1}, {"name": "triagem", "github": "Allan/Triagem"}, {**ok, "name": "Triagem"}, {**ok, "github": "https://github.com/a/b"},
                    {**ok, "github": "Allan/Triagem.git"}, {**ok, "pkg": "semponto"}, {**ok, "github": "../x"}):
            with self.assertRaises(cmds.CommandError, msg=bad):
                cmds.check_project_add_args(bad)
        trust = cmds.Trust("rp", "https://rp", {"m": cmds.Guardian("Gandalf", {}, cmds.ROLE_MASTER), "a": cmds.Guardian("Mor", {}, cmds.ROLE_ADMIN)})
        cmd = lambda g: {"guardian": g, "type": cmds.T_PROJECT_ADD, "args": ok}
        self.assertEqual(cmds.check_author(trust, cmd("m")).name, "Gandalf")
        with self.assertRaises(cmds.CommandError):
            cmds.check_author(trust, cmd("a"))              # só o mestre
        self.assertIn(cmds.T_PROJECT_ADD, cmds.EXECUTOR_MASTER_TYPES)


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
