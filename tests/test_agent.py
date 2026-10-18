import http.client
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import command, envelope  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.agent import actions  # noqa: E402
from guardian.agent.agent import Agent, AgentConfig, pair  # noqa: E402
from guardian.agent.ui import UiServer  # noqa: E402
from guardian.protocol import commands as cmds  # noqa: E402
from test_executor import pairing_string  # noqa: E402
from test_roles import register  # noqa: E402

SHA = "b" * 64


class FakeSys(actions.Sys):
    """Sem Windows: guarda o que seria executado e devolve respostas combinadas."""

    def __init__(self):
        super().__init__(tempfile.mkdtemp())
        self.calls, self.downloads, self.replies, self.hash = [], [], [], SHA
        self.ips = ["100.64.0.9", "192.168.1.5"]

    def run(self, cmd, timeout):
        self.calls.append((cmd, timeout))
        if isinstance(cmd, list) and cmd and str(cmd[0]).endswith("powershell.exe"):
            self.script = open(cmd[-1], encoding="utf-8-sig").read()  # o arquivo existe enquanto o script roda
        return self.replies.pop(0) if self.replies else (0, "ok")

    def download(self, url, dest, max_bytes=0):
        self.downloads.append(url)
        open(dest, "wb").write(b"x")
        return self.hash

    def winget(self):
        return "winget.exe"

    def tailscale_ips(self):
        return self.ips


class AgentEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        st, inv, _ = cls.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Bia"})
        cls.dc, cls.da, cls.dgid = register(cls.env, inv["token"])
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cfg = AgentConfig(cls.tmp.name)
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "device"})
        pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]), "pc-de-teste")
        cls.now = [float(int(time.time()))]
        cls.sys = FakeSys()
        cls.ag = Agent(cls.cfg, cls.sys, now=lambda: cls.now[0])
        cls.dev = cls.ag.dev
        cls.ag.report()

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.tmp.cleanup()

    def send(self, type_, args, who=None):
        c, a, g = who or (self.c, self.a, self.gid)
        (st, r, _), _ = self.env.sign_post(c, a, g, self.dev, type_, {**args, "not_after": int(self.now[0]) + 3600})
        self.assertEqual(st, 200, r)

    def last(self):
        return self.ag.last_executed

    def audit(self):
        return [i["text"] for i in self.c.call("GET", "/v1/audit")[1]["items"] if i["kind"] == "executed"]

    def test_01_report_declares_the_pc(self):
        d = next(x for x in self.c.call("GET", "/v1/devices")[1]["devices"] if x["id"] == self.dev)
        self.assertEqual(d["report"]["platform"], "windows")
        self.assertEqual(d["report"]["tsIps"], ["100.64.0.9"])        # só endereço da Tailscale vale
        self.assertIn(self.gid, d["report"]["trust"])
        self.assertEqual(d["name"], "pc-de-teste")

    def test_02_run_script_executes_and_reports_output(self):
        self.sys.replies.append((0, "Windows 11\n"))
        self.send(cmds.T_WIN_RUN, {"name": "versão", "script": "Get-ComputerInfo", "timeout_s": 90})
        self.assertEqual(self.ag.step(wait_s=0), 1)
        self.assertTrue(self.last()["ok"], self.last())
        cmd, timeout = self.sys.calls[-1]
        self.assertEqual(cmd[:6], ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        self.assertEqual((timeout, self.sys.script), (90, "Get-ComputerInfo"))
        self.assertFalse(os.path.exists(cmd[-1]))                        # apagou o script
        self.ag.report()
        d = next(x for x in self.c.call("GET", "/v1/devices")[1]["devices"] if x["id"] == self.dev)
        self.assertEqual((d["report"]["runs"][-1]["out"], d["report"]["runs"][-1]["ok"]), ("Windows 11", True))
        self.assertTrue(any("win_run ok" in t for t in self.audit()), self.audit())

    def test_03_failed_script_is_reported_as_failed(self):
        self.sys.replies.append((1, "erro: sem permissão"))
        self.send(cmds.T_WIN_RUN, {"script": "exit 1"})
        self.ag.step(wait_s=0)
        self.assertFalse(self.last()["ok"])
        self.assertIn("código 1", self.last()["msg"])
        self.assertFalse(self.ag.runs[-1]["ok"])

    def test_04_winget_install_builds_a_silent_exact_command(self):
        self.send(cmds.T_WIN_INSTALL, {"name": "Git", "source": "winget", "id": "Git.Git", "version": "2.44.0"})
        self.ag.step(wait_s=0)
        self.assertTrue(self.last()["ok"], self.last())
        argv = self.sys.calls[-1][0]
        self.assertEqual(argv[:4], ["winget.exe", "install", "--id", "Git.Git"])
        for flag in ("--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--version") + 1], "2.44.0")
        self.assertEqual(argv[argv.index("--source") + 1], "winget")

    def test_05_installer_by_link_checks_the_hash_before_running(self):
        url = {"name": "App", "source": "url", "url": "https://exemplo.com/setup.msi", "sha256": SHA, "kind": "msi", "args": "ALLUSERS=1"}
        n = len(self.sys.calls)
        self.send(cmds.T_WIN_INSTALL, url)
        self.ag.step(wait_s=0)
        self.assertTrue(self.last()["ok"], self.last())
        self.assertIn('msiexec /i "', self.sys.calls[-1][0])
        self.assertTrue(self.sys.calls[-1][0].endswith('/qn /norestart ALLUSERS=1'))
        self.sys.hash = "c" * 64                                          # arquivo diferente do aprovado
        n = len(self.sys.calls)
        self.send(cmds.T_WIN_INSTALL, {**url, "kind": "exe"})
        self.ag.step(wait_s=0)
        self.assertFalse(self.last()["ok"])
        self.assertIn("SHA-256", self.last()["msg"])
        self.assertEqual(len(self.sys.calls), n)                          # nada foi executado
        self.sys.hash = SHA

    def test_06_exe_installer_and_reboot_code(self):
        self.sys.replies.append((3010, "reiniciar"))
        self.send(cmds.T_WIN_INSTALL, {"name": "Prog", "source": "url", "url": "https://exemplo.com/p.exe", "sha256": SHA, "kind": "exe", "args": "/S"})
        self.ag.step(wait_s=0)
        self.assertTrue(self.last()["ok"])
        self.assertIn("reiniciar", self.last()["msg"])
        self.assertTrue(self.sys.calls[-1][0].endswith('setup.exe" /S'))

    def test_07_agent_refuses_what_the_gateway_would_not_catch(self):
        n = len(self.sys.calls)
        # domínios-guardião assinando direto para o agente (sem passar pelo gateway)
        p = command(self.dev, self.dgid, 1, cmds.T_WIN_RUN, {"script": "whoami", "not_after": int(self.now[0]) + 60})
        self.ag.handle(envelope(p, self.da.sign_command(self.dgid, p)))
        self.assertIn("recusado", self.last()["msg"])
        # comando vencido: o relógio do agente manda
        self.send(cmds.T_WIN_RUN, {"script": "vencido"})
        self.now[0] += 7200
        self.ag.step(wait_s=0)
        self.assertFalse(self.last()["ok"])
        self.assertIn("venceu", self.last()["msg"])
        self.now[0] -= 7200
        self.assertEqual(len(self.sys.calls), n)

    def test_08_replay_and_restart_do_not_run_twice(self):
        n = len(self.sys.calls)
        self.send(cmds.T_WIN_RUN, {"script": "uma vez só"})
        got = self.ag.gw.call("GET", f"/v1/devices/{self.dev}/commands?after={self.ag.state.data['after']}&wait=0")
        env = got["commands"][0]["envelope"]
        self.ag.handle(env)
        self.assertEqual(len(self.sys.calls), n + 1)
        self.ag.handle(env)                                                # o mesmo envelope de novo
        self.assertIn("recusado", self.last()["msg"])
        again = Agent(self.cfg, self.sys, now=lambda: self.now[0])         # reinício: o contador gasto ficou no disco
        again.handle(env)
        self.assertEqual(len(self.sys.calls), n + 1)
        self.ag.state.data["after"] = got["commands"][0]["seq"]
        self.ag.state.save()

    def test_09_not_a_windows_command_is_unsupported(self):
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, "set_config", {"x": 1})
        self.assertEqual(st, 200)                                         # o gateway deixa passar (é tipo de aparelho)...
        self.ag.step(wait_s=0)
        self.assertFalse(self.last()["ok"])                                # ...mas o agente não faz
        self.assertIn("não suportado", self.last()["msg"])

    def test_10_local_ui_state_and_requests(self):
        self.ag.gw.call("POST", f"/v1/devices/{self.dev}/report", {"kind": "device", "platform": "windows"})
        srv = UiServer(self.ag, 0)
        srv.start()
        try:
            port = srv.port

            def call(method, path, body=None, host=None, origin=None, extra=None):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                h = {"Host": host or f"localhost:{port}", **(extra or {})}
                if origin:
                    h["Origin"] = origin
                if body is not None:
                    h["Content-Type"] = "application/json"
                c.request(method, path, json.dumps(body) if body is not None else None, h)
                r = c.getresponse()
                data = r.read()
                return r.status, (json.loads(data) if r.getheader("Content-Type", "").startswith("application/json") else data)

            ok_post = {"origin": f"http://localhost:{port}", "extra": {"X-Guardian-Agent": "1"}}
            st, s = call("GET", "/api/state")
            self.assertEqual((st, s["gateway_ok"], s["dev"]), (200, True, self.dev))
            self.assertEqual(call("GET", "/", host="evil.example")[0], 403)                      # DNS rebinding
            self.assertEqual(call("GET", "/api/state", host=f"localhost:{port + 1}")[0], 403)
            self.assertEqual(call("POST", "/api/request", {"kind": "install", "payload": {}}, **{"origin": "http://evil.example", "extra": {"X-Guardian-Agent": "1"}})[0], 403)
            self.assertEqual(call("POST", "/api/request", {"kind": "install", "payload": {}}, origin=f"http://localhost:{port}")[0], 403)   # sem o cabeçalho
            self.assertEqual(call("POST", "/api/request", {"kind": "outro"}, **ok_post)[0], 400)
            st, r = call("POST", "/api/request", {"kind": "install", "payload": {"name": "x", "source": "winget", "id": "a;b"}}, **ok_post)
            self.assertEqual(st, 400, r)
            self.assertIn("winget", r["error"])
            st, r = call("POST", "/api/request", {"kind": "install", "payload": {"name": "7-Zip", "source": "winget", "id": "7zip.7zip"}}, **ok_post)
            self.assertEqual(st, 200, r)
            st, s = call("GET", "/api/state")
            self.assertEqual([a["status"] for a in s["admin"]][:1], ["open"])
            self.assertIn("7zip.7zip", s["admin"][0]["text"])
            for path, ctype in (("/", b"<!doctype html>"), ("/agent.js", b"import"), ("/ui.js", b"export"), ("/style.css", b":root")):
                st, data = call("GET", path)
                self.assertEqual(st, 200, path)
                self.assertIn(ctype, data, path)
        finally:
            srv.shutdown()
            srv.server_close()


class ActionsUnit(unittest.TestCase):
    def test_clip_keeps_head_and_tail(self):
        long = "A" * 3000 + "B" * 3000
        out = actions.clip(long, 1000)
        self.assertTrue(out.startswith("A" * 500) and out.endswith("B" * 500))
        self.assertLess(len(out), 1100)
        self.assertEqual(actions.clip("  curto  "), "curto")

    def test_https_only_redirect(self):
        import urllib.error
        import urllib.request
        h = actions._HttpsOnly()
        req = urllib.request.Request("https://a.example/x")
        with self.assertRaises(urllib.error.URLError):
            h.redirect_request(req, None, 302, "Found", {}, "http://b.example/x")


if __name__ == "__main__":
    unittest.main()
