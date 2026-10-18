import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import command, envelope  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.protocol import b64, commands as cmds  # noqa: E402
from test_roles import register  # noqa: E402

NOW = int(time.time())
SHA = "a" * 64
INSTALL_WINGET = {"name": "Git", "source": "winget", "id": "Git.Git", "version": "2.44.0"}
INSTALL_URL = {"name": "Meu instalador", "source": "url", "url": "https://exemplo.com/setup.msi", "sha256": SHA, "kind": "msi"}
RUN = {"name": "Ver versão", "script": "Get-ComputerInfo | Select WindowsVersion", "timeout_s": 60}


class WinArgs(unittest.TestCase):
    def ok(self, type_, args, **kw):
        cmds.check_win_args(type_, {**args, "not_after": NOW + 3600}, NOW, **kw)

    def bad(self, type_, args, msg=None, **kw):
        with self.assertRaises(cmds.CommandError, msg=msg or str(args)[:60]):
            cmds.check_win_args(type_, args, NOW, **kw)

    def test_valid_commands(self):
        self.ok(cmds.T_WIN_INSTALL, INSTALL_WINGET)
        self.ok(cmds.T_WIN_INSTALL, {**INSTALL_URL, "kind": "exe", "args": "/S /norestart"})
        self.ok(cmds.T_WIN_RUN, RUN)
        self.ok(cmds.T_WIN_RUN, {"script": "Write-Output 'ação'"})

    def test_install_rejects_bad_input(self):
        base = {"not_after": NOW + 60}
        for a in ({"name": "", "source": "winget", "id": "Git.Git"}, {"name": "x", "source": "winget", "id": "git;rm"},
                  {"name": "x", "source": "winget", "id": "Git.Git", "version": "1 2"}, {"name": "x", "source": "outro"},
                  {**INSTALL_URL, "url": "http://exemplo.com/a.msi"}, {**INSTALL_URL, "url": "https://127.0.0.1/a.msi"},
                  {**INSTALL_URL, "url": "https://user:pw@exemplo.com/a.msi"}, {**INSTALL_URL, "url": "https://localhost/a.msi"},
                  {**INSTALL_URL, "sha256": "A" * 64}, {**INSTALL_URL, "sha256": "a" * 63}, {**INSTALL_URL, "kind": "bat"},
                  {**INSTALL_URL, "args": "x" * 201}, {**INSTALL_URL, "args": "a\nb"}):
            self.bad(cmds.T_WIN_INSTALL, {**a, **base})

    def test_run_rejects_bad_input(self):
        base = {"not_after": NOW + 60}
        for a in ({}, {"script": "   "}, {"script": "a\x00b"}, {"script": "x" * 6001}, {"script": "a", "shell": "cmd"},
                  {"script": "a", "timeout_s": 1}, {"script": "a", "timeout_s": 99999}, {"script": "a", "timeout_s": True}):
            self.bad(cmds.T_WIN_RUN, {**a, **base})

    def test_expiry(self):
        self.bad(cmds.T_WIN_RUN, {"script": "a"}, "sem validade")
        self.bad(cmds.T_WIN_RUN, {"script": "a", "not_after": NOW - 1}, "vencido")
        self.bad(cmds.T_WIN_RUN, {"script": "a", "not_after": NOW + cmds.WIN_MAX_AGE_S + 60}, "longe demais", creating=True)
        cmds.check_win_args(cmds.T_WIN_RUN, {"script": "a", "not_after": NOW + cmds.WIN_MAX_AGE_S + 60}, NOW)  # o agente não impõe o teto

    def test_unknown_type(self):
        with self.assertRaises(cmds.CommandError):
            cmds.check_win_request("win_outra", {})


class WinGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")           # guardião-mor
        st, inv, _ = cls.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Bia"})  # guardião comum
        cls.dc, cls.da, cls.dgid = register(cls.env, inv["token"])
        cls.pckey, cls.pc = cls.env.pair_device(cls.c, name="Meu PC")
        cls.phkey, cls.ph = cls.env.pair_device(cls.c, name="Celular")
        cls.signed = lambda self, key, dev, method, path, body=None: self.env.client().signed(key, method, f"/v1/devices/{dev}{path}", body)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def pc_report(self, **extra):
        st, r, _ = self.signed(self.pckey, self.pc, "POST", "/report", {"kind": "device", "platform": "windows", **extra})
        self.assertEqual(st, 200, r)

    def send(self, c, a, gid, dev, type_, args):
        (st, r, _), _ = self.env.sign_post(c, a, gid, dev, type_, args)
        return st, r

    def test_01_pc_must_declare_windows_before_getting_win_commands(self):
        args = {**RUN, "not_after": NOW + 600}
        self.assertEqual(self.send(self.c, self.a, self.gid, self.pc, cmds.T_WIN_RUN, args)[0], 400)   # ainda sem relatório
        self.pc_report()
        self.signed(self.phkey, self.ph, "POST", "/report", {"kind": "device"})
        self.assertEqual(self.send(self.c, self.a, self.gid, self.ph, cmds.T_WIN_RUN, args)[0], 400)   # o celular nunca
        st, r = self.send(self.c, self.a, self.gid, self.pc, cmds.T_WIN_RUN, args)
        self.assertEqual((st, r["status"]), (200, "ready"), r)

    def test_02_only_admins_may_send_win_commands(self):
        args = {**INSTALL_WINGET, "not_after": NOW + 600}
        st, r = self.send(self.dc, self.da, self.dgid, self.pc, cmds.T_WIN_INSTALL, args)
        self.assertEqual(st, 403, r)
        st, r = self.send(self.c, self.a, self.gid, self.pc, cmds.T_WIN_INSTALL, args)
        self.assertEqual((st, r["status"]), (200, "ready"), r)        # uma passkey basta

    def test_03_gateway_rejects_bad_or_stale_win_commands(self):
        for args in ({**RUN, "not_after": NOW - 5}, {**RUN, "not_after": NOW + cmds.WIN_MAX_AGE_S + 600}, {**RUN}, {"script": "", "not_after": NOW + 60},
                     {**INSTALL_URL, "url": "http://x.com/a.msi", "not_after": NOW + 60}):
            st, r = self.send(self.c, self.a, self.gid, self.pc, cmds.T_WIN_RUN if "script" in args else cmds.T_WIN_INSTALL, args)
            self.assertEqual(st, 400, (args, r))

    def test_04_pc_requests_an_install_and_guardian_approves_exactly_that(self):
        st, r, _ = self.signed(self.pckey, self.pc, "POST", "/requests", {"kind": "install", "payload": INSTALL_WINGET})
        self.assertEqual(st, 200, r)
        reqs = [x for x in self.c.call("GET", "/v1/requests")[1]["items"] if x["kind"] == "install"]
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]["payload"], INSTALL_WINGET)
        self.assertIn("Git.Git 2.44.0", reqs[0]["text"])
        rid = reqs[0]["id"]
        # comando diferente do pedido (outra versão): recusado
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.pc, cmds.T_WIN_INSTALL, {**INSTALL_WINGET, "version": "9.9", "not_after": NOW + 600})
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/resolve", {"cmd": r["id"]})[0], 400)
        # o comando certo fecha o pedido; o guardião comum não consegue
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.pc, cmds.T_WIN_INSTALL, {**INSTALL_WINGET, "not_after": NOW + 600})
        self.assertEqual(self.dc.call("POST", f"/v1/requests/{rid}/resolve", {"cmd": r["id"]})[0], 403)
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/resolve", {"cmd": r["id"]})[0], 200)
        mine = self.signed(self.pckey, self.pc, "GET", "/requests")[1]["admin"]
        self.assertEqual([(x["id"], x["status"]) for x in mine if x["id"] == rid], [(rid, "approved")])
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/resolve", {"cmd": r["id"]})[0], 404)   # já resolvido

    def test_05_deny_a_command_request(self):
        st, r, _ = self.signed(self.pckey, self.pc, "POST", "/requests", {"kind": "command", "payload": RUN})
        self.assertEqual(st, 200, r)
        rid = next(x["id"] for x in self.c.call("GET", "/v1/requests")[1]["items"] if x["kind"] == "command")
        self.assertEqual(self.dc.call("POST", f"/v1/requests/{rid}/dismiss", {})[0], 403)   # guardião comum não nega isto
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/dismiss", {})[0], 200)
        mine = self.signed(self.pckey, self.pc, "GET", "/requests")[1]["admin"]
        self.assertIn((rid, "denied"), [(x["id"], x["status"]) for x in mine])
        self.assertFalse([x for x in self.c.call("GET", "/v1/requests")[1]["items"] if x["id"] == rid])

    def test_06_request_validation_and_scope(self):
        for body in ({"kind": "install", "payload": {"name": "x", "source": "winget", "id": "a;b"}}, {"kind": "command", "payload": {"script": ""}},
                     {"kind": "install", "payload": "texto"}, {"kind": "install"}):
            self.assertEqual(self.signed(self.pckey, self.pc, "POST", "/requests", body)[0], 400, body)
        self.assertEqual(self.signed(self.phkey, self.ph, "POST", "/requests", {"kind": "install", "payload": INSTALL_WINGET})[0], 403)   # celular não pede

    def test_07_open_requests_are_capped_per_device(self):
        n = 0
        for i in range(15):
            st, _, _ = self.signed(self.pckey, self.pc, "POST", "/requests", {"kind": "command", "payload": {"script": f"Write-Output {i}"}})
            n += st == 200
        self.assertLessEqual(n, 10)

    def test_08_payload_is_not_exposed_on_other_kinds(self):
        self.signed(self.pckey, self.pc, "POST", "/requests", {"kind": "other", "text": "oi"})
        for x in self.c.call("GET", "/v1/requests")[1]["items"]:
            if x["kind"] not in ("install", "command"):
                self.assertNotIn("payload", x)

    def test_06b_install_request_from_a_local_file(self):
        body = {"name": "Wireshark", "source": "file", "path": "C:\\Users\\allan\\Downloads\\Wireshark-4.6.9-x64.exe", "sha256": SHA, "kind": "exe", "args": "/S", "publisher": "Wireshark Foundation"}
        st, r, _ = self.signed(self.pckey, self.pc, "POST", "/requests", {"kind": "install", "payload": body})
        self.assertEqual(st, 200, r)
        q = next(x for x in self.c.call("GET", "/v1/requests")[1]["items"] if x["kind"] == "install" and x["payload"].get("source") == "file")
        self.assertIn("Instalar Wireshark (arquivo Wireshark-4.6.9-x64.exe)", q["text"])
        self.assertEqual(q["payload"]["publisher"], "Wireshark Foundation")
        for bad in ({**body, "path": "\\\\srv\\pasta\\a.exe"}, {**body, "kind": "msi"}, {**body, "sha256": "x"}):
            self.assertEqual(self.signed(self.pckey, self.pc, "POST", "/requests", {"kind": "install", "payload": bad})[0], 400)
        (st, r2, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.pc, cmds.T_WIN_INSTALL, {**body, "not_after": NOW + 600})
        self.assertEqual(st, 200, r2)
        self.assertEqual(self.c.call("POST", f"/v1/requests/{q['id']}/resolve", {"cmd": r2["id"]})[0], 200)


if __name__ == "__main__":
    unittest.main()


class IdleArgs(unittest.TestCase):
    def test_idle_s_validado(self):
        base = {"name": "x", "source": "winget", "id": "Git.Git"}
        cmds.check_win_request(cmds.T_WIN_INSTALL, {**base, "idle_s": 0})
        cmds.check_win_request(cmds.T_WIN_INSTALL, {**base, "idle_s": 120})
        for bad in (10, 1801, "2", True, -1):
            with self.assertRaises(cmds.CommandError):
                cmds.check_win_request(cmds.T_WIN_INSTALL, {**base, "idle_s": bad})
