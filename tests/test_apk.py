import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))

from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, GatewayError, pair  # noqa: E402
from guardian.protocol import commands as cmds, devauth  # noqa: E402
from test_executor import pairing_string  # noqa: E402

NOW = float(int(time.time()))
APK = b"PK\x03\x04" + os.urandom(300_000)   # APK de mentira, maior que um pedaço de 64 KB
SHA = hashlib.sha256(APK).hexdigest()
PKG = "com.exemplo.filtro"


class InstallArgs(unittest.TestCase):
    def test_args_are_checked(self):
        ok = {"pkg": PKG, "sha256": SHA, "size": len(APK)}
        cmds.check_install_args(ok)
        cmds.check_install_args({**ok, "version_name": "1.2.0", "version_code": 12})
        for bad in ({**ok, "pkg": "semponto"}, {**ok, "pkg": "../x.y"}, {**ok, "sha256": SHA.upper()}, {**ok, "sha256": "abc"},
                    {**ok, "size": 0}, {**ok, "size": cmds.MAX_APK_BYTES + 1}, {**ok, "size": True}, {**ok, "extra": 1},
                    {**ok, "version_code": 0}, {"pkg": PKG, "sha256": SHA}):
            with self.assertRaises(cmds.CommandError, msg=bad):
                cmds.check_install_args(bad)

    def test_only_the_master_installs_apps(self):
        trust = cmds.Trust("rp", "https://rp", {"m": cmds.Guardian("Gandalf", {}, cmds.ROLE_MASTER), "a": cmds.Guardian("Mor", {}, cmds.ROLE_ADMIN),
                                                "d": cmds.Guardian("G", {}, cmds.ROLE_DOMAINS)})
        cmd = lambda g: {"guardian": g, "type": cmds.T_INSTALL_APP, "args": {"pkg": PKG, "sha256": SHA, "size": 5}}
        self.assertEqual(cmds.check_author(trust, cmd("m")).name, "Gandalf")
        for g in ("a", "d"):
            with self.assertRaises(cmds.CommandError):
                cmds.check_author(trust, cmd(g))
        self.assertNotIn(cmds.T_INSTALL_APP, cmds.EXECUTOR_MASTER_TYPES)   # o executor do Pi não instala app de celular


class ApkThroughTheGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Gandalf")
        cls.env.store.set_role(cls.gid, "master")
        cls.phone_key, cls.phone = cls.env.pair_device(cls.c, name="A56")
        cls.other_key, cls.other = cls.env.pair_device(cls.c, name="Tab")
        cls.fake = FakePihole()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dd = os.path.join(cls.tmp.name, "deploy")
        os.makedirs(os.path.join(cls.dd, "apks"))
        cls.cfg = ExecConfig(cls.tmp.name, cls.fake.url, "senha-app", "canario.example", deploy_dir=cls.dd)
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "executor"})
        pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]))
        cls.ex = Executor(cls.cfg, now=lambda: NOW)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.fake.close()
        cls.tmp.cleanup()

    def offers(self, sha=SHA):
        with open(os.path.join(self.dd, "apk-offers.json"), "w") as f:
            json.dump({"ts": 1, "offers": [{"app": "filtro", "pkg": PKG, "tag": "v1", "sha256": sha, "size": len(APK)}]}, f)

    def get(self, key, dev, sha):
        path = f"/v1/devices/{dev}/apk/{sha}"
        h = devauth.headers(key, "GET", path, b"", int(time.time()), os.urandom(9).hex())
        try:
            with urllib.request.urlopen(urllib.request.Request(f"http://localhost:{self.env.port}{path}", headers=h), timeout=20) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_01_executor_uploads_in_chunks_and_only_once(self):
        with open(os.path.join(self.dd, "apks", SHA + ".apk"), "wb") as f:
            f.write(APK)
        self.offers()
        self.assertEqual(self.ex.sync_apks(), 1)
        self.assertIn(SHA, self.env.store.apk_hashes())
        self.assertEqual(self.ex.sync_apks(), 0)               # já está lá
        self.assertEqual(len(os.listdir(os.path.join(self.env.tmp.name, "apks"))), 1)

    def test_02_content_that_does_not_match_the_hash_is_rejected(self):
        bad_sha = hashlib.sha256(b"outro").hexdigest()
        with open(os.path.join(self.dd, "apks", bad_sha + ".apk"), "wb") as f:
            f.write(APK)                                       # nome diz uma coisa, conteúdo é outro
        self.offers(bad_sha)
        with self.assertRaises(GatewayError) as cm:
            self.ex.sync_apks()
        self.assertEqual(cm.exception.status, 400)
        self.assertNotIn(bad_sha, self.env.store.apk_hashes())
        self.assertFalse(os.path.exists(os.path.join(self.env.tmp.name, "apks", bad_sha + ".apk")))
        self.assertFalse([n for n in os.listdir(os.path.join(self.env.tmp.name, "apks")) if n.endswith(".part")])

    def test_02b_install_waits_until_the_apk_is_at_the_gateway(self):
        missing = hashlib.sha256(b"ainda nao chegou").hexdigest()
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.phone, cmds.T_INSTALL_APP, {"pkg": PKG, "sha256": missing, "size": 5})
        self.assertEqual(st, 409, r)                                  # o contador não foi gasto: o comando nem entrou na fila
        self.assertEqual(self.c.call("GET", f"/v1/devices/{self.phone}/ctr")[1]["next"], 1)
        self.assertIn(SHA, self.c.call("GET", "/v1/devices")[1]["apks"])

    def test_03_phone_downloads_only_after_a_signed_install_command(self):
        self.assertEqual(self.get(self.phone_key, self.phone, SHA)[0], 403)         # sem comando assinado
        args = {"pkg": PKG, "sha256": SHA, "size": len(APK), "version_name": "1.0"}
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.phone, cmds.T_INSTALL_APP, args)
        self.assertEqual(st, 200, r)
        st, body = self.get(self.phone_key, self.phone, SHA)
        self.assertEqual(st, 200)
        self.assertEqual(hashlib.sha256(body).hexdigest(), SHA)                      # o arquivo inteiro, sem corromper
        self.assertEqual(self.get(self.other_key, self.other, SHA)[0], 403)         # outro aparelho não foi autorizado
        self.assertEqual(self.get(self.phone_key, self.phone, "0" * 64)[0], 403)     # nem outro hash

    def test_04_bad_commands_are_refused(self):
        args = {"pkg": PKG, "sha256": SHA, "size": len(APK)}
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.ex.dev, cmds.T_INSTALL_APP, args)
        self.assertEqual(st, 400, r)                                                 # o executor do Pi não instala app
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.phone, cmds.T_INSTALL_APP, {**args, "sha256": "zz"})
        self.assertEqual(st, 400, r)
        self.env.store.set_role(self.gid, "admin")
        try:
            (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.phone, cmds.T_INSTALL_APP, args)
            self.assertEqual(st, 403, r)                                             # guardião-mor sem ser mestre
        finally:
            self.env.store.set_role(self.gid, "master")

    def test_05_phone_cannot_upload_and_unauthenticated_cannot_download(self):
        path = f"/v1/devices/{self.phone}/apks/{SHA}"
        h = devauth.headers_digest(self.phone_key, "POST", path, SHA, int(time.time()), os.urandom(9).hex())
        req = urllib.request.Request(f"http://localhost:{self.env.port}{path}", data=APK[:100], method="POST", headers={**h, "Content-Length": "100"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=20)
        self.assertIn(cm.exception.code, (400, 403))                                 # aparelho não é executor
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(f"http://localhost:{self.env.port}/v1/devices/{self.phone}/apk/{SHA}", timeout=20)
        self.assertEqual(cm.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
