"""Correções da revisão de segurança de 2026-11-12 que valem com um deploy normal (sem reinstalar o deployer)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from gwharness import Env  # noqa: E402
from guardian.executor.veto import Veto  # noqa: E402
from guardian.protocol import commands as cmds  # noqa: E402

SHA = "a" * 64


class VetoCoversParent(unittest.TestCase):
    def test_releasing_the_parent_of_a_vetoed_site_is_refused_in_regex_mode(self):
        v = Veto(None, ["chat.exemplo.com.br"])
        self.assertIn("cobre um site vetado", v.reason("exemplo.com.br", True))
        self.assertIn("cobre um site vetado", v.reason("www.exemplo.com.br", True))   # a regra tira o www.
        self.assertIsNone(v.reason("exemplo.com.br", False))       # exata: só libera o próprio domínio, não o vetado
        self.assertIsNone(v.reason("outro.com.br", True))
        self.assertIsNone(v.reason("loja.exemplo.com.br", True))   # irmão do vetado: a regra não o cobre


class MsiArgs(unittest.TestCase):
    def req(self, args, source="url"):
        base = {"name": "App", "sha256": SHA, "kind": "msi", "args": args}
        base.update({"source": "url", "url": "https://exemplo.com/a.msi"} if source == "url" else {"source": "file", "path": "C:\\Users\\a\\a.msi"})
        return base

    def test_properties_pass(self):
        for a in ("", "ALLUSERS=1", 'INSTALLDIR="C:\\Program Files\\App" ALLUSERS=1  REBOOT=ReallySuppress', "ADDLOCAL=ALL"):
            for src in ("url", "file"):
                cmds.check_win_request(cmds.T_WIN_INSTALL, self.req(a, src))

    def test_options_and_code_carrying_properties_are_refused(self):
        bad = ("TRANSFORMS=C:\\Users\\a\\x.mst", "transforms=x.mst", "PATCH=C:\\x.msp", "/update x.msp", "/i C:\\outro.msi", "/p x",
               "ALLUSERS=1 /qb", 'X="sem fim', "-i x", "A= /update x.msp")
        for a in bad:
            for src in ("url", "file"):
                with self.assertRaises(cmds.CommandError, msg=a):
                    cmds.check_win_request(cmds.T_WIN_INSTALL, self.req(a, src))

    def test_exe_args_are_unchanged(self):
        cmds.check_win_request(cmds.T_WIN_INSTALL, {"name": "P", "source": "url", "url": "https://e.com/p.exe", "sha256": SHA, "kind": "exe", "args": "/S /D=C:\\x"})


class OnlyTheMasterPairsOrForgetsTheExecutor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.cm, _, cls.gm = cls.env.register_guardian("Gandalf")
        cls.ca, _, cls.ga = cls.env.register_guardian("Mor")
        cls.env.store.set_role(cls.gm, "master")

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def test_pairing(self):
        self.assertEqual(self.ca.call("POST", "/v1/pairings", {"kind": "executor"})[0], 403)
        self.assertEqual(self.ca.call("POST", "/v1/pairings", {"kind": "device"})[0], 200)   # aparelho continua com o guardião-mor
        self.assertEqual(self.cm.call("POST", "/v1/pairings", {"kind": "executor"})[0], 200)

    def test_forget(self):
        _, ex = self.env.pair_device(self.cm, "executor", "Pi")
        _, dev = self.env.pair_device(self.ca, "device", "Tab")
        self.assertEqual(self.ca.call("POST", f"/v1/devices/{ex}/forget", {})[0], 403)
        self.assertEqual(self.ca.call("POST", f"/v1/devices/{dev}/forget", {})[0], 200)
        self.assertEqual(self.cm.call("POST", f"/v1/devices/{ex}/forget", {})[0], 200)


if __name__ == "__main__":
    unittest.main()
