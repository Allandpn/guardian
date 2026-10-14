"""O crypto.js do site (WebCrypto) tem que casar com o Python: caixa do PIN, string de pareamento e comando."""
import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from guardian.executor.runner import parse_pairing  # noqa: E402
from guardian.protocol import b64, commands as cmds, devauth, pinbox  # noqa: E402

CLI = os.path.join(os.path.dirname(__file__), "webcrypto_cli.mjs")


def node(*args) -> str:
    return subprocess.run(["node", CLI, *args], capture_output=True, text=True, check=True, timeout=30).stdout.strip()


@unittest.skipUnless(shutil.which("node"), "node não instalado")
class WebCryptoInterop(unittest.TestCase):
    def test_js_sealed_pin_opens_in_python(self):
        k = devauth.new_private_key()
        box = json.loads(node("seal", b64.enc(devauth.spki_of(k)), "123456", "guardian/set_pin/abc"))
        self.assertEqual(pinbox.open_box(k, box, b"guardian/set_pin/abc"), b"123456")
        with self.assertRaises(Exception):
            pinbox.open_box(k, box, b"guardian/set_dev_pin/abc")

    def test_js_pairing_string_parses_in_python(self):
        trust = {"g_1": {"name": "Ana", "creds": {"cred1": "spki1"}}}
        s = node("pairing", "https://pi.example.ts.net", "pi.example.ts.net", "tok123", json.dumps(trust))
        p = parse_pairing(s)
        self.assertEqual((p["url"], p["rp"], p["token"]), ("https://pi.example.ts.net", "pi.example.ts.net", "tok123"))
        self.assertEqual(p["guardians"], trust)

    def test_js_command_bytes_parse_in_python(self):
        cmd = {"v": 1, "dev": "d", "guardian": "g", "ctr": 3, "type": "approve_app", "args": {"pkg": "ação.x"}}
        payload = b64.dec(node("command", json.dumps(cmd)))
        self.assertEqual(cmds.parse_payload(payload), cmd)


if __name__ == "__main__":
    unittest.main()
