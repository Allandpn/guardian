"""O gate.js do site tem que classificar como o Gate.kt do app (casos copiados de LogicTest.kt do NotToday)."""
import json
import os
import shutil
import subprocess
import unittest

CLI = os.path.join(os.path.dirname(__file__), "gate_cli.mjs")

# (chave, antes, depois, esperado) — espelham as asserções de LogicTest.kt
CASES = [
    ("r_no_uninstall_apps", "true", "false", "loosen"), ("r_no_uninstall_apps", "false", "true", "tighten"),
    ("dns_filter", "true", "false", "loosen"), ("new_apps_deny", "true", "false", "loosen"), ("dev_reboot", "true", "false", "loosen"),
    ("dns_filter", "true", "true", "neutral"), ("postpone_updates", "false", "true", "neutral"),
    ("canary", "", "x.com", "tighten"), ("canary", None, "x.com", "tighten"), ("canary", "x.com", "y.com", "loosen"), ("canary", "x.com", "", "loosen"),
    ("routed_extra", "a", "a,b", "tighten"), ("routed_extra", "a,b", "a", "loosen"), ("protected_pkgs", "a", "", "loosen"),
    ("chrome_youtube", "2", "1", "loosen"), ("chrome_youtube", "1", "0", "loosen"), ("chrome_youtube", "0", "2", "tighten"),
    ("chrome_doh_off", "true", "false", "loosen"), ("chrome_safesearch", "true", "false", "loosen"), ("chrome_incognito_block", "false", "true", "tighten"), ("chrome_block_ip", "true", "false", "loosen"), ("chrome_block_ip", "false", "true", "tighten"),
    ("store_extra", "a,b", "a", "loosen"), ("store_extra", "a", "a,b", "tighten"),
    ("browsers_exempt", "", "com.android.chrome", "loosen"), ("browsers_exempt", "com.android.chrome", "", "tighten"),
    ("dev_windows_per_day", "3", "5", "loosen"), ("dev_windows_per_day", "3", "1", "tighten"),
    ("dev_window_seconds", "60", "120", "loosen"), ("dev_window_seconds", "60", "30", "tighten"),
    ("unlock_delay_min", "1440", "60", "loosen"), ("unlock_delay_min", "60", "1440", "tighten"),
]


@unittest.skipUnless(shutil.which("node"), "node não instalado")
class GateJs(unittest.TestCase):
    def test_same_classification_as_the_app(self):
        out = subprocess.run(["node", CLI, json.dumps([c[:3] for c in CASES])], capture_output=True, text=True, check=True, timeout=30).stdout
        got = json.loads(out)
        for case, g in zip(CASES, got, strict=True):
            self.assertEqual(g, case[3], case[:3])


if __name__ == "__main__":
    unittest.main()
