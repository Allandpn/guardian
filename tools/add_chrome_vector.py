"""Acrescenta a protocol/vectors.json um envelope assinado por um passkey real do Chromium.

    CHROME_VECTOR_OUT=/tmp/chrome.json PYTHONPATH=src python tests/e2e_browser.py
    python tools/add_chrome_vector.py /tmp/chrome.json
"""
import json
import os
import sys

path = os.path.join(os.path.dirname(__file__), "..", "protocol", "vectors.json")
v = json.load(open(path))
v["chrome"] = [json.load(open(sys.argv[1]))]
v["note"] = v["note"] + " 'chrome' = envelope assinado por um passkey real do Chromium (autenticador virtual)."
json.dump(v, open(path, "w"), indent=1, ensure_ascii=False)
print("ok", len(v["chrome"]))
