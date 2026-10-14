"""O protocol/vectors.json versionado precisa passar na implementação de referência (Python)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from guardian.protocol import b64, commands as cmds, devauth, pinbox  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

V = json.load(open(os.path.join(os.path.dirname(__file__), "..", "protocol", "vectors.json")))


class Vectors(unittest.TestCase):
    def test_commands(self):
        trust = cmds.Trust.from_json(V["trust"])
        for c in V["commands"]:
            with self.subTest(c["name"]):
                if c["expect_valid"]:
                    cmds.verify_envelope(trust, c["envelope"])
                else:
                    with self.assertRaises(cmds.CommandError):
                        cmds.verify_envelope(trust, c["envelope"])

    def test_device_request_signature(self):
        r = V["device_request"]
        h = r["headers"]
        msg = devauth.signing_string(r["method"], r["path"], h["X-Ts"], h["X-Nonce"], b64.dec(r["body_b64"]))
        self.assertTrue(devauth.verify(b64.dec(r["spki"]), msg, b64.dec(h["X-Sig"])))
        self.assertEqual(h["X-Dev"], devauth.device_id(b64.dec(r["spki"])))

    def test_pinbox(self):
        p = V["pinbox"]
        key = serialization.load_der_private_key(b64.dec(p["device_private_pkcs8"]), None)
        self.assertEqual(pinbox.open_box(key, p["box"], p["aad"].encode()), p["plaintext"].encode())

    def test_device_id_and_challenge(self):
        d = V["device_id"]
        self.assertEqual(devauth.device_id(b64.dec(d["spki"])), d["id"])
        self.assertEqual(devauth.fingerprint(b64.dec(d["spki"])), d["fingerprint"])
        c = V["sha256_challenge"]
        self.assertEqual(b64.enc(cmds.challenge_of(b64.dec(c["payload"]))), c["challenge"])


if __name__ == "__main__":
    unittest.main()
