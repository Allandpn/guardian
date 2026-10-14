import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(__file__))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from guardian.gateway import webpush  # noqa: E402
from guardian.protocol import b64  # noqa: E402


class Rfc8291(unittest.TestCase):
    def test_official_vector(self):
        """Apêndice A da RFC 8291: se isto bater, a criptografia casa com todos os navegadores."""
        ua_pub = b64.dec("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
        auth = b64.dec("BTBZMqHH6r4Tts7J_aSIgg")
        as_priv = ec.derive_private_key(int.from_bytes(b64.dec("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"), "big"), ec.SECP256R1())
        salt = b64.dec("DGv6ra1nlYgDCS1FRnbzlw")
        body = webpush.encrypt(ua_pub, auth, b"When I grow up, I want to be a watermelon", as_priv, salt)
        expected = ("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
        self.assertEqual(b64.enc(body), expected)

    def test_roundtrip(self):
        ua = ec.generate_private_key(ec.SECP256R1())
        auth = os.urandom(16)
        msg = json.dumps({"title": "Aparelho sem sinal", "body": "ação"}).encode()
        self.assertEqual(webpush.decrypt(ua, auth, webpush.encrypt(webpush.public_bytes(ua), auth, msg)), msg)
        with self.assertRaises(ValueError):
            webpush.encrypt(webpush.public_bytes(ua), auth, b"x" * 4000)


class Endpoints(unittest.TestCase):
    def test_allowlist(self):
        ok = ["https://fcm.googleapis.com/fcm/send/abc", "https://updates.push.services.mozilla.com/wpush/v2/x",
              "https://wns2-par02p.notify.windows.com/w/?token=x", "https://web.push.apple.com/abc"]
        bad = ["http://fcm.googleapis.com/x", "https://evil.example/x", "https://fcm.googleapis.com.evil.example/x",
               "https://127.0.0.1/x", "https://fcm.googleapis.com:8443/x", "https://user:pw@fcm.googleapis.com/x",
               "https://localhost/", "file:///etc/passwd", "https://169.254.169.254/latest", "https://notfcm.googleapis.com.x/y", ""]
        for u in ok:
            self.assertTrue(webpush.endpoint_allowed(u), u)
        for u in bad:
            self.assertFalse(webpush.endpoint_allowed(u), u)

    def test_vapid_header_shape_and_signature(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        k = webpush.new_vapid_key()
        h = webpush.vapid_authorization("https://fcm.googleapis.com/fcm/send/abc", k, "mailto:a@b.c", now=1_000_000)
        self.assertTrue(h.startswith("vapid t="))
        jwt, pub = h[len("vapid t="):].split(", k=")
        head, body, sig = jwt.split(".")
        claims = json.loads(b64.dec(body))
        self.assertEqual(claims["aud"], "https://fcm.googleapis.com")
        self.assertEqual(claims["exp"], 1_000_000 + 12 * 3600)
        raw = b64.dec(sig)
        self.assertEqual(len(raw), 64)
        k.public_key().verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                              f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        self.assertEqual(b64.dec(pub), webpush.public_bytes(k))


class FakePushService:
    def __init__(self, status=201):
        self.got = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                outer.got.append((dict(self.headers), self.rfile.read(n)))
                self.send_response(outer.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.status = status
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/push/abc"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class SendTests(unittest.TestCase):
    def test_send_delivers_encrypted_payload_and_detects_gone(self):
        svc = FakePushService()
        try:
            ua = ec.generate_private_key(ec.SECP256R1())
            auth = os.urandom(16)
            sub = {"endpoint": svc.url, "p256dh": b64.enc(webpush.public_bytes(ua)), "auth": b64.enc(auth)}
            vk = webpush.new_vapid_key()
            self.assertEqual(webpush.send(sub, {"title": "t", "body": "b"}, vk, "mailto:x@y.z", allow_any_endpoint=True), 201)
            headers, body = svc.got[0]
            self.assertEqual(headers["Content-Encoding"], "aes128gcm")
            self.assertTrue(headers["Authorization"].startswith("vapid t="))
            self.assertEqual(json.loads(webpush.decrypt(ua, auth, body)), {"title": "t", "body": "b"})
            with self.assertRaises(ValueError):  # sem allow_any_endpoint, 127.0.0.1 é recusado
                webpush.send(sub, {"title": "t"}, vk, "mailto:x@y.z")
            svc.status = 410
            with self.assertRaises(webpush.PushGone):
                webpush.send(sub, {"title": "t"}, vk, "mailto:x@y.z", allow_any_endpoint=True)
            svc.status = 500
            self.assertEqual(webpush.send(sub, {"title": "t"}, vk, "mailto:x@y.z", allow_any_endpoint=True), 500)
        finally:
            svc.close()


if __name__ == "__main__":
    unittest.main()
