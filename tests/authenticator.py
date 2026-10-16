"""Autenticador de mentira (passkey em software) para os testes: faz registros e asserções válidas."""
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from guardian.protocol import b64


def _cbor_int(n: int) -> bytes:
    if n >= 0:
        return _cbor_head(0, n)
    return _cbor_head(1, -1 - n)


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + n.to_bytes(2, "big")


def _cbor_bytes(b: bytes) -> bytes:
    return _cbor_head(2, len(b)) + b


def _cbor_text(s: str) -> bytes:
    raw = s.encode()
    return _cbor_head(3, len(raw)) + raw


class FakeAuthenticator:
    def __init__(self, rp_id: str, origin: str, backup_eligible: bool = False):
        self.rp_id, self.origin = rp_id, origin
        self.be = backup_eligible  # True imita uma passkey sincronizada (conta Google/Apple)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)

    @property
    def cred_id_b64(self) -> str:
        return b64.enc(self.cred_id)

    @property
    def spki(self) -> bytes:
        return self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def register(self, challenge: bytes, *, uv: bool = True, origin: str | None = None) -> dict:
        nums = self.key.public_key().public_numbers()
        cose = (_cbor_head(5, 5) + _cbor_int(1) + _cbor_int(2) + _cbor_int(3) + _cbor_int(-7) + _cbor_int(-1)
                + _cbor_int(1) + _cbor_int(-2) + _cbor_bytes(nums.x.to_bytes(32, "big"))
                + _cbor_int(-3) + _cbor_bytes(nums.y.to_bytes(32, "big")))
        flags = 0x01 | 0x40 | (0x04 if uv else 0) | (0x08 if self.be else 0)
        auth = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
                + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)
        att = (_cbor_head(5, 3) + _cbor_text("fmt") + _cbor_text("none") + _cbor_text("attStmt") + _cbor_head(5, 0)
               + _cbor_text("authData") + _cbor_bytes(auth))
        cd = json.dumps({"type": "webauthn.create", "challenge": b64.enc(challenge),
                         "origin": origin or self.origin}).encode()
        return {"id": self.cred_id_b64, "attestationObject": b64.enc(att), "clientDataJSON": b64.enc(cd)}

    def assert_(self, challenge: bytes, *, uv: bool = True, origin: str | None = None, rp_id: str | None = None) -> dict:
        flags = 0x01 | (0x04 if uv else 0) | (0x08 if self.be else 0)
        auth = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
        cd = json.dumps({"type": "webauthn.get", "challenge": b64.enc(challenge),
                         "origin": origin or self.origin}).encode()
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": self.cred_id_b64, "authenticatorData": b64.enc(auth), "clientDataJSON": b64.enc(cd),
                "signature": b64.enc(sig)}

    def sign_command(self, guardian: str, payload: bytes, **kw) -> dict:
        a = self.assert_(hashlib.sha256(payload).digest(), **kw)
        return {"guardian": guardian, "cred": a["id"], "authenticatorData": a["authenticatorData"],
                "clientDataJSON": a["clientDataJSON"], "signature": a["signature"]}


def command(dev: str, guardian: str, ctr: int, type_: str, args: dict | None = None) -> bytes:
    return json.dumps({"v": 1, "dev": dev, "guardian": guardian, "ctr": ctr, "type": type_, "args": args or {}},
                      separators=(",", ":")).encode()


def envelope(payload: bytes, *sigs: dict) -> dict:
    return {"payload": b64.enc(payload), "sigs": list(sigs)}
