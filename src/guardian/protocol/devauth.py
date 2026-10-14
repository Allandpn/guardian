"""Chave do aparelho/executor (P-256): identificador e requisições assinadas."""
import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import b64

MAX_SKEW_S = 300


def device_id(spki: bytes) -> str:
    """Identificador estável derivado da chave: 20 caracteres base32 minúsculos."""
    return base64.b32encode(hashlib.sha256(spki).digest()).decode().lower().rstrip("=")[:20]


def fingerprint(spki: bytes) -> str:
    """Para conferir por voz: o id em grupos de 4."""
    d = device_id(spki)
    return "-".join(d[i:i + 4] for i in range(0, len(d), 4))


def new_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def spki_of(priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def signing_string(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    return f"{method}\n{path}\n{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()


def sign(priv: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    return priv.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(spki: bytes, message: bytes, signature: bytes) -> bool:
    try:
        serialization.load_der_public_key(spki).verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def headers(priv: ec.EllipticCurvePrivateKey, method: str, path: str, body: bytes, ts: int, nonce: str) -> dict:
    """Cabeçalhos de uma requisição assinada. `path` inclui a query, exatamente como vai na linha de requisição."""
    spki = spki_of(priv)
    msg = signing_string(method, path, str(ts), nonce, body)
    return {"X-Dev": device_id(spki), "X-Ts": str(ts), "X-Nonce": nonce, "X-Sig": b64.enc(sign(priv, msg))}
