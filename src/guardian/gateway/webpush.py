"""Web Push (RFC 8030 + criptografia RFC 8291 aes128gcm + VAPID RFC 8292) só com `cryptography`.

O gateway envia avisos curtos às PWAs dos guardiões. O conteúdo vai cifrado de ponta a ponta até o navegador
(o serviço de push do Google/Mozilla/Apple só vê bytes). A chave VAPID só autoriza enviar avisos a quem se inscreveu.
"""
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..protocol import b64

RECORD_SIZE = 4096
MAX_PAYLOAD = 3000  # cabe num único registro (4096 - cabeçalho - tag)

# Só serviços de push conhecidos (o endpoint vem do navegador do guardião: sem lista, seria SSRF).
PUSH_HOST_SUFFIXES = (
    "fcm.googleapis.com", "updates.push.services.mozilla.com", "push.services.mozilla.com",
    "notify.windows.com", "push.apple.com", "web.push.apple.com",
)


def endpoint_allowed(url: str) -> bool:
    try:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
        return (p.scheme == "https" and p.port in (None, 443) and not p.username and not p.password
                and any(host == s or host.endswith("." + s) for s in PUSH_HOST_SUFFIXES) and len(url) < 1000)
    except ValueError:
        return False


def public_bytes(priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def new_vapid_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def encrypt(ua_public: bytes, auth_secret: bytes, plaintext: bytes, as_private: ec.EllipticCurvePrivateKey | None = None,
            salt: bytes | None = None) -> bytes:
    """Corpo `aes128gcm` de um registro único (RFC 8291). `as_private`/`salt` só para o vetor de teste."""
    if len(plaintext) > MAX_PAYLOAD:
        raise ValueError("aviso grande demais")
    as_private = as_private or ec.generate_private_key(ec.SECP256R1())
    salt = salt or os.urandom(16)
    as_public = public_bytes(as_private)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    shared = as_private.exchange(ec.ECDH(), ua_key)
    ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth_secret,
               info=b"WebPush: info\x00" + ua_public + as_public).derive(shared)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt, info=b"Content-Encoding: nonce\x00").derive(ikm)
    ct = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    return salt + RECORD_SIZE.to_bytes(4, "big") + bytes([len(as_public)]) + as_public + ct


def decrypt(ua_private: ec.EllipticCurvePrivateKey, auth_secret: bytes, body: bytes) -> bytes:
    """O lado do navegador (usado nos testes para conferir a ida e volta)."""
    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    as_public, ct = body[21:21 + idlen], body[21 + idlen:]
    assert rs >= len(ct)
    ua_public = public_bytes(ua_private)
    shared = ua_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth_secret,
               info=b"WebPush: info\x00" + ua_public + as_public).derive(shared)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt, info=b"Content-Encoding: nonce\x00").derive(ikm)
    plain = AESGCM(cek).decrypt(nonce, ct, None)
    return plain[:plain.rindex(b"\x02")]


def vapid_authorization(endpoint: str, priv: ec.EllipticCurvePrivateKey, subject: str, now: float | None = None) -> str:
    p = urlsplit(endpoint)
    claims = {"aud": f"{p.scheme}://{p.netloc}", "exp": int((now or time.time()) + 12 * 3600), "sub": subject}
    head = b64.enc(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    body = b64.enc(json.dumps(claims, separators=(",", ":")).encode())
    r, s = decode_dss_signature(priv.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    sig = b64.enc(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"vapid t={head}.{body}.{sig}, k={b64.enc(public_bytes(priv))}"


class PushGone(Exception):
    """O serviço de push disse que a inscrição não existe mais (404/410): apague-a."""


def send(sub: dict, payload: dict, vapid_priv: ec.EllipticCurvePrivateKey, subject: str, timeout: float = 10.0,
         allow_any_endpoint: bool = False) -> int:
    """Envia um aviso. `sub` = {endpoint, p256dh, auth} (b64url). Devolve o status HTTP; levanta PushGone em 404/410."""
    endpoint = sub["endpoint"]
    if not allow_any_endpoint and not endpoint_allowed(endpoint):
        raise ValueError("endpoint de push não permitido")
    body = encrypt(b64.dec(sub["p256dh"]), b64.dec(sub["auth"]), json.dumps(payload, separators=(",", ":")).encode())
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": "3600", "Urgency": "high",
        "Authorization": vapid_authorization(endpoint, vapid_priv, subject)})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            raise PushGone() from e
        return e.code
