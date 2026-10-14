"""Caixa selada para o PIN: ECDH P-256 efêmero + HKDF-SHA256 + AES-256-GCM.

O navegador sela (WebCrypto) para a chave do aparelho; só o aparelho abre (Android Keystore). O gateway
e o usuário nunca veem o PIN. Formato: epk = ponto não comprimido (65 bytes), nonce de 12 bytes.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import b64

INFO = b"guardian/pinbox/v1"


def _key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)


def seal(device_spki: bytes, plaintext: bytes, aad: bytes, _eph: ec.EllipticCurvePrivateKey | None = None,
         _nonce: bytes | None = None) -> dict:
    import os
    dev_pub = serialization.load_der_public_key(device_spki)
    eph = _eph or ec.generate_private_key(ec.SECP256R1())
    nonce = _nonce or os.urandom(12)
    key = _key(eph.exchange(ec.ECDH(), dev_pub))
    epk = eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"epk": b64.enc(epk), "nonce": b64.enc(nonce), "ct": b64.enc(AESGCM(key).encrypt(nonce, plaintext, aad))}


def open_box(device_priv: ec.EllipticCurvePrivateKey, box: dict, aad: bytes) -> bytes:
    epk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64.dec(box["epk"]))
    key = _key(device_priv.exchange(ec.ECDH(), epk))
    return AESGCM(key).decrypt(b64.dec(box["nonce"]), b64.dec(box["ct"]), aad)
