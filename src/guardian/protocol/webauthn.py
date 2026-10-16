"""Registro e verificação de passkeys (WebAuthn), só ES256 e attestation "none".

O mesmo algoritmo de `verify_assertion` roda no aparelho (Kotlin): rpIdHash, flags UP+UV, origin, challenge e a
assinatura ES256 sobre authenticatorData ‖ SHA-256(clientDataJSON).
"""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import b64, cbor

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08   # backup eligible: a passkey pode ser copiada para a nuvem (conta Google, Apple…)
FLAG_AT = 0x40
COSE_ES256 = -7


class WebAuthnError(ValueError):
    pass


def _client_data(raw: bytes, kind: str, challenge: bytes, origin: str) -> None:
    try:
        cd = json.loads(raw)
    except ValueError as e:
        raise WebAuthnError("clientDataJSON inválido") from e
    if not isinstance(cd, dict):
        raise WebAuthnError("clientDataJSON inválido")
    if cd.get("type") != kind:
        raise WebAuthnError("tipo de cerimônia errado")
    if cd.get("challenge") != b64.enc(challenge):
        raise WebAuthnError("challenge diferente")
    if cd.get("origin") != origin:
        raise WebAuthnError("origin diferente")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("crossOrigin não permitido")


def _check_auth_data(auth: bytes, rp_id: str) -> int:
    if len(auth) < 37:
        raise WebAuthnError("authenticatorData curto")
    if auth[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("rpIdHash diferente")
    flags = auth[32]
    if not flags & FLAG_UP or not flags & FLAG_UV:
        raise WebAuthnError("exige presença e verificação do usuário")
    return flags


def cose_to_spki(cose: dict) -> bytes:
    if cose.get(1) != 2 or cose.get(3) != COSE_ES256 or cose.get(-1) != 1:
        raise WebAuthnError("só ES256/P-256 é aceito")
    x, y = cose.get(-2), cose.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
        raise WebAuthnError("chave COSE inválida")
    try:
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError as e:
        raise WebAuthnError("ponto fora da curva") from e
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def parse_registration(attestation_object: bytes, client_data_json: bytes, challenge: bytes, rp_id: str,
                       origin: str) -> tuple[bytes, bytes, bool]:
    """Valida um registro. Devolve (credential_id, chave pública SPKI/DER, sincronizável). A attestation é ignorada."""
    _client_data(client_data_json, "webauthn.create", challenge, origin)
    try:
        att, _ = cbor.decode(attestation_object)
        auth = att["authData"]
    except (cbor.CborError, KeyError, TypeError, UnicodeDecodeError) as e:
        raise WebAuthnError("attestationObject inválido") from e
    if not isinstance(auth, bytes):
        raise WebAuthnError("authData inválido")
    flags = _check_auth_data(auth, rp_id)
    if not flags & FLAG_AT or len(auth) < 55:
        raise WebAuthnError("sem credencial no registro")
    cred_len = int.from_bytes(auth[53:55], "big")
    if cred_len == 0 or cred_len > 1023 or len(auth) < 55 + cred_len:
        raise WebAuthnError("credentialId inválido")
    cred_id = auth[55:55 + cred_len]
    try:
        cose, _ = cbor.decode(auth[55 + cred_len:])
    except cbor.CborError as e:
        raise WebAuthnError("chave COSE inválida") from e
    if not isinstance(cose, dict):
        raise WebAuthnError("chave COSE inválida")
    return cred_id, cose_to_spki(cose), bool(flags & FLAG_BE)


def verify_assertion(spki: bytes, authenticator_data: bytes, client_data_json: bytes, signature: bytes,
                     challenge: bytes, rp_id: str, origin: str, allow_sync: bool = True) -> bool:
    """Levanta WebAuthnError se a asserção não valer para este challenge. Devolve se a passkey é sincronizável.

    Com `allow_sync=False` (guardião só neste aparelho) uma passkey com a flag BE é recusada. A flag está dentro do que
    é assinado, então não dá para esconder."""
    _client_data(client_data_json, "webauthn.get", challenge, origin)
    flags = _check_auth_data(authenticator_data, rp_id)
    if not allow_sync and flags & FLAG_BE:
        raise WebAuthnError("passkey sincronizável não vale para este guardião")
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    try:
        key = serialization.load_der_public_key(spki)
        key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as e:
        raise WebAuthnError("assinatura inválida") from e
    return bool(flags & FLAG_BE)
