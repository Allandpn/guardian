"""Gera protocol/vectors.json: casos fixos (válidos e inválidos) que o Kotlin do aparelho também deve passar.

    PYTHONPATH=src:tests python tools/gen_vectors.py > protocol/vectors.json
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

from authenticator import FakeAuthenticator, command, envelope  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from guardian.protocol import b64, devauth, pinbox  # noqa: E402

RP, ORIGIN = "guardian.example.ts.net", "https://guardian.example.ts.net"


def main():
    a, b = FakeAuthenticator(RP, ORIGIN), FakeAuthenticator(RP, ORIGIN)
    trust = {"rp_id": RP, "origin": ORIGIN, "guardians": {
        "g_ana": {"name": "Ana", "creds": {a.cred_id_b64: b64.enc(a.spki)}},
        "g_bia": {"name": "Bia", "creds": {b.cred_id_b64: b64.enc(b.spki)}}}}
    dev = "aaaabbbbccccddddeeee"

    def case(name, env, valid, why=""):
        return {"name": name, "envelope": env, "expect_valid": valid, "why": why}

    p1 = command(dev, "g_ana", 1, "approve_app", {"pkg": "com.exemplo.app"})
    p2 = command(dev, "g_ana", 2, "remove_guardian", {"id": "g_bia"})
    tampered = envelope(p1, a.sign_command("g_ana", p1))
    tampered["payload"] = b64.enc(command(dev, "g_ana", 1, "approve_app", {"pkg": "com.outro"}))
    cases = [
        case("um guardião aprova app", envelope(p1, a.sign_command("g_ana", p1)), True),
        case("payload adulterado", tampered, False, "assinatura não cobre os bytes"),
        case("sem verificação do usuário", envelope(p1, a.sign_command("g_ana", p1, uv=False)), False, "flag UV ausente"),
        case("origin errada", envelope(p1, a.sign_command("g_ana", p1, origin="https://evil.example")), False, "origin"),
        case("rpId errado", envelope(p1, a.sign_command("g_ana", p1, rp_id="evil.example")), False, "rpIdHash"),
        case("remover guardião com uma assinatura", envelope(p2, a.sign_command("g_ana", p2)), False, "exige 2 guardiões"),
        case("remover guardião com duas", envelope(p2, a.sign_command("g_ana", p2), b.sign_command("g_bia", p2)), True),
        case("autor não assinou", envelope(p1, b.sign_command("g_bia", p1)), False, "guardian do payload não está entre os signatários"),
    ]
    k = devauth.new_private_key()
    spki = devauth.spki_of(k)
    h = devauth.headers(k, "GET", "/v1/devices/%s/commands?after=0&wait=25" % devauth.device_id(spki), b"", 1_700_000_000, "nonce-fixo-0001")
    req = {"method": "GET", "path": "/v1/devices/%s/commands?after=0&wait=25" % devauth.device_id(spki), "body_b64": "",
           "headers": h, "spki": b64.enc(spki), "expect_dev": devauth.device_id(spki)}
    aad = f"guardian/set_pin/{dev}"
    box = pinbox.seal(spki, b"135790", aad.encode())
    out = {
        "note": "Gerado por tools/gen_vectors.py. 'envelope.payload' e as assinaturas são base64url; chaves públicas são SPKI/DER em base64url.",
        "trust": trust, "dev": dev, "commands": cases,
        "device_request": req,
        "pinbox": {"device_private_pkcs8": b64.enc(k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                                 serialization.NoEncryption())),
                   "device_spki": b64.enc(spki), "aad": aad, "plaintext": "135790", "box": box},
        "device_id": {"spki": b64.enc(spki), "id": devauth.device_id(spki), "fingerprint": devauth.fingerprint(spki)},
        "sha256_challenge": {"payload": b64.enc(p1), "challenge": b64.enc(hashlib.sha256(p1).digest())},
    }
    path = os.path.join(os.path.dirname(__file__), "..", "protocol", "vectors.json")
    if os.path.exists(path):  # preserva os vetores capturados de um Chromium real (tools/add_chrome_vector.py)
        old = json.load(open(path))
        if "chrome" in old:
            out["chrome"] = old["chrome"]
    json.dump(out, sys.stdout, indent=1, ensure_ascii=False)
    print()


if __name__ == "__main__":
    main()
