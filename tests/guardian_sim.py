"""Simulador de guardião para testes de integração de outras linguagens (o Kotlin do NotToday).

    python tests/guardian_sim.py serve    --dir D     # sobe um gateway de verdade e cadastra um guardião; imprime {"port":..}
    python tests/guardian_sim.py pairing  --dir D     # imprime uma string de pareamento nova
    python tests/guardian_sim.py devices  --dir D     # imprime /v1/devices
    python tests/guardian_sim.py audit    --dir D     # imprime /v1/audit
    python tests/guardian_sim.py send     --dir D --dev ID --type T [--args JSON] [--pin 123456]

Precisa de PYTHONPATH=src:tests. O estado do guardião (passkey de mentira) fica em D/state.json.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import FakeAuthenticator, command, envelope  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from gwharness import RP, Client, Env  # noqa: E402
from guardian.protocol import b64, pinbox  # noqa: E402


def load(d):
    st = json.load(open(os.path.join(d, "state.json")))
    a = FakeAuthenticator(RP, st["origin"])
    a.key = serialization.load_der_private_key(b64.dec(st["key"]), None)
    a.cred_id = b64.dec(st["cred"])
    c = Client(st["port"], st["origin"])
    s, o, _ = c.call("POST", "/v1/auth/options", {})
    asn = a.assert_(b64.dec(o["publicKey"]["challenge"]))
    s, v, _ = c.call("POST", "/v1/auth/verify", {"challengeId": o["challengeId"], **asn})
    assert s == 200, v
    return st, a, c


def main():
    p = argparse.ArgumentParser()
    p.add_argument("cmd")
    p.add_argument("--dir", required=True)
    p.add_argument("--dev")
    p.add_argument("--type")
    p.add_argument("--args", default="{}")
    p.add_argument("--pin")
    a = p.parse_args()
    if a.cmd == "serve":
        env = Env()
        c, auth, gid = env.register_guardian("Ana")
        json.dump({"port": env.port, "origin": env.cfg.origin, "gid": gid,
                   "key": b64.enc(auth.key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())),
                   "cred": auth.cred_id_b64}, open(os.path.join(a.dir, "state.json"), "w"))
        print(json.dumps({"port": env.port}), flush=True)
        while True:
            time.sleep(3600)
    st, auth, c = load(a.dir)
    if a.cmd == "pairing":
        _, me, _ = c.call("GET", "/v1/me")
        _, t, _ = c.call("POST", "/v1/pairings", {"kind": "device"})
        print(b64.enc(json.dumps({"v": 1, "url": st["origin"], "rp": RP, "token": t["token"], "guardians": me["trust"]}).encode()))
    elif a.cmd == "devices":
        print(json.dumps(c.call("GET", "/v1/devices")[1]))
    elif a.cmd == "audit":
        print(json.dumps(c.call("GET", "/v1/audit?limit=200")[1]))
    elif a.cmd == "send":
        args = json.loads(a.args)
        if a.pin:
            devs = c.call("GET", "/v1/devices")[1]["devices"]
            spki = b64.dec(next(d for d in devs if d["id"] == a.dev)["spki"])
            args = {"box": pinbox.seal(spki, a.pin.encode(), f"guardian/{a.type}/{a.dev}".encode())}
        _, n, _ = c.call("GET", f"/v1/devices/{a.dev}/ctr")
        payload = command(a.dev, st["gid"], n["next"], a.type, args)
        s, r, _ = c.call("POST", f"/v1/devices/{a.dev}/commands", envelope(payload, auth.sign_command(st["gid"], payload)))
        print(json.dumps({"status": s, **r}))
        sys.exit(0 if s == 200 else 1)
    else:
        sys.exit("comando desconhecido")


if __name__ == "__main__":
    main()
