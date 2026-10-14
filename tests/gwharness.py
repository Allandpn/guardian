"""Sobe um gateway de verdade numa porta livre e oferece um cliente HTTP mínimo para os testes."""
import http.client
import json
import os
import tempfile
import threading
import time

from authenticator import FakeAuthenticator, command, envelope
from guardian.gateway.config import Config
from guardian.gateway.server import create_invite, make_server
from guardian.protocol import b64, devauth

RP = "localhost"


class Client:
    def __init__(self, port: int, origin: str):
        self.port, self.origin, self.cookie = port, origin, None

    def call(self, method, path, body=None, headers=None, raw=None, origin=True):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        h = dict(headers or {})
        if method == "POST":
            h["Content-Length"] = str(len(data))
        if self.cookie:
            h["Cookie"] = self.cookie
        if origin and method != "GET":
            h["Origin"] = self.origin
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=40)
        c.request(method, path, body=data if method == "POST" else None, headers=h)
        r = c.getresponse()
        raw_body = r.read()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.cookie = sc.split(";")[0] if "Max-Age=0" not in sc else None
        c.close()
        try:
            return r.status, json.loads(raw_body) if raw_body else {}, r
        except ValueError:
            return r.status, raw_body, r

    def signed(self, key, method, path, body=None, nonce=None):
        data = json.dumps(body).encode() if body is not None else b""
        h = devauth.headers(key, method, path, data, int(time.time()), nonce or os.urandom(9).hex())
        return self.call(method, path, raw=data, headers=h)


class Env:
    def __init__(self, limit_scale: float = 100.0):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(origin="http://localhost", rp_id=RP, db_path=os.path.join(self.tmp.name, "g.db"),
                          bind="127.0.0.1", port=0, secure_cookies=False, limit_scale=limit_scale)
        self.srv = make_server(self.cfg)
        self.port = self.srv.server_address[1]
        self.cfg.origin = f"http://localhost:{self.port}"
        self.store = self.srv.gw.store
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def client(self) -> Client:
        return Client(self.port, self.cfg.origin)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def auth(self) -> FakeAuthenticator:
        return FakeAuthenticator(RP, self.cfg.origin)

    def register_guardian(self, name="Ana"):
        """Convite → registro com passkey de mentira. Devolve (cliente logado, autenticador, gid)."""
        a, c = self.auth(), self.client()
        token = create_invite(self.store, "new_guardian", None, name, 3600)
        st, o, _ = c.call("POST", "/v1/register/options", {"invite": token})
        assert st == 200, o
        reg = a.register(b64.dec(o["publicKey"]["challenge"]))
        st, v, _ = c.call("POST", "/v1/register/verify", {"challengeId": o["challengeId"], **reg})
        assert st == 200, v
        return c, a, v["guardian"]["id"]

    def pair_device(self, c, kind="device", name="Tab S8"):
        st, p, _ = c.call("POST", "/v1/pairings", {"kind": kind})
        assert st == 200, p
        key = devauth.new_private_key()
        spki = devauth.spki_of(key)
        dev = devauth.device_id(spki)
        body = {"pairing": p["token"], "pubkey": b64.enc(spki), "name": name, "kind": kind}
        st, r, _ = self.client().signed(key, "POST", "/v1/devices/register", body)
        assert st == 200, r
        return key, dev

    def sign_post(self, c, auth, gid, dev, type_, args=None, extra_signers=()):
        st, n, _ = c.call("GET", f"/v1/devices/{dev}/ctr")
        assert st == 200, n
        p = command(dev, gid, n["next"], type_, args)
        sigs = [auth.sign_command(gid, p)] + [a.sign_command(g, p) for g, a in extra_signers]
        return c.call("POST", f"/v1/devices/{dev}/commands", envelope(p, *sigs)), p
