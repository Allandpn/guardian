"""Servidor HTTP do gateway: só biblioteca padrão + cryptography, HTTP/1.0 (uma requisição por conexão)."""
import hashlib
import json
import os
import re
import secrets
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ..protocol import b64, commands as cmds, devauth, webauthn
from .config import Config
from .db import Store
from .limits import Limiter, NonceCache

DEVICE_TYPES = {"set_config", "confirm", "cancel", "approve_app", "revoke_app", "request_maintenance",
                "set_dev_policy", "set_pin", "set_dev_pin", "activate"} | cmds.TRUST_TYPES
EXECUTOR_TYPES = {"pihole_allow", "pihole_deny", "pihole_remove"} | cmds.TRUST_TYPES
REQUEST_KINDS = {"domain", "app", "other"}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/crypto.js": ("crypto.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class HttpError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


class Req:
    def __init__(self, method, path, query, headers, body, ip, raw_target):
        self.method, self.path, self.query, self.headers, self.body = method, path, query, headers, body
        self.ip, self.raw_target = ip, raw_target

    def json(self) -> dict:
        try:
            d = json.loads(self.body or b"{}")
        except ValueError:
            raise HttpError(400, "JSON inválido")
        if not isinstance(d, dict):
            raise HttpError(400, "esperado um objeto JSON")
        return d


def _str(d: dict, k: str, maxlen: int = 512) -> str:
    v = d.get(k)
    if not isinstance(v, str) or not v or len(v) > maxlen:
        raise HttpError(400, f"campo '{k}' ausente ou inválido")
    return v


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Gateway:
    def __init__(self, cfg: Config, store: Store | None = None):
        self.cfg = cfg
        self.store = store or Store(cfg.db_path)
        self.lock = threading.Lock()
        self.sessions: dict[str, tuple[str, float]] = {}
        self.challenges: dict[str, tuple[bytes, str, dict, float]] = {}
        self.cond = threading.Condition()
        self.poll_gen: dict[str, int] = {}
        self.nonces = NonceCache(2 * devauth.MAX_SKEW_S)
        k = cfg.limit_scale
        self.l_ip = Limiter(120 * k, int(40 * k))
        self.l_auth = Limiter(12 * k, int(8 * k))
        self.l_global = Limiter(1500 * k, int(300 * k))
        self.l_static = Limiter(300 * k, int(100 * k))
        self.l_dev = Limiter(120 * k, int(30 * k))
        self.l_cmd = Limiter(30 * k, int(15 * k))
        self.static = {}
        for path, (name, ctype) in STATIC.items():
            p = os.path.join(STATIC_DIR, name)
            if os.path.exists(p):
                with open(p, "rb") as f:
                    self.static[path] = (f.read(), ctype)
        self.routes = [
            ("GET", r"/healthz", self.healthz),
            ("POST", r"/v1/register/options", self.register_options),
            ("POST", r"/v1/register/verify", self.register_verify),
            ("POST", r"/v1/auth/options", self.auth_options),
            ("POST", r"/v1/auth/verify", self.auth_verify),
            ("POST", r"/v1/auth/logout", self.auth_logout),
            ("GET", r"/v1/me", self.me),
            ("POST", r"/v1/invites", self.make_invite),
            ("POST", r"/v1/pairings", self.make_pairing),
            ("GET", r"/v1/devices", self.list_devices),
            ("POST", r"/v1/devices/register", self.device_register),
            ("GET", r"/v1/devices/(?P<dev>[a-z2-7]{20})/ctr", self.next_ctr),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/commands", self.post_command),
            ("GET", r"/v1/devices/(?P<dev>[a-z2-7]{20})/commands", self.poll_commands),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/report", self.post_report),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/requests", self.post_request),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/forget", self.forget),
            ("GET", r"/v1/commands/awaiting", self.awaiting),
            ("POST", r"/v1/commands/(?P<cid>[0-9]{1,12})/cosign", self.cosign),
            ("GET", r"/v1/audit", self.audit),
            ("GET", r"/v1/requests", self.requests),
            ("POST", r"/v1/requests/(?P<rid>[0-9]{1,12})/dismiss", self.dismiss),
        ]
        self.routes = [(m, re.compile(p + r"\Z"), f) for m, p, f in self.routes]

    # ------------------------------------------------------------------ infra
    def body_limit(self, path: str) -> int:
        if path.endswith("/report"):
            return 64 * 1024
        if path.endswith("/commands") or path.endswith("/cosign"):
            return 16 * 1024
        return 4 * 1024

    def dispatch(self, req: Req):
        if req.method == "GET" and req.path in self.static:
            if not self.l_static.allow(req.ip):
                raise HttpError(429, "devagar")
            body, ctype = self.static[req.path]
            return 200, body, {"Content-Type": ctype, "Cache-Control": "no-cache"}
        if not self.l_global.allow("g") or not self.l_ip.allow(req.ip):
            raise HttpError(429, "devagar")
        for method, rx, fn in self.routes:
            m = rx.match(req.path)
            if m and method == req.method:
                return fn(req, **m.groupdict())
        raise HttpError(404, "não encontrado")

    def _purge_loop(self):
        while True:
            time.sleep(3600)
            try:
                self.store.purge()
            except Exception as e:  # nunca derruba o serviço
                print("purge falhou:", e, file=sys.stderr)

    # ------------------------------------------------------------------ sessões e desafios
    def new_challenge(self, purpose: str, ctx: dict) -> tuple[str, bytes]:
        now = time.monotonic()
        with self.lock:
            self.challenges = {k: v for k, v in self.challenges.items() if v[3] > now}
            if len(self.challenges) >= 500:
                raise HttpError(503, "ocupado")
            cid, ch = secrets.token_urlsafe(16), os.urandom(32)
            self.challenges[cid] = (ch, purpose, ctx, now + self.cfg.challenge_ttl_s)
            return cid, ch

    def take_challenge(self, cid: str, purpose: str) -> tuple[bytes, dict]:
        with self.lock:
            item = self.challenges.pop(cid, None)
        if not item or item[1] != purpose or item[3] < time.monotonic():
            raise HttpError(400, "desafio expirado ou inválido")
        return item[0], item[2]

    def cookie_name(self) -> str:
        return "__Host-gsession" if self.cfg.secure_cookies else "gsession"

    def start_session(self, gid: str) -> dict:
        now = time.time()
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v[1] > now}
            if len(self.sessions) >= 200:
                raise HttpError(503, "ocupado")
            token = secrets.token_urlsafe(32)
            self.sessions[_hash(token)] = (gid, now + self.cfg.session_ttl_s)
        attrs = f"{self.cookie_name()}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={self.cfg.session_ttl_s}"
        if self.cfg.secure_cookies:
            attrs += "; Secure"
        return {"Set-Cookie": attrs}

    def guardian(self, req: Req) -> str:
        if req.method != "GET" and req.headers.get("Origin") != self.cfg.origin:
            raise HttpError(403, "origem não permitida")
        raw = req.headers.get("Cookie", "")
        token = next((p.split("=", 1)[1] for p in (x.strip() for x in raw.split(";")) if p.startswith(self.cookie_name() + "=")), None)
        with self.lock:
            s = self.sessions.get(_hash(token)) if token else None
        if not s or s[1] < time.time():
            raise HttpError(401, "faça login")
        return s[0]

    # ------------------------------------------------------------------ autenticação do aparelho
    def _device_headers(self, req: Req, spki: bytes, dev: str) -> None:
        h = req.headers
        ts, nonce, sig, claimed = h.get("X-Ts", ""), h.get("X-Nonce", ""), h.get("X-Sig", ""), h.get("X-Dev", "")
        if claimed != dev or not re.fullmatch(r"[0-9]{1,12}", ts) or not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", nonce):
            raise HttpError(401, "assinatura do aparelho ausente")
        if abs(time.time() - int(ts)) > devauth.MAX_SKEW_S:
            raise HttpError(401, "relógio fora da janela")
        if not self.l_dev.allow(dev):
            raise HttpError(429, "devagar")
        try:
            sigb = b64.dec(sig)
        except ValueError:
            raise HttpError(401, "assinatura inválida")
        msg = devauth.signing_string(req.method, req.raw_target, ts, nonce, req.body)
        if not devauth.verify(spki, msg, sigb):
            raise HttpError(401, "assinatura inválida")
        if self.nonces.seen(f"{dev}:{nonce}"):
            raise HttpError(401, "nonce repetido")

    def device(self, req: Req, dev: str):
        row = self.store.device(dev)
        if not row:
            raise HttpError(404, "aparelho desconhecido")
        self._device_headers(req, b64.dec(row["spki"]), dev)
        return row

    # ------------------------------------------------------------------ rotas públicas
    def healthz(self, req):
        return 200, {"ok": True}, {}

    def _auth_limit(self, req):
        if not self.l_auth.allow(req.ip):
            raise HttpError(429, "devagar")

    def register_options(self, req):
        self._auth_limit(req)
        token = _str(req.json(), "invite", 200)
        inv = self.store.invite(_hash(token))
        if not inv:
            raise HttpError(400, "convite inválido ou expirado")
        if inv["kind"] == "new_guardian":
            gid, name, exclude = "g_" + secrets.token_hex(4), inv["name"] or "Guardião", []
        else:
            g = self.store.one("SELECT * FROM guardians WHERE id=?", (inv["guardian"],))
            if not g:
                raise HttpError(400, "convite inválido")
            gid, name = g["id"], g["name"]
            exclude = [c["cred"] for c in self.store.q("SELECT cred FROM credentials WHERE guardian=?", (gid,))]
        cid, ch = self.new_challenge("register", {"gid": gid, "name": name, "kind": inv["kind"], "invite": _hash(token)})
        return 200, {"challengeId": cid, "publicKey": {
            "challenge": b64.enc(ch), "rp": {"id": self.cfg.rp_id, "name": "NotToday Guardian"},
            "user": {"id": b64.enc(gid.encode()), "name": name, "displayName": name},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "preferred", "userVerification": "required"},
            "attestation": "none", "timeout": 60000,
            "excludeCredentials": [{"type": "public-key", "id": c} for c in exclude]}}, {}

    def register_verify(self, req):
        self._auth_limit(req)
        d = req.json()
        ch, ctx = self.take_challenge(_str(d, "challengeId", 64), "register")
        try:
            cred, spki = webauthn.parse_registration(
                b64.dec(_str(d, "attestationObject", 4096)), b64.dec(_str(d, "clientDataJSON", 2048)),
                ch, self.cfg.rp_id, self.cfg.origin)
        except (webauthn.WebAuthnError, ValueError) as e:
            raise HttpError(400, f"registro recusado: {e}")
        if not self.store.consume_invite(ctx["invite"]):
            raise HttpError(400, "convite já usado ou expirado")
        cred_b64 = b64.enc(cred)
        if self.store.credential(cred_b64):
            raise HttpError(409, "credencial já cadastrada")
        if ctx["kind"] == "new_guardian":
            self.store.add_guardian(ctx["gid"], ctx["name"], cred_b64, b64.enc(spki))
        else:
            self.store.add_credential(ctx["gid"], cred_b64, b64.enc(spki))
        self.store.audit(None, "guardian", f"{ctx['kind']}: {ctx['gid']}")
        return 200, {"guardian": {"id": ctx["gid"], "name": ctx["name"]}, "cred": cred_b64, "spki": b64.enc(spki)}, \
            self.start_session(ctx["gid"])

    def auth_options(self, req):
        self._auth_limit(req)
        cid, ch = self.new_challenge("login", {})
        return 200, {"challengeId": cid, "publicKey": {
            "challenge": b64.enc(ch), "rpId": self.cfg.rp_id, "userVerification": "required", "timeout": 60000}}, {}

    def auth_verify(self, req):
        self._auth_limit(req)
        d = req.json()
        ch, _ = self.take_challenge(_str(d, "challengeId", 64), "login")
        row = self.store.credential(_str(d, "id", 1400))
        if not row:
            raise HttpError(401, "credencial desconhecida")
        try:
            webauthn.verify_assertion(
                b64.dec(row["spki"]), b64.dec(_str(d, "authenticatorData", 1024)), b64.dec(_str(d, "clientDataJSON", 2048)),
                b64.dec(_str(d, "signature", 512)), ch, self.cfg.rp_id, self.cfg.origin)
        except (webauthn.WebAuthnError, ValueError):
            raise HttpError(401, "login recusado")
        g = self.store.one("SELECT * FROM guardians WHERE id=?", (row["guardian"],))
        self.store.audit(None, "login", g["id"])
        return 200, {"guardian": {"id": g["id"], "name": g["name"]}}, self.start_session(g["id"])

    def auth_logout(self, req):
        raw = req.headers.get("Cookie", "")
        token = next((p.split("=", 1)[1] for p in (x.strip() for x in raw.split(";")) if p.startswith(self.cookie_name() + "=")), None)
        with self.lock:
            self.sessions.pop(_hash(token), None) if token else None
        return 200, {"ok": True}, {"Set-Cookie": f"{self.cookie_name()}=; Path=/; Max-Age=0"}

    # ------------------------------------------------------------------ rotas do guardião
    def me(self, req):
        gid = self.guardian(req)
        g = self.store.one("SELECT * FROM guardians WHERE id=?", (gid,))
        return 200, {"guardian": {"id": gid, "name": g["name"]}, "trust": self.store.trust_dict(),
                     "rp_id": self.cfg.rp_id, "origin": self.cfg.origin}, {}

    def make_invite(self, req):
        gid = self.guardian(req)
        d = req.json()
        kind = d.get("kind")
        if kind not in ("new_guardian", "add_passkey"):
            raise HttpError(400, "tipo de convite inválido")
        token = create_invite(self.store, kind, gid if kind == "add_passkey" else None,
                              _str(d, "name", 64) if kind == "new_guardian" else None, self.cfg.invite_ttl_s)
        return 200, {"token": token, "expires_in": self.cfg.invite_ttl_s}, {}

    def make_pairing(self, req):
        self.guardian(req)
        kind = req.json().get("kind")
        if kind not in ("device", "executor"):
            raise HttpError(400, "tipo inválido")
        token = secrets.token_urlsafe(24)
        self.store.put_pairing(_hash(token), kind, int(time.time()) + self.cfg.invite_ttl_s)
        return 200, {"token": token, "expires_in": self.cfg.invite_ttl_s}, {}

    def list_devices(self, req):
        self.guardian(req)
        out = []
        for r in self.store.devices():
            out.append({"id": r["id"], "kind": r["kind"], "name": r["name"], "spki": r["spki"], "created": r["created"],
                        "last_seen": r["last_seen"], "report_ts": r["report_ts"], "pending": r["pending"],
                        "report": json.loads(r["report"]) if r["report"] else None})
        return 200, {"devices": out, "now": int(time.time())}, {}

    def next_ctr(self, req, dev):
        gid = self.guardian(req)
        row = self.store.device(dev)
        if not row:
            raise HttpError(404, "aparelho desconhecido")
        reported = 0
        if row["report"]:
            r = json.loads(row["report"]).get("ctrs", {})
            reported = r.get(gid, 0) if isinstance(r, dict) and isinstance(r.get(gid, 0), int) else 0
        return 200, {"next": max(self.store.last_ctr(dev, gid), reported) + 1}, {}

    def post_command(self, req, dev):
        gid = self.guardian(req)
        if not self.l_cmd.allow(gid):
            raise HttpError(429, "devagar")
        row = self.store.device(dev)
        if not row:
            raise HttpError(404, "aparelho desconhecido")
        env = req.json()
        trust = cmds.Trust(self.cfg.rp_id, self.cfg.origin,
                           {g: cmds.Guardian(v["name"], v["creds"]) for g, v in self.store.trust_dict().items()})
        try:
            payload = b64.dec(_str(env, "payload", 12000))
            cmd = cmds.parse_payload(payload)
            signers = cmds.verify_sigs(trust, payload, env.get("sigs"))
        except (cmds.CommandError, ValueError) as e:
            raise HttpError(400, str(e))
        allowed = EXECUTOR_TYPES if row["kind"] == "executor" else DEVICE_TYPES
        if cmd["dev"] != dev or cmd["guardian"] != gid or gid not in signers or cmd["type"] not in allowed:
            raise HttpError(400, "comando não confere com o destino, o autor ou o tipo")
        if self.store.pending_count(dev) >= self.cfg.max_pending_per_dev:
            raise HttpError(429, "fila cheia")
        ready = len(signers) >= cmds.required_signers(trust, cmd["type"])
        cid = self.store.enqueue(dev, gid, cmd["ctr"], {"payload": env["payload"], "sigs": env["sigs"]}, ready)
        if cid is None:
            raise HttpError(409, "contador repetido")
        self.store.audit(dev, "queued", f"{gid}: {cmd['type']}" + ("" if ready else " (aguarda 2º guardião)"))
        if ready:
            self._wake()
        return 200, {"id": cid, "status": "ready" if ready else "awaiting"}, {}

    def _wake(self):
        with self.cond:
            self.cond.notify_all()

    def awaiting(self, req):
        gid = self.guardian(req)
        out = []
        for r in self.store.awaiting():
            env = json.loads(r["envelope"])
            signed = {s.get("guardian") for s in env.get("sigs", [])}
            out.append({"id": r["id"], "dev": r["dev"], "guardian": r["guardian"], "envelope": env,
                        "can_cosign": gid not in signed})
        return 200, {"commands": out}, {}

    def cosign(self, req, cid):
        gid = self.guardian(req)
        if not self.l_cmd.allow(gid):
            raise HttpError(429, "devagar")
        row = self.store.command(int(cid))
        if not row or row["status"] != "awaiting":
            raise HttpError(404, "comando não aguarda assinatura")
        env = json.loads(row["envelope"])
        sig = req.json().get("sig")
        if not isinstance(sig, dict) or sig.get("guardian") != gid or any(s.get("guardian") == gid for s in env["sigs"]):
            raise HttpError(400, "assinatura inválida para este guardião")
        trust = cmds.Trust(self.cfg.rp_id, self.cfg.origin,
                           {g: cmds.Guardian(v["name"], v["creds"]) for g, v in self.store.trust_dict().items()})
        payload = b64.dec(env["payload"])
        sigs = env["sigs"] + [sig]
        try:
            signers = cmds.verify_sigs(trust, payload, sigs)
        except cmds.CommandError as e:
            raise HttpError(400, str(e))
        cmd = cmds.parse_payload(payload)
        if len(signers) < cmds.required_signers(trust, cmd["type"]):
            raise HttpError(400, "ainda faltam assinaturas")
        self.store.make_ready(row["id"], {"payload": env["payload"], "sigs": sigs})
        self.store.audit(row["dev"], "queued", f"{gid} co-assinou {cmd['type']}")
        self._wake()
        return 200, {"status": "ready"}, {}

    def audit(self, req):
        self.guardian(req)
        q = parse_qs(req.query)
        limit = min(int(q.get("limit", ["100"])[0]) if q.get("limit", ["100"])[0].isdigit() else 100, 500)
        return 200, {"items": [dict(r) for r in self.store.audit_list(limit)]}, {}

    def requests(self, req):
        self.guardian(req)
        return 200, {"items": [dict(r) for r in self.store.requests_open()]}, {}

    def dismiss(self, req, rid):
        self.guardian(req)
        self.store.dismiss_request(int(rid))
        return 200, {"ok": True}, {}

    def forget(self, req, dev):
        self.guardian(req)
        self.store.forget_device(dev)
        self.store.audit(dev, "forget", "aparelho removido do gateway")
        return 200, {"ok": True}, {}

    # ------------------------------------------------------------------ rotas do aparelho / executor
    def device_register(self, req):
        d = req.json()
        try:
            spki = b64.dec(_str(d, "pubkey", 400))
            dev = devauth.device_id(spki)
            kind = d.get("kind")
            if kind not in ("device", "executor"):
                raise HttpError(400, "tipo inválido")
            self._device_headers(req, spki, dev)
        except ValueError:
            raise HttpError(400, "chave inválida")
        if self.store.device(dev):
            raise HttpError(409, "aparelho já registrado")
        if not self.store.consume_pairing(_hash(_str(d, "pairing", 100)), kind):
            raise HttpError(403, "código de pareamento inválido ou expirado")
        self.store.add_device(dev, kind, _str(d, "name", 64), b64.enc(spki))
        self.store.audit(dev, "paired", f"{kind} {devauth.fingerprint(spki)}")
        return 200, {"dev": dev, "fingerprint": devauth.fingerprint(spki)}, {}

    def poll_commands(self, req, dev):
        self.device(req, dev)
        self.store.touch(dev)
        q = parse_qs(req.query)
        try:
            after = int(q.get("after", ["0"])[0])
            wait = min(int(q.get("wait", ["0"])[0]), self.cfg.max_poll_s)
        except ValueError:
            raise HttpError(400, "parâmetros inválidos")
        deadline = time.monotonic() + max(wait, 0)
        with self.cond:
            gen = self.poll_gen[dev] = self.poll_gen.get(dev, 0) + 1
        while True:
            rows = self.store.ready_after(dev, after)
            if rows or time.monotonic() >= deadline:
                break
            with self.cond:
                if self.poll_gen.get(dev) != gen:
                    break  # uma consulta mais nova assumiu
                self.cond.wait(timeout=min(1.0, max(0.0, deadline - time.monotonic())))
        return 200, {"commands": [{"id": r["id"], "seq": r["ready_seq"], "envelope": json.loads(r["envelope"])} for r in rows],
                     "next": rows[-1]["ready_seq"] if rows else after}, {}

    def post_report(self, req, dev):
        self.device(req, dev)
        report = req.json()
        executed = report.pop("executed", [])
        if isinstance(executed, list):
            for e in executed[:50]:
                if isinstance(e, dict):
                    self.store.audit(dev, "executed", f"{str(e.get('type', '?'))[:40]} "
                                     f"{'ok' if e.get('ok') else 'FALHOU'}: {str(e.get('msg', ''))[:200]}")
        self.store.save_report(dev, report)
        return 200, {"ok": True}, {}

    def post_request(self, req, dev):
        self.device(req, dev)
        d = req.json()
        if d.get("kind") not in REQUEST_KINDS:
            raise HttpError(400, "tipo inválido")
        if not self.store.add_request(dev, d["kind"], _str(d, "text", 500)):
            raise HttpError(429, "pedidos demais em aberto")
        return 200, {"ok": True}, {}


def create_invite(store: Store, kind: str, guardian: str | None, name: str | None, ttl: int) -> str:
    token = secrets.token_urlsafe(24)
    store.put_invite(_hash(token), kind, guardian, name, int(time.time()) + ttl)
    return token


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, addr, handler, gw: Gateway):
        self.gw = gw
        self._active = 0
        self._alock = threading.Lock()
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        with self._alock:
            if self._active >= self.gw.cfg.max_connections:
                self.shutdown_request(request)  # lotado: fecha na hora, sem criar thread
                return
            self._active += 1
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._alock:
                self._active -= 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = 10
    server_version = "guardian"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _ip(self) -> str:
        peer = self.client_address[0]
        if peer in ("127.0.0.1", "::1"):  # atrás do proxy do Tailscale (serve/funnel): confia no último XFF
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[-1].strip()[:64] or peer
        return peer

    def _send(self, status, body, headers):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        ctype = headers.pop("Content-Type", "application/json")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if self.server.gw.cfg.secure_cookies:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if not ctype.startswith(("text/javascript", "text/css", "image/")):
            self.send_header("Cache-Control", "no-store")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _handle(self):
        gw = self.server.gw
        try:
            parts = urlsplit(self.path)
            if len(self.path) > 2048:
                raise HttpError(414, "endereço grande demais")
            body = b""
            if self.command == "POST":
                if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                    raise HttpError(411, "use Content-Length")
                try:
                    n = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    raise HttpError(400, "Content-Length inválido")
                if n < 0 or n > gw.body_limit(parts.path):
                    raise HttpError(413, "corpo grande demais")
                body = self.rfile.read(n) if n else b""
                if len(body) != n:
                    raise HttpError(400, "corpo incompleto")
            req = Req(self.command, parts.path, parts.query, self.headers, body, self._ip(), self.path)
            status, payload, headers = gw.dispatch(req)
            self._send(status, payload, dict(headers))
        except HttpError as e:
            self._send(e.status, {"error": e.msg}, {})
        except (TimeoutError, ConnectionError, BrokenPipeError):
            pass
        except Exception as e:  # não vaza detalhes
            print("erro interno:", repr(e), file=sys.stderr)
            try:
                self._send(500, {"error": "erro interno"}, {})
            except OSError:
                pass

    do_GET = do_POST = _handle

    def do_PUT(self):
        self._send(405, {"error": "método não permitido"}, {})

    do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_PUT


def make_server(cfg: Config, store: Store | None = None) -> _Server:
    gw = Gateway(cfg, store)
    srv = _Server((cfg.bind, cfg.port), Handler, gw)
    threading.Thread(target=gw._purge_loop, daemon=True).start()
    return srv
