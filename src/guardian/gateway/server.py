"""Servidor HTTP do gateway: só biblioteca padrão + cryptography, HTTP/1.0 (uma requisição por conexão)."""
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import serialization

from ..protocol import b64, commands as cmds, devauth, tailnet, webauthn
from ..executor.domains import is_public_suffix
from ..executor.domains import normalize as normalize_domain
from . import webpush
from .advisor import Advisor
from .alerts import Alerts, Notifier
from .config import Config
from .db import REQUEST_DOMAINS_MAX, Store
from .limits import Limiter, NonceCache

DEVICE_TYPES = {"set_config", "confirm", "cancel", "approve_app", "revoke_app", "request_maintenance",
                "set_dev_policy", "set_pin", "set_dev_pin", "activate"} | cmds.TRUST_TYPES
EXECUTOR_TYPES = {"pihole_allow", "pihole_deny", "pihole_remove", "pihole_batch"} | cmds.MASTER_TYPES | cmds.TRUST_TYPES
SEE_FLAGS = ("devices", "rules", "apps", "history")   # o que o admin deixa um guardião ver
STATUS_KEYS = {"kind", "ts", "version", "owner", "filterActive", "filterReason", "tailscale", "activated", "pinSet", "platform"}
RULE_KEYS = {"snapshot", "labels", "groups", "hints", "pending", "windows", "pkgNames"}
APP_KEYS = {"pendingApps", "approvedApps"}
REQUEST_KINDS = {"domain", "app", "other", "unblock", "install", "command"}
ADMIN_REQUEST_KINDS = {"install": cmds.T_WIN_INSTALL, "command": cmds.T_WIN_RUN}  # pedido do computador -> comando que o aprova
ADMIN_REQUESTS_MAX_PER_DEV = 10
NET_ID = r"net-[0-9a-f]{1,4}(?:-[0-9a-f]{1,4}){3,7}"  # cliente da rede sem pareamento (IP com hífens)
BLOCK_SOURCES = {"own", "list", "veto"}  # own: nada liberou (dá para pedir) · list: lista do Pi-hole · veto: site vetado pelo mestre

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/crypto.js": ("crypto.js", "text/javascript; charset=utf-8"),
    "/ui.js": ("ui.js", "text/javascript; charset=utf-8"),
    "/gate.js": ("gate.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
    "/icon-maskable-512.png": ("icon-maskable-512.png", "image/png"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def describe_window(w: dict | None) -> str:
    if not w:
        return "sem restrição"
    names = ["seg", "ter", "qua", "qui", "sex", "sáb", "dom"]
    days = [d for d in range(7) if d in w["days"]]
    runs, start = [], 0
    for i in range(1, len(days) + 1):
        if i == len(days) or days[i] != days[i - 1] + 1:
            runs.append((days[start], days[i - 1]))
            start = i
    text = ", ".join(names[a] if a == b else f"{names[a]}–{names[b]}" for a, b in runs)
    f = lambda m: f"{m // 60}h" + (f"{m % 60:02d}" if m % 60 else "")  # noqa: E731
    return f"{text}, {f(w['from'])} às {f(w['to'])}"


def window_left_s(w: dict, now: float) -> float:
    """Segundos até o fim da janela de hoje (0 se estiver fora)."""
    import datetime
    t = datetime.datetime.fromtimestamp(now + w["utc_offset_min"] * 60, datetime.timezone.utc)
    return max(0.0, (w["to"] - (t.hour * 60 + t.minute)) * 60 - t.second)


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
        self.advisor = Advisor(self.store, cfg.ai_key, cfg.ai_model, cfg.ai_daily_max)   # desligado se não houver chave
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
        self.vapid = self._load_vapid()
        self.alerts = Alerts(self.store)
        self.notifier = Notifier(self.store, self.vapid, cfg.push_subject, cfg.allow_any_push_endpoint)
        self.static = {}
        for path, (name, ctype) in STATIC.items():
            p = os.path.join(STATIC_DIR, name)
            if os.path.exists(p):
                with open(p, "rb") as f:
                    self.static[path] = (f.read(), ctype)
        h = hashlib.sha256()
        for path in sorted(self.static):
            h.update(path.encode() + b"|" + self.static[path][0])
        self.build = h.hexdigest()[:12]
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
            ("GET", r"/v1/devices/(?P<dev>[a-z2-7]{20})/requests", self.device_requests),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/requests/(?P<rid>[0-9]{1,12})/cancel", self.cancel_request),
            ("GET", r"/v1/devices/(?P<dev>[a-z2-7]{20})/clients", self.executor_clients),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/apps/refuse", self.refuse_app),
            ("GET", r"/v1/my/decisions", self.my_decisions),
            ("GET", r"/v1/devices/(?P<dev>[a-z2-7]{20})/apps/refused", self.device_refused_apps),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/apps/request", self.device_ask_apps),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/blocked", self.post_blocked),
            ("GET", r"/v1/devices/(?P<dev>[a-z2-7]{20})/blocked", self.device_blocked),
            ("GET", r"/v1/devices/(?P<dev>[a-z2-7]{20})/blocked-index", self.executor_blocked_index),
            ("GET", r"/v1/blocked", self.blocked),
            ("POST", r"/v1/requests/(?P<rid>[0-9]{1,12})/resolve", self.resolve),
            ("POST", r"/v1/devices/(?P<dev>[a-z2-7]{20})/forget", self.forget),
            ("GET", r"/v1/push/key", self.push_key),
            ("POST", r"/v1/push/subscribe", self.push_subscribe),
            ("POST", r"/v1/push/unsubscribe", self.push_unsubscribe),
            ("POST", r"/v1/push/test", self.push_test),
            ("GET", r"/v1/commands/awaiting", self.awaiting),
            ("POST", r"/v1/commands/(?P<cid>[0-9]{1,12})/cosign", self.cosign),
            ("GET", r"/v1/audit", self.audit),
            ("POST", r"/v1/guardians/(?P<gid>g_[0-9a-f]{8})/see", self.set_see),
            ("POST", r"/v1/guardians/(?P<gid>g_[0-9a-f]{8})/remove", self.remove_guardian),
            ("POST", r"/v1/guardians/(?P<gid>g_[0-9a-f]{8})/credentials/remove", self.remove_credential),
            ("GET", r"/v1/requests", self.requests),
            ("GET", r"/v1/analyses", self.analyses),
            ("POST", r"/v1/requests/(?P<rid>[0-9]{1,12})/dismiss", self.dismiss),
        ]
        self.routes = [(m, re.compile(p + r"\Z"), f) for m, p, f in self.routes]

    # ------------------------------------------------------------------ infra
    def body_limit(self, path: str) -> int:
        if path.endswith("/report") or path.endswith("/blocked"):
            return 64 * 1024
        if path.endswith("/commands") or path.endswith("/cosign"):
            return 16 * 1024
        if path.endswith("/requests"):
            return 12 * 1024  # pedido de comando do computador leva o script (até 6 KB)
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

    def _load_vapid(self):
        raw = self.store.meta_get("vapid_priv")
        if raw:
            return serialization.load_der_private_key(b64.dec(raw), None)
        key = webpush.new_vapid_key()
        self.store.meta_set("vapid_priv", b64.enc(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))
        return key

    def alerts_tick(self) -> int:
        """Avalia o que mudou e avisa os guardiões inscritos. Devolve quantos avisos foram gerados."""
        notes = self.alerts.evaluate()
        if notes:
            self.notifier.notify(notes)
        return len(notes)

    def _alerts_loop(self):
        while True:
            time.sleep(self.cfg.alerts_interval_s)
            try:
                self.alerts_tick()
            except Exception as e:
                print("alertas falharam:", repr(e), file=sys.stderr)

    # ------------------------------------------------------------------ push
    def push_key(self, req):
        self.guardian(req)
        return 200, {"key": b64.enc(webpush.public_bytes(self.vapid))}, {}

    def push_subscribe(self, req):
        gid = self.guardian(req)
        d = req.json()
        keys = d.get("keys") if isinstance(d.get("keys"), dict) else {}
        endpoint = _str(d, "endpoint", 1000)
        try:
            p256dh, auth = b64.dec(_str(keys, "p256dh", 200)), b64.dec(_str(keys, "auth", 100))
        except ValueError:
            raise HttpError(400, "chaves de push inválidas")
        if len(p256dh) != 65 or p256dh[0] != 4 or len(auth) != 16:
            raise HttpError(400, "chaves de push inválidas")
        if not self.cfg.allow_any_push_endpoint and not webpush.endpoint_allowed(endpoint):
            raise HttpError(400, "serviço de push não permitido")
        self.store.add_push(endpoint, gid, keys["p256dh"], keys["auth"])
        return 200, {"ok": True}, {}

    def push_unsubscribe(self, req):
        gid = self.guardian(req)
        self.store.delete_push(_str(req.json(), "endpoint", 1000), gid)
        return 200, {"ok": True}, {}

    def push_test(self, req):
        gid = self.guardian(req)
        if not self.l_cmd.allow("push:" + gid):
            raise HttpError(429, "devagar")
        n = self.notifier.notify([{"tag": "teste", "title": "NotToday Guardian", "body": "Aviso de teste: as notificações funcionam.",
                                   "exclude": None}], guardian=gid)
        return 200, {"sent": n}, {}

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

    @staticmethod
    def _window(g) -> dict | None:
        return json.loads(g["window"]) if g["window"] else None

    def start_session(self, gid: str) -> dict:
        now = time.time()
        ttl = self.cfg.session_ttl_s
        w = self._window(self.store.guardian(gid))
        if w:  # a sessão de quem tem janela acaba quando a janela acaba
            ttl = min(ttl, window_left_s(w, now))
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v[1] > now}
            if len(self.sessions) >= 200:
                raise HttpError(503, "ocupado")
            token = secrets.token_urlsafe(32)
            self.sessions[_hash(token)] = (gid, now + ttl)
        attrs = f"{self.cookie_name()}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={int(ttl)}"
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
        g = self.store.guardian(s[0])
        if not g:
            raise HttpError(401, "faça login")
        w = self._window(g)
        if not cmds.in_window(w, time.time()):
            raise HttpError(403, f"fora da janela de horário deste guardião ({describe_window(w)})")
        return s[0]

    def who(self, req: Req):
        """(gid, papel, o que pode ver) do guardião logado."""
        gid = self.guardian(req)
        g = self.store.guardian(gid)
        if not g:
            raise HttpError(401, "faça login")
        try:
            see = json.loads(g["see"] or "{}")
        except ValueError:
            see = {}
        return gid, g["role"], {k: bool(see.get(k)) for k in SEE_FLAGS}

    def admin(self, req: Req) -> str:
        gid, role, _ = self.who(req)
        if role not in cmds.ADMINISH:
            raise HttpError(403, "só o guardião-mor")
        return gid

    def master(self, req: Req) -> str:
        """Incluir e remover guardiões: só o mestre. Enquanto não existe mestre, vale o modo antigo (guardião-mor)."""
        gid, role, _ = self.who(req)
        if role == cmds.ROLE_MASTER or (role == cmds.ROLE_ADMIN and self.store.master_count() == 0):
            return gid
        raise HttpError(403, "só o guardião-mestre inclui, remove ou muda guardiões")

    def trust(self) -> cmds.Trust:
        return cmds.Trust(self.cfg.rp_id, self.cfg.origin,
                          {g: cmds.Guardian(v["name"], v["creds"], v["role"], v["allow_sync"], v["window"])
                           for g, v in self.store.trust_dict().items()})

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
            allow_sync, window = bool(inv["allow_sync"]), json.loads(inv["window"]) if inv["window"] else None
        else:
            g = self.store.one("SELECT * FROM guardians WHERE id=?", (inv["guardian"],))
            if not g:
                raise HttpError(400, "convite inválido")
            gid, name = g["id"], g["name"]
            exclude = [c["cred"] for c in self.store.q("SELECT cred FROM credentials WHERE guardian=?", (gid,))]
            allow_sync, window = bool(g["allow_sync"]), json.loads(g["window"]) if g["window"] else None  # passkey nova herda a regra do guardião
        role = "admin" if self.store.guardian_count() == 0 else inv["role"]
        cid, ch = self.new_challenge("register", {"gid": gid, "name": name, "kind": inv["kind"], "invite": _hash(token), "role": role,
                                                  "allow_sync": allow_sync, "window": window})
        return 200, {"allow_sync": allow_sync, "challengeId": cid, "publicKey": {
            **({} if allow_sync else {"hints": ["client-device"]}),
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
            cred, spki, be = webauthn.parse_registration(
                b64.dec(_str(d, "attestationObject", 4096)), b64.dec(_str(d, "clientDataJSON", 2048)),
                ch, self.cfg.rp_id, self.cfg.origin)
        except (webauthn.WebAuthnError, ValueError) as e:
            raise HttpError(400, f"registro recusado: {e}")
        if be and not ctx.get("allow_sync", True):
            raise HttpError(400, "essa passkey seria sincronizada (por exemplo na conta Google ou Apple); este guardião só aceita passkey "
                                 "presa ao aparelho: escolha o Windows Hello, o Touch ID ou uma chave de segurança")
        if not self.store.consume_invite(ctx["invite"]):
            raise HttpError(400, "convite já usado ou expirado")
        cred_b64 = b64.enc(cred)
        if self.store.credential(cred_b64):
            raise HttpError(409, "credencial já cadastrada")
        if ctx["kind"] == "new_guardian":
            self.store.add_guardian(ctx["gid"], ctx["name"], cred_b64, b64.enc(spki), ctx.get("role", "domains"), be,
                                    ctx.get("allow_sync", True), ctx.get("window"))
        else:
            self.store.add_credential(ctx["gid"], cred_b64, b64.enc(spki), be)
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
        g = self.store.guardian(row["guardian"])
        try:
            webauthn.verify_assertion(
                b64.dec(row["spki"]), b64.dec(_str(d, "authenticatorData", 1024)), b64.dec(_str(d, "clientDataJSON", 2048)),
                b64.dec(_str(d, "signature", 512)), ch, self.cfg.rp_id, self.cfg.origin, allow_sync=bool(g["allow_sync"]))
        except (webauthn.WebAuthnError, ValueError):
            raise HttpError(401, "login recusado")
        w = self._window(g)
        if not cmds.in_window(w, time.time()):
            self.store.audit(None, "login", f"{g['id']} recusado: fora da janela de horário")
            raise HttpError(403, f"fora da janela de horário deste guardião ({describe_window(w)})")
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
        gid, role, see = self.who(req)
        g = self.store.guardian(gid)
        others = {r["id"]: json.loads(r["see"] or "{}") for r in self.store.q("SELECT id, see FROM guardians")} if role in cmds.ADMINISH else {}
        creds = {r["cred"]: {"created": r["created"], "be": bool(r["be"])} for guardian in self.store.trust_dict() for r in self.store.credentials_of(guardian)
                 if role in cmds.ADMINISH or guardian == gid}
        return 200, {"guardian": {"id": gid, "name": g["name"], "role": role, "see": see}, "see_of": others, "cred_info": creds, "now": int(time.time()),
                     "trust": self.store.trust_dict(),
                     "rp_id": self.cfg.rp_id, "origin": self.cfg.origin}, {}

    def make_invite(self, req):
        gid, role, _ = self.who(req)
        d = req.json()
        kind = d.get("kind")
        if kind not in ("new_guardian", "add_passkey"):
            raise HttpError(400, "tipo de convite inválido")
        if kind == "new_guardian":
            self.master(req)
        new_role = d.get("role", "domains")
        if new_role not in cmds.ROLES:
            raise HttpError(400, "papel inválido")
        if new_role == cmds.ROLE_MASTER and role != cmds.ROLE_MASTER:
            raise HttpError(403, "só um mestre convida outro mestre (sem mestre, promova um guardião-mor)")
        allow_sync = d.get("allow_sync", True)
        if not isinstance(allow_sync, bool):
            raise HttpError(400, "valor inválido para passkey sincronizável")
        try:
            window = cmds.check_window(d.get("window"))
        except cmds.CommandError as e:
            raise HttpError(400, str(e))
        token = create_invite(self.store, kind, gid if kind == "add_passkey" else None,
                              _str(d, "name", 64) if kind == "new_guardian" else None, self.cfg.invite_ttl_s,
                              new_role if kind == "new_guardian" else role, allow_sync, window)
        return 200, {"token": token, "expires_in": self.cfg.invite_ttl_s}, {}

    def make_pairing(self, req):
        self.admin(req)
        kind = req.json().get("kind")
        if kind not in ("device", "executor"):
            raise HttpError(400, "tipo inválido")
        token = secrets.token_urlsafe(24)
        self.store.put_pairing(_hash(token), kind, int(time.time()) + self.cfg.invite_ttl_s)
        return 200, {"token": token, "expires_in": self.cfg.invite_ttl_s}, {}

    def list_devices(self, req):
        _, role, see = self.who(req)
        out = []
        refused = self.store.refused_apps()
        approved_by, refused_by = self.store.app_marks()
        asked = self.store.asked_apps()
        for r in self.store.devices():
            report = json.loads(r["report"]) if r["report"] else None
            d = {"id": r["id"], "kind": r["kind"], "name": r["name"], "spki": r["spki"], "created": r["created"],
                 "last_seen": r["last_seen"], "report_ts": r["report_ts"], "pending": r["pending"], "report": report,
                 "refused": refused.get(r["id"], []), "approved_by": approved_by.get(r["id"], {}), "refused_by": refused_by.get(r["id"], {})}
            if report and report.get("pendingApps") and asked.get(r["id"]):
                report["pendingApps"] = [{**a, "asked": True} if a.get("pkg") in asked[r["id"]] else a for a in report["pendingApps"] if isinstance(a, dict)]
            if role not in cmds.ADMINISH and r["kind"] != "executor":
                # apps pendentes todo guardião vê (ele também aprova e recusa); o resto depende do que o guardião-mor liberou
                keep = (STATUS_KEYS if see["devices"] else set()) | (RULE_KEYS if see["rules"] else set()) | (APP_KEYS if see["apps"] else {"pendingApps"})
                d["report"] = {k: v for k, v in report.items() if k in keep} if report and keep else None
                if not see["devices"]:
                    d.update(last_seen=0, report_ts=0, pending=0)
            out.append(d)
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

    @staticmethod
    def _is_windows(row) -> bool:
        """O aparelho se declarou computador com Windows (o agente informa `platform` no relatório assinado dele)."""
        try:
            return json.loads(row["report"] or "{}").get("platform") == "windows"
        except (ValueError, AttributeError):
            return False

    def post_command(self, req, dev):
        gid = self.guardian(req)
        if not self.l_cmd.allow(gid):
            raise HttpError(429, "devagar")
        row = self.store.device(dev)
        if not row:
            raise HttpError(404, "aparelho desconhecido")
        env = req.json()
        trust = self.trust()
        try:
            payload = b64.dec(_str(env, "payload", 12000))
            cmd = cmds.parse_payload(payload)
            signers = cmds.verify_sigs(trust, payload, env.get("sigs"))
        except (cmds.CommandError, ValueError) as e:
            raise HttpError(400, str(e))
        allowed = EXECUTOR_TYPES if row["kind"] == "executor" else DEVICE_TYPES | (cmds.WIN_TYPES if self._is_windows(row) else set())
        if cmd["dev"] != dev or cmd["guardian"] != gid or gid not in signers or cmd["type"] not in allowed:
            raise HttpError(400, "comando não confere com o destino, o autor ou o tipo")
        try:
            cmds.check_author(trust, cmd)  # papel e janela de horário (o aparelho e o executor conferem de novo, com o relógio deles)
        except cmds.CommandError as e:
            raise HttpError(403, str(e))
        if cmd["type"] in cmds.WIN_TYPES:
            try:
                cmds.check_win_args(cmd["type"], cmd["args"], time.time(), creating=True)
            except cmds.CommandError as e:
                raise HttpError(400, str(e))
        if self.store.pending_count(dev) >= self.cfg.max_pending_per_dev:
            raise HttpError(429, "fila cheia")
        ready = cmd["type"] in cmds.GUARDIAN_TYPES or len(signers & trust.admins()) >= cmds.required_signers(trust, cmd)
        cid = self.store.enqueue(dev, gid, cmd["ctr"], {"payload": env["payload"], "sigs": env["sigs"]}, ready)
        if cid is None:
            raise HttpError(409, "contador repetido")
        self.store.audit(dev, "queued", f"{gid}: {cmd['type']}" + ("" if ready else " (aguarda 2º guardião)"))
        pkg = cmd["args"].get("pkg")
        if ready and isinstance(pkg, str) and re.fullmatch(r"[A-Za-z0-9._]{1,200}", pkg):
            if cmd["type"] == "approve_app":
                self.store.record_approval(dev, pkg, gid)  # para o guardião ver o que aprovou e poder revogar
            elif cmd["type"] == "revoke_app":
                self.store.drop_approval(dev, pkg)
        if ready:
            self._after_ready(cmd, gid)
            self._wake()
        return 200, {"id": cid, "status": "ready" if ready else "awaiting"}, {}

    def _after_ready(self, cmd: dict, by: str) -> None:
        """Efeitos no próprio gateway de um comando que já tem as assinaturas: o gateway guarda o papel de cada guardião."""
        if cmd["type"] == cmds.T_SET_ROLE:
            a = cmd["args"]
            g = self.store.guardian(a.get("id"))
            if g and a.get("role") in cmds.ROLES and not (g["role"] == cmds.ROLE_MASTER and a["role"] != cmds.ROLE_MASTER and self.store.master_count() <= 1):
                self.store.set_role(a["id"], a["role"])
                self.store.audit(None, "guardian", f"{by} mudou o papel de {a['id']} para {a['role']}")

    def _wake(self):
        with self.cond:
            self.cond.notify_all()

    def awaiting(self, req):
        gid, role, _ = self.who(req)
        out = []
        if role not in cmds.ADMINISH:
            return 200, {"commands": out}, {}
        for r in self.store.awaiting():
            env = json.loads(r["envelope"])
            signed = {s.get("guardian") for s in env.get("sigs", [])}
            out.append({"id": r["id"], "dev": r["dev"], "guardian": r["guardian"], "envelope": env,
                        "can_cosign": gid not in signed})
        return 200, {"commands": out}, {}

    def cosign(self, req, cid):
        gid = self.admin(req)
        if not self.l_cmd.allow(gid):
            raise HttpError(429, "devagar")
        row = self.store.command(int(cid))
        if not row or row["status"] != "awaiting":
            raise HttpError(404, "comando não aguarda assinatura")
        env = json.loads(row["envelope"])
        sig = req.json().get("sig")
        if not isinstance(sig, dict) or sig.get("guardian") != gid or any(s.get("guardian") == gid for s in env["sigs"]):
            raise HttpError(400, "assinatura inválida para este guardião")
        trust = self.trust()
        payload = b64.dec(env["payload"])
        sigs = env["sigs"] + [sig]
        try:
            signers = cmds.verify_sigs(trust, payload, sigs)
        except cmds.CommandError as e:
            raise HttpError(400, str(e))
        cmd = cmds.parse_payload(payload)
        try:
            cmds.check_author(trust, cmd)
        except cmds.CommandError as e:
            raise HttpError(400, str(e))
        if len(signers & trust.admins()) < cmds.required_signers(trust, cmd):
            raise HttpError(400, "ainda faltam assinaturas")
        self.store.make_ready(row["id"], {"payload": env["payload"], "sigs": sigs})
        self.store.audit(row["dev"], "queued", f"{gid} co-assinou {cmd['type']}")
        self._after_ready(cmd, gid)
        self._wake()
        return 200, {"status": "ready"}, {}

    def audit(self, req):
        _, role, see = self.who(req)
        q = parse_qs(req.query)
        limit = min(int(q.get("limit", ["100"])[0]) if q.get("limit", ["100"])[0].isdigit() else 100, 500)
        rows = [dict(r) for r in self.store.audit_list(limit)]
        if role not in cmds.ADMINISH and not see["history"]:  # sem permissão: só o que é de domínio (executor e pedidos)
            ex = {r["id"] for r in self.store.q("SELECT id FROM devices WHERE kind='executor'")}
            rows = [r for r in rows if r["dev"] in ex or r["kind"] == "request"]
        return 200, {"items": rows}, {}

    def set_see(self, req, gid):
        self.admin(req)
        g = self.store.guardian(gid)
        if not g or g["role"] in cmds.ADMINISH:
            raise HttpError(404, "guardião não encontrado")
        d = req.json()
        see = {k: bool(d.get(k)) for k in SEE_FLAGS}
        self.store.set_see(gid, see)
        self.store.audit(None, "guardian", f"visibilidade de {gid}: " + ", ".join(k for k, v in see.items() if v))
        return 200, {"see": see}, {}

    def remove_credential(self, req, gid):
        me = self.master(req)
        cred = _str(req.json(), "cred", 1400)
        if not self.store.delete_credential(gid, cred):
            raise HttpError(400, "passkey inexistente, ou é a última do guardião (remova o guardião)")
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v[0] != gid or me == gid}
        self.store.audit(None, "guardian", f"{me} removeu uma passkey de {gid}")
        return 200, {"ok": True}, {}

    def remove_guardian(self, req, gid):
        me = self.master(req)
        g = self.store.guardian(gid)
        if not g:
            raise HttpError(404, "guardião não encontrado")
        if gid == me or (g["role"] in cmds.ADMINISH and self.store.admin_count() <= 1) or (g["role"] == cmds.ROLE_MASTER and self.store.master_count() <= 1):
            raise HttpError(400, "não remove o último guardião-mor, o último mestre nem a si mesmo")
        self.store.delete_guardian(gid)
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v[0] != gid}
        self.store.audit(None, "guardian", f"{me} removeu {gid} do gateway")
        return 200, {"ok": True}, {}

    def requests(self, req):
        self.guardian(req)
        out = []
        for r in self.store.requests_open():
            d = dict(r)
            if r["kind"] == "unblock":
                d["items"] = [{"domain": i["domain"], "state": i["state"]} for i in self.store.request_items(r["id"])]
            if r["kind"] in ADMIN_REQUEST_KINDS:
                try:
                    d["payload"] = json.loads(r["payload"] or "{}")
                except ValueError:
                    d["payload"] = {}
            else:
                d.pop("payload", None)
            out.append(d)
        return 200, {"items": out}, {}

    def blocked(self, req):
        self.guardian(req)
        q = parse_qs(req.query)
        dev, src = q.get("dev", [None])[0], q.get("src", [None])[0]
        if dev is not None and not (re.fullmatch(r"[a-z2-7]{20}", dev) or re.fullmatch(NET_ID, dev)):
            raise HttpError(400, "aparelho inválido")
        if src is not None and src not in BLOCK_SOURCES:
            raise HttpError(400, "origem inválida")
        canaries: dict[str, str] = {}
        rows = [r for r in (self.store.blocked_list(dev, src) if dev else self.store.blocked_list_each(src))
                if r["domain"] != canaries.setdefault(r["dev"], self._canary(r["dev"]))]
        return 200, {"items": [self._blocked_row(r) for r in rows], "net": [dict(r) for r in self.store.net_clients()],
                     "now": int(time.time())}, {}

    @staticmethod
    def _blocked_row(r) -> dict:
        return {"dev": r["dev"], "domain": r["domain"], "src": r["src"], "list": r["list"], "cname": bool(r["cname"]),
                "count": r["count"], "first": r["first"], "last": r["last"]}

    def resolve(self, req, rid):
        gid = self.guardian(req)
        if not self.l_cmd.allow(gid):
            raise HttpError(429, "devagar")
        d = req.json()
        row = self.store.request(int(rid))
        if row and row["kind"] in ADMIN_REQUEST_KINDS and row["status"] == "open":
            return self._resolve_admin(req, gid, row, d)
        if not row or row["kind"] != "unblock" or row["status"] != "open":
            raise HttpError(404, "pedido não encontrado ou já resolvido")
        open_domains = {i["domain"] for i in self.store.request_items(row["id"]) if i["state"] == "open"}
        states: dict[str, tuple[str, int | None]] = {}
        cid = d.get("cmd")
        if cid is not None:
            c = self.store.command(cid) if isinstance(cid, int) and not isinstance(cid, bool) else None
            ex = self.store.device(c["dev"]) if c else None
            if not c or c["guardian"] != gid or not ex or ex["kind"] != "executor":
                raise HttpError(400, "comando não confere")
            try:
                cmd = cmds.parse_payload(b64.dec(json.loads(c["envelope"])["payload"]))
            except (cmds.CommandError, ValueError, KeyError):
                raise HttpError(400, "comando ilegível")
            if cmd["type"] != "pihole_batch":
                raise HttpError(400, "comando não é uma liberação")
            for it in cmd["args"].get("items", []):
                try:
                    dom = normalize_domain(it.get("domain"))
                except (ValueError, AttributeError):
                    continue
                if dom in open_domains:
                    states[dom] = ("allowed", it.get("ttl_s") if isinstance(it.get("ttl_s"), int) else None)
        deny = d.get("deny", [])
        if not isinstance(deny, list) or len(deny) > REQUEST_DOMAINS_MAX:
            raise HttpError(400, "lista de negados inválida")
        for dom in deny:
            if isinstance(dom, str) and dom in open_domains and dom not in states:
                states[dom] = ("denied", None)
        if not states:
            raise HttpError(400, "nada para resolver")
        self.store.resolve_domains(row["id"], states, gid)
        self.store.audit(row["dev"], "request", f"{gid}: " + ", ".join(f"{k} {v[0]}" for k, v in sorted(states.items()))[:250])
        return 200, {"ok": True}, {}

    def _resolve_admin(self, req, gid: str, row, d: dict):
        """Aprova um pedido de instalação ou de comando: o guardião-mor já enviou o comando assinado que faz exatamente o que foi pedido."""
        if self.store.guardian(gid)["role"] not in cmds.ADMINISH:
            raise HttpError(403, "só o guardião-mor")
        cid = d.get("cmd")
        c = self.store.command(cid) if isinstance(cid, int) and not isinstance(cid, bool) else None
        if not c or c["guardian"] != gid or c["dev"] != row["dev"]:
            raise HttpError(400, "comando não confere")
        try:
            cmd = cmds.parse_payload(b64.dec(json.loads(c["envelope"])["payload"]))
            want = json.loads(row["payload"] or "{}")
        except (cmds.CommandError, ValueError, KeyError):
            raise HttpError(400, "comando ilegível")
        if cmd["type"] != ADMIN_REQUEST_KINDS[row["kind"]] or any(cmd["args"].get(k) != v for k, v in want.items()):
            raise HttpError(400, "o comando não é o que foi pedido")  # o que foi assinado tem de ser exatamente o pedido
        self.store.set_request_status(row["id"], "approved")
        self.store.audit(row["dev"], "request", f"{gid}: aprovou {row['kind']}: {row['text'][:200]}")
        return 200, {"ok": True}, {}

    def dismiss(self, req, rid):
        _, role, _ = self.who(req)
        row = self.store.request(int(rid))
        if not row:
            raise HttpError(404, "pedido não encontrado")
        if role not in cmds.ADMINISH and row["kind"] not in ("domain", "unblock"):
            raise HttpError(403, "só o guardião-mor")
        if row["kind"] in ADMIN_REQUEST_KINDS:  # negar é diferente de aprovar: o computador mostra o estado
            self.store.set_request_status(int(rid), "denied")
            self.store.audit(row["dev"], "request", f"negou {row['kind']}: {row['text'][:200]}")
        else:
            self.store.dismiss_request(int(rid))
        return 200, {"ok": True}, {}

    def forget(self, req, dev):
        self.admin(req)
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
                    if e.get("type") == "pihole_batch" and isinstance(e.get("failed"), dict):
                        self.store.fail_allowed(dev, list(e["failed"])[:50])  # o guardião assinou, mas o executor não aplicou
        self.store.save_report(dev, report)
        if report.get("platform") == "windows":
            self.advisor.consider(dev, report)   # instalação que falhou ou não conferiu: abre a análise (em segundo plano)
        return 200, {"ok": True}, {}

    def analyses(self, req):
        """As análises por IA das instalações, para o guardião-mor e o mestre."""
        self.admin(req)
        return 200, {"items": self.store.analyses_for(None, 40), "enabled": self.advisor.enabled}, {}

    def device_refused_apps(self, req, dev):
        """O aparelho pergunta quais dos apps suspensos foram recusados (para mostrar o estado e permitir pedir de novo)."""
        row = self.device(req, dev)
        if row["kind"] != "device":
            raise HttpError(403, "aparelho inválido")
        return 200, {"refused": self.store.refused_of(dev)}, {}

    def device_ask_apps(self, req, dev):
        """A pessoa pede a liberação de apps suspensos (inclusive os que o guardião recusou, talvez por engano)."""
        row = self.device(req, dev)
        if row["kind"] != "device":
            raise HttpError(403, "aparelho inválido")
        d = req.json()
        raw = d.get("apps")
        if not isinstance(raw, list) or not 1 <= len(raw) <= 20:
            raise HttpError(400, "lista de apps inválida")
        pending = {a.get("pkg"): a.get("label") for a in (json.loads(row["report"]) if row["report"] else {}).get("pendingApps", []) if isinstance(a, dict)}
        names = []
        for a in raw:
            pkg = a.get("pkg") if isinstance(a, dict) else None
            if not isinstance(pkg, str) or not re.fullmatch(r"[A-Za-z0-9._]{1,200}", pkg) or pkg not in pending:
                raise HttpError(400, "só dá para pedir apps que estão suspensos neste aparelho")
            names.append(str(pending.get(pkg) or pkg)[:60])
        for a in raw:
            self.store.ask_app(dev, a["pkg"])
        text = f"Pediu a liberação de: {', '.join(names)}"[:500]
        if not self.store.add_request(dev, "app", text):
            raise HttpError(429, "pedidos demais em aberto")
        self.store.audit(dev, "request", text[:250])
        return 200, {"ok": True}, {}

    def my_decisions(self, req):
        """O que ESTE guardião decidiu: apps que aprovou e domínios que recusou (os domínios que liberou vêm do relatório do executor)."""
        gid = self.guardian(req)
        now = int(time.time())
        return 200, {"apps": [{"dev": r["dev"], "pkg": r["pkg"], "ts": r["ts"]} for r in self.store.approvals_by(gid)],
                     "denied": [{"dev": r["dev"], "domain": r["domain"], "ts": r["ts"]}
                                for r in self.store.denied_by(gid, now - 30 * 24 * 3600)]}, {}

    def refuse_app(self, req, dev):
        """Recusar um app pendente: some da lista dos guardiões; o aparelho o mantém suspenso. `undo` reconsidera."""
        gid = self.guardian(req)
        if not self.l_cmd.allow(gid):
            raise HttpError(429, "devagar")
        row = self.store.device(dev)
        if not row or row["kind"] != "device":
            raise HttpError(404, "aparelho desconhecido")
        d = req.json()
        pkg = d.get("pkg")
        if not isinstance(pkg, str) or not re.fullmatch(r"[A-Za-z0-9._]{1,200}", pkg):
            raise HttpError(400, "pacote inválido")
        if d.get("undo") is True:
            self.store.unrefuse_app(dev, pkg)
            self.store.audit(dev, "app", f"{gid}: reconsiderou {pkg}")
        else:
            self.store.refuse_app(dev, pkg, gid)
            self.store.audit(dev, "app", f"{gid}: recusou {pkg}")
        return 200, {"ok": True}, {}

    def executor_clients(self, req, dev):
        """Os IPs na Tailscale que cada aparelho declarou no relatório assinado dele (o executor monta o mapeamento IP -> aparelho)."""
        row = self.device(req, dev)
        if row["kind"] != "executor":
            raise HttpError(403, "só o executor lê isto")
        claims = {}
        for r in self.store.devices():
            if r["kind"] == "device" and r["report"]:
                claims[r["id"]] = tailnet.valid_ips(json.loads(r["report"]).get("tsIps"))
        ok = tailnet.ip_map(claims)  # IP declarado por dois aparelhos não vale para nenhum
        return 200, {"clients": [{"dev": d, "ips": [ip for ip in ips if ip in ok]} for d, ips in claims.items() if any(ip in ok for ip in ips)]}, {}

    def executor_blocked_index(self, req, dev):
        """O que está guardado, para o executor apagar o que passou a ser vetado (site vetado pelo mestre, lista nova). Só o executor lê."""
        row = self.device(req, dev)
        if row["kind"] != "executor":
            raise HttpError(403, "só o executor lê isto")
        return 200, {"items": [{"dev": r["dev"], "domain": r["domain"]} for r in self.store.blocked_pairs()]}, {}

    def post_blocked(self, req, dev):
        row = self.device(req, dev)
        if row["kind"] != "executor":
            raise HttpError(403, "só o executor envia bloqueios")
        d = req.json()
        target = d.get("dev")
        if isinstance(target, str) and re.fullmatch(NET_ID, target):  # cliente da rede sem pareamento: só aparece, não pede liberação
            name, ip = d.get("name"), d.get("ip")
            if not (isinstance(name, str) and name.strip() and isinstance(ip, str) and len(ip) <= 45):
                raise HttpError(400, "cliente da rede sem nome")
            self.store.put_net_client(target, name.strip()[:60], ip)
        else:
            trow = self.store.device(target) if isinstance(target, str) and re.fullmatch(r"[a-z2-7]{20}", target) else None
            if not trow or trow["kind"] != "device":
                raise HttpError(400, "aparelho de destino inválido")
        raw = d.get("items")
        if not isinstance(raw, list) or len(raw) > 200:
            raise HttpError(400, "lista inválida")
        items, now = [], int(time.time())
        for it in raw:
            try:
                dom = normalize_domain(it.get("domain"))
                src = it["src"]
                cnt, first, last = it["count"], it["first"], it["last"]
                lst = it.get("list", "")
                ok = (src in BLOCK_SOURCES and all(isinstance(x, int) and not isinstance(x, bool) for x in (cnt, first, last))
                      and 1 <= cnt <= 10_000_000 and 0 < first <= last <= now + 300 and isinstance(lst, str))
            except (ValueError, KeyError, AttributeError, TypeError):
                ok = False
            if ok:
                items.append({"domain": dom, "src": src, "list": lst[:120], "cname": 1 if it.get("cname") else 0,
                              "count": cnt, "first": first, "last": last})
        self.store.merge_blocked(target, items)
        veto = []  # domínios que o executor vetou (listas de conteúdo adulto, site vetado pelo mestre): somem do que já estava guardado
        for x in (d.get("veto") if isinstance(d.get("veto"), list) else [])[:500]:
            try:
                veto.append(normalize_domain(x))
            except ValueError:
                continue
        self.store.drop_blocked(target, veto)
        return 200, {"ok": True, "accepted": len(items)}, {}

    def _canary(self, dev: str) -> str:
        """O domínio-canário que o aparelho relatou ('' se não houver). Ele é o teste de saúde: bloqueado de propósito."""
        row = self.store.device(dev)
        try:
            return normalize_domain(json.loads(row["report"])["snapshot"]["canary"])
        except (TypeError, KeyError, ValueError, AttributeError):
            return ""

    def device_blocked(self, req, dev):
        row = self.device(req, dev)
        if row["kind"] != "device":
            raise HttpError(403, "aparelho inválido")
        src = parse_qs(req.query).get("src", [None])[0]
        if src is not None and src not in BLOCK_SOURCES:
            raise HttpError(400, "origem inválida")
        self.store.touch(dev)
        if parse_qs(req.query).get("scope", [None])[0] == "all":
            return self._blocked_all(row, src)
        canary = self._canary(dev)
        return 200, {"items": [self._blocked_row(r) for r in self.store.blocked_list(dev, src, 300) if r["domain"] != canary],
                     "now": int(time.time())}, {}

    def _blocked_all(self, row, src):
        """O computador (agente do Windows) vê os bloqueios de todos os aparelhos protegidos, só para ler: pedir liberação continua
        sendo por aparelho e só para regras próprias. Outros aparelhos (celular, tablet) enxergam só os próprios."""
        try:
            platform = json.loads(row["report"]).get("platform")
        except (TypeError, ValueError, AttributeError):
            platform = None
        if platform != "windows":
            raise HttpError(403, "só o computador vê os bloqueios dos outros aparelhos")
        devs = [d for d in self.store.devices() if d["kind"] == "device"]
        names = {d["id"]: d["name"] for d in devs}
        canaries = {d["id"]: self._canary(d["id"]) for d in devs}
        items = [{**self._blocked_row(r), "name": names[r["dev"]]} for r in self.store.blocked_list_each(src)
                 if r["dev"] in names and r["domain"] != canaries[r["dev"]]]
        return 200, {"items": items, "devices": [{"id": d["id"], "name": d["name"]} for d in devs], "now": int(time.time())}, {}

    def device_requests(self, req, dev):
        self.device(req, dev)
        return 200, {"requests": self.store.device_requests(dev), "admin": self.store.device_admin_requests(dev),
                     "analyses": self.store.analyses_for(dev, 10), "now": int(time.time())}, {}

    def cancel_request(self, req, dev, rid):
        self.device(req, dev)
        if not self.store.cancel_request(int(rid), dev):
            raise HttpError(404, "pedido não encontrado ou já resolvido")
        self.store.audit(dev, "request", f"pedido {rid} cancelado pelo aparelho")
        return 200, {"ok": True}, {}

    def post_request(self, req, dev):
        self.device(req, dev)
        d = req.json()
        if d.get("kind") not in REQUEST_KINDS:
            raise HttpError(400, "tipo inválido")
        if d["kind"] == "unblock":
            raw = d.get("domains")
            if not isinstance(raw, list) or not 1 <= len(raw) <= REQUEST_DOMAINS_MAX:
                raise HttpError(400, "lista de domínios inválida")
            try:
                doms = sorted({normalize_domain(x) for x in raw})
            except ValueError:
                raise HttpError(400, "domínio inválido")
            canary = self._canary(dev)
            if canary and any(canary == x or canary.endswith("." + x) for x in doms):  # nem ele, nem um pai que o cubra
                raise HttpError(400, "o domínio-canário não pode ser liberado")
            if any(is_public_suffix(x) for x in doms):
                raise HttpError(400, "não dá para pedir um sufixo inteiro (como cn ou com.br)")
            if not all(self.store.blocked_under(dev, x) for x in doms):  # o domínio bloqueado ou o pai dele (o app deixa encurtar)
                raise HttpError(400, "só dá para pedir domínios que foram bloqueados")
            if any(self.store.blocked_under(dev, x, "veto") for x in doms):  # site vetado pelo mestre: não se pede
                raise HttpError(400, "esse site foi vetado pelo guardião-mor; não dá para pedir")
            if not all(self.store.blocked_under(dev, x, "own") for x in doms):  # bloqueio de lista é só para ver: quem libera é o guardião, à mão
                raise HttpError(400, "esse domínio é bloqueado por uma lista; só o guardião pode liberar")
            rid = self.store.add_unblock_request(dev, doms)
            if rid is None:
                raise HttpError(429, "pedidos demais em aberto")
            self.store.audit(dev, "request", f"pedido de liberação: {', '.join(doms)[:250]}")
            return 200, {"ok": True, "id": rid or None}, {}
        if d["kind"] in ADMIN_REQUEST_KINDS:
            return self._post_admin_request(dev, d)
        if not self.store.add_request(dev, d["kind"], _str(d, "text", 500)):
            raise HttpError(429, "pedidos demais em aberto")
        return 200, {"ok": True}, {}

    def _post_admin_request(self, dev: str, d: dict):
        """O computador pede para instalar um programa ou rodar um comando como administrador. O guardião-mor lê o que vai ser executado."""
        row = self.store.device(dev)
        if not self._is_windows(row):
            raise HttpError(403, "só computadores com o agente do Windows pedem isto")
        type_ = ADMIN_REQUEST_KINDS[d["kind"]]
        payload = d.get("payload")
        try:
            cmds.check_win_request(type_, payload)
        except cmds.CommandError as e:
            raise HttpError(400, str(e))
        if self.store.admin_requests_open(dev) >= ADMIN_REQUESTS_MAX_PER_DEV:
            raise HttpError(429, "pedidos demais em aberto")
        if type_ == cmds.T_WIN_INSTALL:
            what = ((payload["id"] + (f" {payload['version']}" if payload.get("version") else "")) if payload["source"] == "winget"
                    else payload["url"] if payload["source"] == "url" else "arquivo " + payload["path"].replace("/", "\\").rsplit("\\", 1)[-1])
            text = f"Instalar {payload['name']} ({what})"
        else:
            text = "Rodar comando: " + (payload.get("name") or payload["script"].strip().splitlines()[0])[:120]
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if not self.store.add_request(dev, d["kind"], text[:500], body):
            raise HttpError(429, "pedidos demais em aberto")
        self.store.audit(dev, "request", text[:250])
        return 200, {"ok": True}, {}


def create_invite(store: Store, kind: str, guardian: str | None, name: str | None, ttl: int, role: str = "admin",
                  allow_sync: bool = True, window: dict | None = None) -> str:
    token = secrets.token_urlsafe(24)
    store.put_invite(_hash(token), kind, guardian, name, int(time.time()) + ttl, role, allow_sync, window)
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
        self.send_header("X-Build", self.server.gw.build)  # o site recarrega sozinho quando o servidor passa a servir outra versão
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
    if cfg.alerts_enabled:
        threading.Thread(target=gw._alerts_loop, daemon=True).start()
    return srv
