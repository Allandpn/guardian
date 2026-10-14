"""Laço do executor: puxa comandos, verifica, aplica no Pi-hole, expira liberações temporárias e se reporta."""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..protocol import b64, commands as cmds, devauth
from . import domains
from .pihole import Pihole, PiholeError

MIN_TTL_S, MAX_TTL_S = 60, 30 * 24 * 3600
REPORT_EVERY_S = 60
LIST_CAP = 500


@dataclass
class ExecConfig:
    state_dir: str
    pihole_url: str
    pihole_password: str
    canary: str
    pihole_ca: str | None = None


def _fmt_ttl(s: int) -> str:
    return f"{s // 86400} d" if s >= 86400 and s % 86400 == 0 else f"{s // 3600} h" if s >= 3600 and s % 3600 == 0 else f"{max(1, s // 60)} min"


class GatewayClient:
    def __init__(self, base: str, key, timeout: float = 40.0):
        self.base, self.key, self.timeout = base.rstrip("/"), key, timeout

    def call(self, method: str, path: str, body: dict | None = None, wait_s: float = 0):
        data = json.dumps(body).encode() if body is not None else b""
        h = devauth.headers(self.key, method, path, data, int(time.time()), os.urandom(9).hex())
        req = urllib.request.Request(self.base + path, data=data if method == "POST" else None, method=method, headers=h)
        if method == "POST":
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout + wait_s) as r:
                return json.loads(r.read(4_000_000) or b"{}")
        except urllib.error.HTTPError as e:
            raise GatewayError(e.code, e.read(2000).decode("utf-8", "replace")) from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise GatewayError(0, str(e)) from e


class GatewayError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(f"gateway {status}: {msg}")
        self.status = status


def parse_pairing(text: str) -> dict:
    try:
        d = json.loads(b64.dec(text.strip()))
        assert d["v"] == 1 and isinstance(d["guardians"], dict)
        return {"url": str(d["url"]).rstrip("/"), "rp": str(d["rp"]), "token": str(d["token"]), "guardians": d["guardians"]}
    except (ValueError, KeyError, AssertionError, TypeError) as e:
        raise ValueError("string de pareamento inválida") from e


class State:
    """Estado persistente: confiança fixada, contadores, cursor da fila e liberações temporárias."""

    def __init__(self, path: str):
        self.path = path
        self.data = {"gateway": None, "consumer": None, "after": 0, "temp": []}
        if os.path.exists(path):
            with open(path) as f:
                self.data.update(json.load(f))

    def save(self) -> None:
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)


def load_or_create_key(path: str):
    from cryptography.hazmat.primitives import serialization
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), None)
    key = devauth.new_private_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def pair(cfg: ExecConfig, pairing: str, name: str = "Pi-hole") -> str:
    """Registra o executor no gateway e fixa os guardiões do pareamento. Devolve o fingerprint."""
    p = parse_pairing(pairing)
    os.makedirs(cfg.state_dir, mode=0o700, exist_ok=True)
    key = load_or_create_key(os.path.join(cfg.state_dir, "executor.pem"))
    spki = devauth.spki_of(key)
    dev = devauth.device_id(spki)
    gw = GatewayClient(p["url"], key)
    body = {"pairing": p["token"], "pubkey": b64.enc(spki), "name": name, "kind": "executor"}
    gw.call("POST", "/v1/devices/register", body)
    st = State(os.path.join(cfg.state_dir, "state.json"))
    trust = cmds.Trust(p["rp"], p["url"], {g: cmds.Guardian(v["name"], dict(v["creds"])) for g, v in p["guardians"].items()})
    st.data.update(gateway=p["url"], consumer=cmds.Consumer(dev, trust).to_json(), after=0)
    st.save()
    return devauth.fingerprint(spki)


class Executor:
    def __init__(self, cfg: ExecConfig, pihole: Pihole | None = None, now=time.time):
        self.cfg = cfg
        self.now = now
        self.key = load_or_create_key(os.path.join(cfg.state_dir, "executor.pem"))
        self.state = State(os.path.join(cfg.state_dir, "state.json"))
        if not self.state.data["consumer"]:
            raise RuntimeError("executor não pareado: rode 'pair' primeiro")
        self.consumer = cmds.Consumer.from_json(self.state.data["consumer"])
        self.dev = devauth.device_id(devauth.spki_of(self.key))
        self.gw = GatewayClient(self.state.data["gateway"], self.key)
        self.pihole = pihole or Pihole(cfg.pihole_url, cfg.pihole_password, cfg.pihole_ca)
        self.executed: list[dict] = []
        self.last_report = 0.0

    # --- execução ---------------------------------------------------------------
    def _guard(self, domain) -> str:
        d = domains.normalize(domain)
        if self.cfg.canary and d == domains.normalize(self.cfg.canary):
            raise ValueError("o domínio-canário não pode ser alterado")
        return d

    @staticmethod
    def _ttl(args: dict) -> int | None:
        ttl = args.get("ttl_s")
        if ttl is None:
            return None
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not MIN_TTL_S <= ttl <= MAX_TTL_S:
            raise ValueError("duração fora do limite (1 min a 30 dias)")
        return ttl

    def _drop_temp(self, list_: str, domain: str) -> None:
        self.state.data["temp"] = [t for t in self.state.data["temp"] if (t["list"], t["domain"]) != (list_, domain)]

    def apply(self, cmd: dict) -> str:
        t, a, who = cmd["type"], cmd["args"], cmd["guardian"]
        if t in cmds.TRUST_TYPES:
            self.consumer.apply_trust(cmd)
            return "confiança atualizada"
        if t in ("pihole_allow", "pihole_deny"):
            list_, other = ("allow", "deny") if t == "pihole_allow" else ("deny", "allow")
            d, ttl = self._guard(a.get("domain")), self._ttl(a)
            self.pihole.put_domain(list_, d, f"guardian:{who}")
            if list_ == "deny":
                self.pihole.delete_domain("allow", d)  # a lista de permissão vence a de bloqueio
                self._drop_temp("allow", d)
            self._drop_temp(list_, d)
            if ttl:
                self.state.data["temp"].append({"list": list_, "domain": d, "expires": int(self.now()) + ttl})
            return f"{'liberado' if list_ == 'allow' else 'bloqueado'} {d}" + (f" por {_fmt_ttl(ttl)}" if ttl else " (sem prazo)")
        if t == "pihole_remove":
            if a.get("list") not in ("allow", "deny"):
                raise ValueError("lista inválida")
            d = self._guard(a.get("domain"))
            self.pihole.delete_domain(a["list"], d)
            self._drop_temp(a["list"], d)
            return f"removido de {'liberados' if a['list'] == 'allow' else 'bloqueados'}: {d}"
        raise ValueError(f"comando desconhecido: {t}")

    def expire_temp(self) -> None:
        keep, now = [], int(self.now())
        for t in self.state.data["temp"]:
            if t["expires"] > now:
                keep.append(t)
                continue
            try:
                self.pihole.delete_domain(t["list"], t["domain"])
                self.executed.append({"type": "expirou", "ok": True, "msg": f"{t['list']} {t['domain']}"})
            except PiholeError as e:
                keep.append(t)  # tenta de novo no próximo ciclo
                print("expirar falhou:", e, file=sys.stderr)
        self.state.data["temp"] = keep
        self.state.save()

    def handle(self, env: dict) -> None:
        try:
            v = self.consumer.accept(env)
        except cmds.CommandError as e:
            self.executed.append({"type": "?", "ok": False, "msg": f"recusado: {e}"})
            return
        try:
            msg = self.apply(v.cmd)
            self.executed.append({"type": v.cmd["type"], "ok": True, "msg": msg})
        except (ValueError, cmds.CommandError, PiholeError) as e:
            self.executed.append({"type": v.cmd["type"], "ok": False, "msg": str(e)})
        self.state.data["consumer"] = self.consumer.to_json()  # contador consumido, deu certo ou não
        self.state.save()

    # --- relatório ---------------------------------------------------------------
    def report(self) -> None:
        r = {"kind": "executor", "ts": int(self.now()), "canary_set": bool(self.cfg.canary),
             "ctrs": self.consumer.last_ctr, "temp": self.state.data["temp"][:100],
             "trust": {g: sorted(v.creds) for g, v in self.consumer.trust.guardians.items()},
             "executed": self.executed[-50:]}
        try:
            r["allow"], r["deny"] = self.pihole.list_domains("allow")[:LIST_CAP], self.pihole.list_domains("deny")[:LIST_CAP]
            r["pihole_ok"] = True
        except PiholeError as e:
            r["pihole_ok"], r["pihole_error"] = False, str(e)[:200]
        self.gw.call("POST", f"/v1/devices/{self.dev}/report", r)
        self.executed.clear()
        self.last_report = time.monotonic()

    # --- laço --------------------------------------------------------------------
    def step(self, wait_s: int = 25) -> int:
        """Um ciclo: consulta a fila, aplica o que veio, expira o que venceu e reporta se for hora. Devolve quantos comandos."""
        path = f"/v1/devices/{self.dev}/commands?after={self.state.data['after']}&wait={wait_s}"
        got = self.gw.call("GET", path, wait_s=wait_s)
        n = 0
        for c in got.get("commands", []):
            self.handle(c["envelope"])
            self.state.data["after"] = max(self.state.data["after"], c["seq"])
            self.state.save()
            n += 1
        self.expire_temp()
        if n or time.monotonic() - self.last_report >= REPORT_EVERY_S:
            self.report()
        return n

    def run(self, stop) -> None:
        delay = 2
        while not stop.is_set():
            try:
                self.step()
                delay = 2
            except (GatewayError, PiholeError) as e:
                print("erro:", e, file=sys.stderr)
                stop.wait(delay)
                delay = min(delay * 2, 60)
        self.pihole.logout()
