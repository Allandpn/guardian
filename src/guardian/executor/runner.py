"""Laço do executor: puxa comandos, verifica, aplica no Pi-hole, expira liberações temporárias e se reporta."""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..protocol import b64, commands as cmds, devauth, tailnet
from . import domains
from .pihole import Pihole, PiholeError
from .veto import Veto

MIN_TTL_S, MAX_TTL_S = 60, 30 * 24 * 3600
REPORT_EVERY_S = 60
LIST_CAP = 500
BATCH_MAX = 50
BLOCKS_EVERY_S = 10
BLOCKS_CHUNK = 150
BLOCKS_BACKFILL_S = 3600
BLOCKS_VETO_MAX = 400
OWN_STATUSES = {"REGEX", "DENYLIST", "REGEX_CNAME", "DENYLIST_CNAME"}
LIST_STATUSES = {"GRAVITY", "GRAVITY_CNAME"}


@dataclass
class ExecConfig:
    state_dir: str
    pihole_url: str
    pihole_password: str
    canary: str
    pihole_ca: str | None = None
    clients: dict | None = None       # {IP do aparelho na Tailscale: id do aparelho protegido}
    allow_mode: str = "exact"         # "regex": grava domínio + subdomínios como regex no Pi-hole (o guardião só vê o domínio)
    gravity_db: str | None = None     # gravity.db do Pi-hole: o que está nas listas dele (conteúdo adulto) não pode ser liberado; None desliga


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
        self.lock = threading.RLock()
        self.data = {"gateway": None, "consumer": None, "after": 0, "temp": [], "blocked_since": 0}
        if os.path.exists(path):
            with open(path) as f:
                self.data.update(json.load(f))

    def save(self) -> None:
        with self.lock:
            self._save()

    def _save(self) -> None:
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
        self._lists: dict | None = None
        self._lists_ts = 0.0
        self.veto = Veto(cfg.gravity_db, self.state.data.get("veto_parents"))

    # --- execução ---------------------------------------------------------------
    def _guard(self, domain, allow: bool = False) -> str:
        d = domains.normalize(domain)
        canary = domains.normalize(self.cfg.canary) if self.cfg.canary else None
        if canary and d == canary:
            raise ValueError("o domínio-canário não pode ser alterado")
        if allow and canary and self.cfg.allow_mode == "regex" and canary.endswith("." + domains.rule_domain(d)):
            raise ValueError("a liberação cobriria o domínio-canário")  # a regex inclui os subdomínios
        if allow:
            why = self.veto.reason(d, self.cfg.allow_mode == "regex")
            if why:
                raise ValueError(f"vetado: {why}")
        return d

    def _put(self, list_: str, d: str, who: str) -> None:
        if self.cfg.allow_mode == "regex":
            self.pihole.put_domain(list_, domains.to_regex(d), f"guardian:{who}", kind="regex")
        else:
            self.pihole.put_domain(list_, d, f"guardian:{who}")

    def _del(self, list_: str, d: str) -> None:
        """Tira o domínio da lista nas duas formas (exata e a regex gerada aqui); regras escritas à mão não são tocadas."""
        self.pihole.delete_domain(list_, d)
        for rx in domains.regex_forms(d):  # a atual (sem "www.") e a antiga (host inteiro)
            self.pihole.delete_domain(list_, rx, kind="regex")

    def _entries(self, list_: str) -> list[dict]:
        """Entradas da lista como domínios simples: as exatas e as regex geradas aqui."""
        out = {e["domain"]: e for e in self.pihole.list_entries(list_)}
        for e in self.pihole.list_entries(list_, kind="regex"):
            d = domains.from_regex(e["domain"])
            if d:
                out.setdefault(d, {"domain": d, "comment": e["comment"], "rx": True})  # rx: a regra cobre também os subdomínios
        return list(out.values())

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
            d, ttl = self._guard(a.get("domain"), allow=list_ == "allow"), self._ttl(a)
            self._put(list_, d, who)
            if list_ == "deny":
                self._del("allow", d)  # a lista de permissão vence a de bloqueio
                self._drop_temp("allow", d)
            self._drop_temp(list_, d)
            if ttl:
                self.state.data["temp"].append({"list": list_, "domain": d, "expires": int(self.now()) + ttl})
            return f"{'liberado' if list_ == 'allow' else 'bloqueado'} {d}" + (f" por {_fmt_ttl(ttl)}" if ttl else " (sem prazo)")
        if t == "pihole_batch":
            items = a.get("items")
            if not isinstance(items, list) or not 1 <= len(items) <= BATCH_MAX:
                raise ValueError("lote inválido")
            ok, bad = [], []
            for it in items:
                try:
                    if not isinstance(it, dict):
                        raise ValueError("item inválido")
                    d, ttl = self._guard(it.get("domain"), allow=True), self._ttl(it)
                    self._put("allow", d, who)
                    self._drop_temp("allow", d)
                    if ttl:
                        self.state.data["temp"].append({"list": "allow", "domain": d, "expires": int(self.now()) + ttl})
                    ok.append(f"{d} por {_fmt_ttl(ttl)}" if ttl else d)
                except ValueError as e:
                    bad.append(f"{str(it.get('domain'))[:60] if isinstance(it, dict) else '?'}: {e}")
            if bad and not ok:
                raise ValueError("; ".join(bad))
            return "liberados: " + ", ".join(ok) + (f" | falharam: {'; '.join(bad)}" if bad else "")
        if t == cmds.T_PARENT_BLOCK:
            action = a.get("action")
            if action not in ("add", "remove"):
                raise ValueError("ação inválida")
            changed = self.veto.add_parent(a.get("domain")) if action == "add" else self.veto.remove_parent(a.get("domain"))
            self.state.data["veto_parents"] = list(self.veto.parents)
            self.state.save()
            d = domains.rule_domain(a.get("domain"))
            if action == "add":
                return f"site vetado: {d}" if changed else f"{d} já estava vetado"
            return f"veto removido: {d}" if changed else f"{d} não estava vetado"
        if t == "pihole_remove":
            if a.get("list") not in ("allow", "deny"):
                raise ValueError("lista inválida")
            d = self._guard(a.get("domain"))
            self._del(a["list"], d)
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
                self._del(t["list"], t["domain"])
                self.executed.append({"type": "expirou", "ok": True, "msg": f"{t['list']} {t['domain']}"})
            except PiholeError as e:
                keep.append(t)  # tenta de novo no próximo ciclo
                print("expirar falhou:", e, file=sys.stderr)
        self.state.data["temp"] = keep
        self.state.save()

    def handle(self, env: dict) -> None:
        try:
            v = self.consumer.accept(env, now=self.now())  # janela de horário: relógio do executor, não o do navegador
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
             "roles": {g: v.role for g, v in self.consumer.trust.guardians.items()},
             "executed": self.executed[-50:]}
        try:
            allow, deny = self._entries("allow"), self._entries("deny")
            # As entradas do Guardian vêm primeiro: com centenas de entradas suas no Pi-hole, o corte alfabético escondia as liberações dele.
            for name, entries in (("allow", allow), ("deny", deny)):
                mine = sorted(e["domain"] for e in entries if e["comment"].startswith("guardian:"))
                others = sorted(e["domain"] for e in entries if not e["comment"].startswith("guardian:"))
                r[name] = (mine + others)[:LIST_CAP]
                r[name + "_total"] = len(entries)
                r[name + "_by"] = {e["domain"]: e["comment"][9:] for e in entries if e["comment"].startswith("guardian:")}
            r["pihole_ok"] = True
            r["veto"] = self._veto_report(allow)
        except PiholeError as e:
            r["pihole_ok"], r["pihole_error"] = False, str(e)[:200]
        self.gw.call("POST", f"/v1/devices/{self.dev}/report", r)
        self.executed.clear()
        self.last_report = time.monotonic()

    def _veto_report(self, allow: list[dict]) -> dict:
        """Os sites vetados pelo mestre e a auditoria: liberações que o veto não deixaria passar hoje (a lista muda todo dia)."""
        self.veto.refresh()
        bad = []
        for e in allow:
            why = self.veto.reason(e["domain"], bool(e.get("rx")))  # exata só cobre ela mesma; a regex cobre os subdomínios
            if why:
                bad.append({"domain": e["domain"], "why": why, "by": e["comment"][9:] if e["comment"].startswith("guardian:") else ""})
        bad.sort(key=lambda x: x["domain"])
        return {"on": self.veto.enabled, "parents": sorted(self.veto.parents), "listed": len(self.veto.listed),
                "audit": bad[:100], "audit_total": len(bad)}

    # --- bloqueios ---------------------------------------------------------------
    def _list_name(self, list_id) -> str:
        if self._lists is None or self.now() - self._lists_ts > 600:
            try:
                self._lists = self.pihole.list_names()
            except PiholeError:
                self._lists = self._lists or {}
            self._lists_ts = self.now()
        return self._lists.get(list_id, "") if isinstance(list_id, int) else ""

    def known_clients(self) -> dict:
        """IP -> aparelho: os que os aparelhos declaram no relatório (via gateway) e, por cima, o CLIENTS escrito à mão."""
        try:
            got = self.gw.call("GET", f"/v1/devices/{self.dev}/clients").get("clients", [])
            self._auto_clients = tailnet.ip_map({c["dev"]: c["ips"] for c in got
                                                 if isinstance(c, dict) and isinstance(c.get("dev"), str) and isinstance(c.get("ips"), list)})
        except (GatewayError, KeyError, TypeError) as e:
            print("clientes:", e, file=sys.stderr)  # sem o gateway, vale o último mapa bom
        return {**getattr(self, "_auto_clients", {}), **(self.cfg.clients or {})}

    def collect_blocks(self) -> int:
        """Lê no Pi-hole o que foi bloqueado para os aparelhos pareados e envia ao gateway. Devolve quantos domínios."""
        clients = self.known_clients()
        if not clients:
            return 0
        since = self.state.data.get("blocked_since") or self.now() - BLOCKS_BACKFILL_S
        newest = since
        canary = domains.normalize(self.cfg.canary) if self.cfg.canary else None
        per_dev: dict[str, dict] = {}
        vetoed: dict[str, set] = {}
        for ip, dev in clients.items():
            for q in self.pihole.queries(since, ip):
                status, t = q.get("status"), q.get("time")
                kind = "own" if status in OWN_STATUSES else "list" if status in LIST_STATUSES else None
                if kind is None or not isinstance(t, (int, float)):
                    continue
                newest = max(newest, float(t))
                cname = str(status).endswith("_CNAME")
                raw = q.get("cname") if cname and q.get("cname") else q.get("domain")
                try:
                    d = domains.normalize(raw)
                except ValueError:
                    continue
                if d == canary:  # o canário é o teste de saúde do aparelho: bloqueado de propósito, não é pedido de ninguém
                    continue
                if self.veto.reason(d, self.cfg.allow_mode == "regex"):  # não pode ser liberado: não vira pedido (e some do que já estava guardado)
                    vetoed.setdefault(dev, set()).add(d)
                    continue
                e = per_dev.setdefault(dev, {}).setdefault(d, {"domain": d, "count": 0, "first": int(t), "last": int(t),
                                                               "src": kind, "list": "", "cname": cname})
                e["count"] += 1
                e["first"], e["last"] = min(e["first"], int(t)), max(e["last"], int(t))
                if kind == "list" and not e["list"]:
                    e["list"] = self._list_name(q.get("list_id"))
        total = 0
        for dev in sorted(set(per_dev) | set(vetoed)):
            items = sorted(per_dev.get(dev, {}).values(), key=lambda x: x["last"], reverse=True)
            drop = sorted(vetoed.get(dev, ()))[:BLOCKS_VETO_MAX]
            for i in range(0, max(len(items), 1), BLOCKS_CHUNK):
                body = {"dev": dev, "items": items[i:i + BLOCKS_CHUNK]}
                if i == 0 and drop:
                    body["veto"] = drop  # o gateway apaga o que já tinha guardado destes domínios
                self.gw.call("POST", f"/v1/devices/{self.dev}/blocked", body)
            total += len(items)
        if newest > since:
            self.state.data["blocked_since"] = newest + 0.000001
            self.state.save()
        return total

    def _blocks_loop(self, stop) -> None:
        while not stop.is_set():
            try:
                self.collect_blocks()
            except (GatewayError, PiholeError) as e:
                print("bloqueios:", e, file=sys.stderr)
            stop.wait(BLOCKS_EVERY_S)

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
        threading.Thread(target=self._blocks_loop, args=(stop,), daemon=True).start()
        while not stop.is_set():
            try:
                self.step()
                delay = 2
            except (GatewayError, PiholeError) as e:
                print("erro:", e, file=sys.stderr)
                stop.wait(delay)
                delay = min(delay * 2, 60)
        self.pihole.logout()
