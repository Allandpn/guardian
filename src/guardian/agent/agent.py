"""Agente do Windows: puxa os comandos assinados dos guardiões, confere, executa como administrador e se reporta.

O computador é um aparelho como o celular (chave própria, relatório, pedidos). A diferença é o que ele sabe fazer: instalar programa e rodar script,
só com assinatura de guardião-mor ou mestre. O agente roda como SYSTEM e a pasta de estado só abre para SYSTEM e administradores:
quem usa o computador, numa conta comum, não alcança a chave nem o estado. Veja docs/AGENTE.md.
"""
import os
import queue
import re
import socket
import sys
import threading
import time
import traceback
from dataclasses import dataclass

from ..executor.runner import GatewayClient, GatewayError, State, load_or_create_key, parse_pairing
from ..protocol import b64, commands as cmds, devauth, tailnet
from . import actions

VERSION = "0.2.0"
REPORT_EVERY_S = actions._env_int("GUARDIAN_AGENT_REPORT_EVERY_S", 60)
RUNS_KEEP = 6
RUN_OUT_REPORT = 3000
UI_BLOCKED_MAX = 150


@dataclass
class AgentConfig:
    state_dir: str
    ui_port: int = 47657


def default_state_dir() -> str:
    base = os.environ.get("ProgramData") or os.path.expanduser("~")
    return os.path.join(base, "GuardianAgent")


def pair(cfg: AgentConfig, pairing: str, name: str | None = None) -> str:
    """Registra o computador no gateway e fixa os guardiões do pareamento. Devolve o fingerprint (confira por voz com o guardião)."""
    p = parse_pairing(pairing)
    # O papel, a regra de passkey e a janela de horário de cada guardião vêm do pareamento. Sem o papel, o agente não pareia:
    # assumir "guardião-mor" para quem não declarou papel daria a um guardião comum o poder de mandar comandos como administrador.
    if any(not isinstance(v, dict) or "role" not in v for v in p["guardians"].values()):
        raise ValueError("string de pareamento antiga (sem os papéis dos guardiões): gere uma nova no site")
    try:
        trust = cmds.Trust.from_json({"rp_id": p["rp"], "origin": p["url"], "guardians": p["guardians"]})
    except (cmds.CommandError, KeyError, TypeError) as e:
        raise ValueError(f"string de pareamento inválida: {e}") from e
    os.makedirs(cfg.state_dir, mode=0o700, exist_ok=True)
    key = load_or_create_key(os.path.join(cfg.state_dir, "agent.pem"))
    spki = devauth.spki_of(key)
    dev = devauth.device_id(spki)
    gw = GatewayClient(p["url"], key)
    gw.call("POST", "/v1/devices/register", {"pairing": p["token"], "pubkey": b64.enc(spki), "name": (name or socket.gethostname())[:64], "kind": "device"})
    st = State(os.path.join(cfg.state_dir, "state.json"))
    st.data.update(gateway=p["url"], consumer=cmds.Consumer(dev, trust).to_json(), after=0, runs=[])
    st.save()
    return devauth.fingerprint(spki)


# Argumentos silenciosos que cada fabricante documenta. Só uma sugestão: o que vale é o que o guardião lê e aprova.
SILENT_ARGS = (
    ("dbeaver", "/S /allusers"),   # o instalador do DBeaver recusa o /S sozinho (código 666660)
)
# pelo tipo de instalador (marcas no arquivo): Inno Setup ignora o /S e abre janela (LocalSend travou assim)
TYPE_ARGS = {"inno": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS", "burn": "/quiet /norestart", "nsis": "/S"}


def suggest_args(kind: str, signer: str, installer: str = "") -> str:
    if kind == "msi":
        return ""   # o msiexec já roda com /qn
    s = (signer or "").lower()
    return next((a for k, a in SILENT_ARGS if k in s), TYPE_ARGS.get(installer, "/S"))


class Agent:
    def __init__(self, cfg: AgentConfig, system: actions.Sys | None = None, now=time.time):
        self.cfg, self.now = cfg, now
        self.key = load_or_create_key(os.path.join(cfg.state_dir, "agent.pem"))
        self.state = State(os.path.join(cfg.state_dir, "state.json"))
        if not self.state.data["consumer"]:
            raise RuntimeError("agente não pareado: rode 'pair' primeiro")
        self.consumer = cmds.Consumer.from_json(self.state.data["consumer"])
        self.dev = devauth.device_id(devauth.spki_of(self.key))
        self.gw = GatewayClient(self.state.data["gateway"], self.key)
        self.system = system or actions.Sys(os.path.join(cfg.state_dir, "work"))
        self.executed: list[dict] = []   # o que falta contar ao gateway (esvazia a cada relatório)
        self.last_executed: dict = {}    # o último resultado, para a tela e os testes
        self.runs: list[dict] = list(self.state.data.get("runs") or [])
        self.last_report = -1e9
        self.last_error = ""
        self.lock = threading.RLock()
        self.busy = threading.Lock()  # uma instalação ou script por vez
        self.current: dict | None = None   # o que está rodando agora (nome, desde quando): vai no relatório e na tela
        self.async_exec = False            # em produção (run) os comandos do Windows rodam numa fila própria; os testes rodam na hora
        self._q: queue.Queue = queue.Queue()

    # --- execução ---------------------------------------------------------------
    def apply(self, cmd: dict) -> str:
        t, a = cmd["type"], cmd["args"]
        if t in cmds.TRUST_TYPES:
            self.consumer.apply_trust(cmd)
            return "confiança atualizada"
        if t in cmds.WIN_TYPES:
            cmds.check_win_args(t, a, now=self.now(), creating=False)  # o agente confere de novo: não confia no gateway
            with self.busy:
                res = actions.install(self.system, a) if t == cmds.T_WIN_INSTALL else actions.run_script(self.system, a)
            with self.lock:
                run = {"ctr": cmd["ctr"], "type": t, "name": (a.get("name") or "")[:80], "ok": res.ok, "rc": res.rc,
                       "out": res.out, "by": cmd["guardian"], "ts": int(self.now())}
                if t == cmds.T_WIN_INSTALL:
                    # O pedido original (sem a validade), para a tela poder pedir de novo com outros argumentos, e o que a conferência achou.
                    # `needs_help`: falhou, ou o código foi bom mas nada instalou: é o que dispara a análise (gateway).
                    run.update(req={k: v for k, v in a.items() if k != "not_after"}, installed=res.installed, verified=res.verified,
                               needs_help=(not res.ok) or res.verified is False)
                self.runs.append(run)
                self.runs = self.runs[-RUNS_KEEP:]
                self.state.data["runs"] = self.runs
            if not res.ok:
                raise ValueError(res.msg)
            return res.msg
        raise ValueError(f"comando não suportado neste computador: {t}")

    def handle(self, env: dict) -> None:
        try:
            v = self.consumer.accept(env, now=self.now())  # assinatura, papel, janela de horário, destino e contador
        except cmds.CommandError as e:
            self._note({"type": "?", "ok": False, "msg": f"recusado: {e}"})
            return
        with self.lock:
            self.state.data["consumer"] = self.consumer.to_json()
            self.state.save()  # o contador é gasto ANTES de executar: se o agente cair no meio de uma instalação, o comando não roda de novo
        if self.async_exec and v.cmd["type"] in cmds.WIN_TYPES:
            self._q.put(v.cmd)  # instalar ou rodar script demora e pode travar: não pode prender a conversa com o gateway
        else:
            self._execute(v.cmd)

    def _execute(self, cmd: dict) -> None:
        a = cmd.get("args") or {}
        if cmd["type"] in cmds.WIN_TYPES:
            with self.lock:
                self.current = {"type": cmd["type"], "name": str(a.get("name") or "")[:80], "since": int(self.now())}
        try:
            msg = self.apply(cmd)
            self._note({"type": cmd["type"], "ok": True, "msg": msg})
        except (ValueError, cmds.CommandError, OSError) as e:
            self._note({"type": cmd["type"], "ok": False, "msg": str(e)})
        except Exception as e:  # nada inesperado derruba o agente: vira "falhou" (o contador já foi gasto, então não roda de novo)
            traceback.print_exc()
            self._note({"type": cmd["type"], "ok": False, "msg": f"erro inesperado: {type(e).__name__}: {e}"[:300]})
        finally:
            with self.lock:
                self.current = None
                self.state.data["consumer"] = self.consumer.to_json()
                self.state.save()

    def _note(self, entry: dict) -> None:
        with self.lock:
            self.executed.append(entry)
            self.last_executed = entry

    def start_worker(self, stop: threading.Event) -> threading.Thread:
        """A fila de execução: um comando do Windows por vez, fora do laço que fala com o gateway."""
        self.async_exec = True

        def loop():
            while not stop.is_set():
                try:
                    cmd = self._q.get(timeout=1)
                except queue.Empty:
                    continue
                self._execute(cmd)
                try:
                    self.report()  # resultado logo, sem esperar o próximo ciclo
                except GatewayError as e:
                    print("relatório:", e, file=sys.stderr)

        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t

    # --- relatório ---------------------------------------------------------------
    def report(self) -> None:
        ips = tailnet.valid_ips(self.system.tailscale_ips())
        r = {"kind": "device", "platform": "windows", "ts": int(self.now()), "version": VERSION, "tailscale": bool(ips), "tsIps": ips,
             "host": socket.gethostname()[:64], "ctrs": self.consumer.last_ctr,
             "trust": {g: sorted(v.creds) for g, v in self.consumer.trust.guardians.items()},
             "roles": {g: v.role for g, v in self.consumer.trust.guardians.items()},
             "busy": None}
        with self.lock:
            r["runs"] = [{**x, "out": x["out"][-RUN_OUT_REPORT:]} for x in self.runs[-RUNS_KEEP:]]
            sent = list(self.executed[-50:])
            r["executed"], r["busy"] = sent, (dict(self.current) if self.current else None)
            n_sent = len(self.executed)
        self.gw.call("POST", f"/v1/devices/{self.dev}/report", r)
        with self.lock:
            del self.executed[:n_sent]   # só o que foi enviado (o que chegou durante o envio fica para o próximo)
        self.last_report = time.monotonic()

    # --- o que a tela local mostra e pede (sempre pelo gateway, com a chave do agente) ----------
    def ui_state(self) -> dict:
        out = {"dev": self.dev, "host": socket.gethostname(), "version": VERSION, "blocked": [], "requests": [], "admin": [],
               "runs": [{k: v for k, v in r.items() if k != "by"} for r in self.runs[-RUNS_KEEP:]], "gateway_ok": True, "error": self.last_error,
               "busy": dict(self.current) if self.current else None}
        try:
            b = self.gw.call("GET", f"/v1/devices/{self.dev}/blocked?scope=all")   # todos os aparelhos, regras próprias e listas
            out["blocked"] = [{**{k: i[k] for k in ("dev", "domain", "src", "list", "count", "last")}, "name": i.get("name", "")}
                              for i in b.get("items", [])][:UI_BLOCKED_MAX]
            out["devices"] = b.get("devices", [])
            out["me"] = self.dev
            q = self.gw.call("GET", f"/v1/devices/{self.dev}/requests")
            out["requests"], out["admin"] = q.get("requests", []), q.get("admin", [])
            out["analyses"] = q.get("analyses", [])   # análise por IA das instalações que falharam (se o gateway tiver a chave)
        except GatewayError as e:
            out["gateway_ok"], out["error"] = False, str(e)[:200]
        return out

    def ui_inspect(self, path) -> dict:
        """Confere um instalador que a pessoa já baixou (tamanho, SHA-256, assinatura) para ela pedir a instalação. Só leitura, só em C:\\Users."""
        if not isinstance(path, str) or not re.match(r"^[A-Za-z]:\\Users\\[^<>\"|?*]+\.(exe|msi)$", path, re.I) or ".." in path.split("\\"):
            raise ValueError("informe o caminho completo de um .exe ou .msi dentro de C:\\Users")
        if not os.path.isfile(path):
            raise ValueError("arquivo não encontrado")
        info = self.system.file_info(path)
        ext = path.lower().rsplit(".", 1)[-1]
        stem = path.replace("/", "\\").rsplit("\\", 1)[-1].rsplit(".", 1)[0]
        return {**info, "path": path, "kind": ext, "name": stem[:80], "suggested_args": suggest_args(ext, info.get("signer", ""), info.get("installer", ""))}

    def ui_request(self, body: dict) -> dict:
        return self.gw.call("POST", f"/v1/devices/{self.dev}/requests", body)

    # --- laço --------------------------------------------------------------------
    def step(self, wait_s: int = 25) -> int:
        got = self.gw.call("GET", f"/v1/devices/{self.dev}/commands?after={self.state.data['after']}&wait={wait_s}", wait_s=wait_s)
        n = 0
        for c in got.get("commands", []):
            self.handle(c["envelope"])
            self.state.data["after"] = max(self.state.data["after"], c["seq"])
            self.state.save()
            n += 1
        if n or time.monotonic() - self.last_report >= REPORT_EVERY_S:
            self.report()
        return n

    def run(self, stop: threading.Event) -> None:
        delay = 2
        self.start_worker(stop)
        while not stop.is_set():
            try:
                if self.last_report < 0:
                    self.report()  # logo ao subir: é o relatório que declara o computador (o gateway só aceita comandos do Windows depois dele)
                self.step()
                self.last_error = ""
                delay = 2
            except GatewayError as e:
                self.last_error = str(e)[:200]
                print("erro:", e, file=sys.stderr)
                stop.wait(delay)
                delay = min(delay * 2, 60)
