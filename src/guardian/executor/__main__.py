"""python -m guardian.executor pair --pairing STRING | run

Configuração por variáveis de ambiente:
  EXECUTOR_STATE        diretório de estado (padrão /var/lib/guardian-executor)
  PIHOLE_URL            padrão http://127.0.0.1:8080
  PIHOLE_PASSWORD_FILE  arquivo com a senha de aplicativo do Pi-hole (modo 0600)
  PIHOLE_CA             CA para HTTPS do Pi-hole (opcional)
  CANARY                domínio-canário que nunca pode ser alterado
  CLIENTS               aparelhos protegidos: "IP=id,IP=id" (IP do aparelho na Tailscale, v4 e v6, e o id do aparelho no site)
"""
import argparse
import os
import signal
import sys
import threading

from .runner import ExecConfig, Executor, pair


def cfg_from_env() -> ExecConfig:
    e = os.environ
    pw = ""
    if e.get("PIHOLE_PASSWORD_FILE"):
        with open(e["PIHOLE_PASSWORD_FILE"]) as f:
            pw = f.read().strip()
    clients = {}
    for part in e.get("CLIENTS", "").split(","):
        if "=" in part:
            ip, dev = part.strip().split("=", 1)
            clients[ip.strip()] = dev.strip()
    return ExecConfig(e.get("EXECUTOR_STATE", "/var/lib/guardian-executor"), e.get("PIHOLE_URL", "http://127.0.0.1:8080"),
                      pw, e.get("CANARY", ""), e.get("PIHOLE_CA"), clients)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="guardian.executor")
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("pair")
    pr.add_argument("--pairing", required=True)
    pr.add_argument("--name", default="Pi-hole")
    sub.add_parser("run")
    a = p.parse_args(argv)
    cfg = cfg_from_env()
    if a.cmd == "pair":
        print("Fingerprint do executor (confira por voz com o guardião):", pair(cfg, a.pairing, a.name))
        return 0
    if not cfg.canary:
        print("AVISO: CANARY não definido; o domínio-canário não fica protegido.", file=sys.stderr)
    ex = Executor(cfg)
    stop = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    ex.run(stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())
