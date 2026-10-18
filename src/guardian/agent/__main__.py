"""python -m guardian.agent pair --pairing STRING | run | tray

Variáveis de ambiente:
  AGENT_STATE    pasta de estado (padrão %ProgramData%\\GuardianAgent; só SYSTEM e administradores devem abrir)
  AGENT_UI_PORT  porta da tela local em 127.0.0.1 (padrão 47657)
"""
import argparse
import os
import signal
import sys
import threading
import webbrowser

from .agent import Agent, AgentConfig, default_state_dir, pair
from .ui import UiServer


def cfg_from_env() -> AgentConfig:
    e = os.environ
    return AgentConfig(e.get("AGENT_STATE") or default_state_dir(), int(e.get("AGENT_UI_PORT", "47657")))


def tray(port: int) -> int:
    """Ícone na bandeja (roda na sessão de quem usa o computador; precisa de pystray e pillow)."""
    try:
        import json
        import urllib.request
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        print("faltam pystray e pillow para o ícone da bandeja; abra http://localhost:%d no navegador" % port, file=sys.stderr)
        return 2
    url = f"http://localhost:{port}/"

    def icon_image(ok: bool):
        im = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        color = (226, 182, 89, 255) if ok else (238, 138, 112, 255)
        d.polygon([(32, 4), (58, 14), (58, 36), (32, 60), (6, 36), (6, 14)], outline=color, fill=(26, 46, 58, 255), width=4)
        d.polygon([(18, 40), (16, 22), (26, 30), (32, 18), (38, 30), (48, 22), (46, 40)], fill=color)
        return im

    ic = pystray.Icon("guardian", icon_image(True), "Guardian", menu=pystray.Menu(
        pystray.MenuItem("Abrir o Guardian", lambda: webbrowser.open(url), default=True),
        pystray.MenuItem("Sair", lambda icon: icon.stop())))

    def poll():
        stop = threading.Event()
        while not stop.wait(15):
            try:
                req = urllib.request.Request(url + "api/state", headers={"Host": f"localhost:{port}"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    s = json.loads(r.read())
                ok = bool(s.get("gateway_ok"))
                pending = sum(1 for a in s.get("admin", []) if a.get("status") == "open")
            except (OSError, ValueError):
                ok, pending = False, 0
            ic.icon = icon_image(ok)
            ic.title = "Guardian: " + ("conectado" if ok else "sem conexão") + (f" · {pending} pedido(s) aguardando" if pending else "")

    threading.Thread(target=poll, daemon=True).start()
    ic.run()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="guardian.agent")
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("pair")
    pr.add_argument("--pairing", required=True)
    pr.add_argument("--name", default=None)
    sub.add_parser("run")
    sub.add_parser("tray")
    a = p.parse_args(argv)
    cfg = cfg_from_env()
    if a.cmd == "pair":
        print("Fingerprint do agente (confira por voz com o guardião):", pair(cfg, a.pairing, a.name))
        return 0
    if a.cmd == "tray":
        return tray(cfg.ui_port)
    agent = Agent(cfg)
    ui = UiServer(agent, cfg.ui_port)
    ui.start()
    print(f"Guardian Agent {agent.dev} · tela local em http://localhost:{ui.port}/", file=sys.stderr)
    stop = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    agent.run(stop)
    ui.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
