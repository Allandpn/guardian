"""Tela local do agente: um servidor só em 127.0.0.1 para quem usa o computador ver o que foi bloqueado e fazer pedidos.

O que a pessoa pede vai ao gateway assinado com a chave do agente (que ela não alcança). Nada aqui executa nada: quem aprova é o guardião.
Contra uma página de outro site falando com este servidor: confere o `Host` (DNS rebinding) e, nos POST, a origem e um cabeçalho próprio.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..executor.runner import GatewayError

HERE = os.path.dirname(os.path.abspath(__file__))
GATEWAY_STATIC = os.path.join(os.path.dirname(HERE), "gateway", "static")
FILES = {  # caminho -> (arquivo, tipo)
    "/": (os.path.join(HERE, "static", "index.html"), "text/html; charset=utf-8"),
    "/agent.js": (os.path.join(HERE, "static", "agent.js"), "text/javascript; charset=utf-8"),
    "/ui.js": (os.path.join(GATEWAY_STATIC, "ui.js"), "text/javascript; charset=utf-8"),
    "/style.css": (os.path.join(GATEWAY_STATIC, "style.css"), "text/css; charset=utf-8"),
    "/icon.svg": (os.path.join(GATEWAY_STATIC, "icon.svg"), "image/svg+xml"),
}
REQUEST_KINDS = ("unblock", "install", "command")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_BODY = 12 * 1024


class UiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, agent, port: int = 47657):
        self.agent = agent
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        super().__init__(("127.0.0.1", port), Handler)
        self.port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = 10
    server_version = "guardian-agent"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json; charset=utf-8")

    def _guard(self) -> bool:
        srv = self.server
        if self.headers.get("Host", "") not in srv.allowed_hosts:
            self._json(403, {"error": "host não permitido"})
            return False
        if self.command == "POST":
            if self.headers.get("Origin", "") not in srv.allowed_origins or self.headers.get("X-Guardian-Agent") != "1":
                self._json(403, {"error": "origem não permitida"})
                return False
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._json(415, {"error": "use JSON"})
                return False
        return True

    def do_GET(self):
        if not self._guard():
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/state":
            return self._json(200, self.server.agent.ui_state())
        if path in FILES:
            f, ctype = FILES[path]
            try:
                with open(f, "rb") as fh:
                    return self._send(200, fh.read(), ctype)
            except OSError:
                return self._json(404, {"error": "arquivo ausente"})
        self._json(404, {"error": "não encontrado"})

    def do_POST(self):
        if not self._guard():
            return
        if self.path not in ("/api/request", "/api/inspect"):
            return self._json(404, {"error": "não encontrado"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json(400, {"error": "Content-Length inválido"})
        if not 0 < n <= MAX_BODY:
            return self._json(413, {"error": "corpo inválido ou grande demais"})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self._json(400, {"error": "JSON inválido"})
        if self.path == "/api/inspect":
            try:
                return self._json(200, self.server.agent.ui_inspect(body.get("path") if isinstance(body, dict) else None))
            except (ValueError, OSError) as e:
                return self._json(400, {"error": str(e)[:200]})
        if not isinstance(body, dict) or body.get("kind") not in REQUEST_KINDS:
            return self._json(400, {"error": "tipo de pedido inválido"})
        allowed = {"kind", "domains"} if body["kind"] == "unblock" else {"kind", "payload"}
        try:
            self._json(200, self.server.agent.ui_request({k: v for k, v in body.items() if k in allowed}))
        except GatewayError as e:
            self._json(e.status if 400 <= e.status < 500 else 502, {"error": _reason(e)})


def _reason(e: GatewayError) -> str:
    """A mensagem do gateway sem o envelope técnico."""
    msg = str(e)
    i = msg.find("{")
    if i >= 0:
        try:
            return str(json.loads(msg[i:]).get("error") or msg)
        except ValueError:
            pass
    return msg[:200]
