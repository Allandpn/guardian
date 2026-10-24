"""Pi-hole v6 de mentira (só o que o executor usa), para testar sem Pi-hole de verdade."""
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlsplit


class FakePihole:
    def __init__(self, password="senha-app"):
        self.password = password
        self.lists = {"allow": {}, "deny": {}}
        self.regex = {"allow": {}, "deny": {}}   # regras regex (a chave é a própria expressão)
        self.sid = "sid-" + "x" * 20
        self.sessions_valid = True
        self.down = False
        self.logins = 0
        self.added = {}     # (lista, tipo, domínio) -> date_added
        self.queries = []   # [{"time","domain","status","client":{"ip"},"cname"?,"list_id"?}]
        self.lists_api = {"lists": [{"id": 7, "address": "https://listas.example/ads.txt"}]}
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status, body=None):
                data = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _auth(self):
                return fake.sessions_valid and self.headers.get("X-FTL-SID") == fake.sid

            def _body(self):
                n = int(self.headers.get("Content-Length", "0"))
                return json.loads(self.rfile.read(n) or b"{}")

            def handle_any(self):
                if fake.down:
                    return self._reply(503, {})
                p = self.path
                if p == "/api/auth" and self.command == "POST":
                    if self._body().get("password") != fake.password:
                        return self._reply(401, {"error": {"key": "unauthorized"}})
                    fake.logins += 1
                    fake.sessions_valid = True
                    return self._reply(200, {"session": {"valid": True, "sid": fake.sid, "validity": 300}})
                if p == "/api/auth" and self.command == "DELETE":
                    fake.sessions_valid = False
                    return self._reply(204)
                if not self._auth():
                    return self._reply(401, {})
                u = urlsplit(p)
                if u.path == "/api/queries" and self.command == "GET":
                    q = {k: v[0] for k, v in parse_qs(u.query).items()}
                    rows = [x for x in fake.queries if x["client"]["ip"] == q.get("client_ip", x["client"]["ip"])
                            and x["time"] >= float(q.get("from", 0))]
                    rows.sort(key=lambda x: x["time"])
                    start, n = int(q.get("start", 0)), int(q.get("length", 100))
                    return self._reply(200, {"queries": rows[start:start + n], "recordsTotal": len(rows)})
                if u.path == "/api/lists" and self.command == "GET":
                    return self._reply(200, fake.lists_api)
                parts = p.split("/")  # ['', 'api', 'domains', type, kind, (domain)]
                if len(parts) >= 5 and parts[2] == "domains" and parts[3] in fake.lists and parts[4] in ("exact", "regex"):
                    lst = fake.lists[parts[3]] if parts[4] == "exact" else fake.regex[parts[3]]
                    if len(parts) == 5 and self.command == "GET":
                        return self._reply(200, {"domains": [{"domain": d, "comment": c, "enabled": True, "date_added": fake.added.get((parts[3], parts[4], d), 1700000000)}
                                                             for d, c in lst.items()]})
                    if len(parts) == 6:
                        dom = unquote(parts[5])
                        if self.command == "PUT":
                            lst[dom] = self._body().get("comment", "")
                            fake.added[(parts[3], parts[4], dom)] = int(time.time())
                            return self._reply(201, {})
                        if self.command == "DELETE":
                            return self._reply(204 if lst.pop(dom, None) is not None else 404, {})
                return self._reply(404, {})

            do_GET = do_PUT = do_POST = do_DELETE = handle_any

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
