"""Cliente mínimo da API REST do Pi-hole v6. Os caminhos dos domínios estão só aqui (confira em /api/docs do seu Pi-hole)."""
import json
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request


class PiholeError(Exception):
    pass


class Pihole:
    def __init__(self, base_url: str, password: str, ca_file: str | None = None, timeout: float = 10.0):
        self.base = base_url.rstrip("/")
        self.password = password
        self.timeout = timeout
        self.sid: str | None = None
        self.lock = threading.Lock()
        self.ctx = ssl.create_default_context(cafile=ca_file) if self.base.startswith("https") else None

    # --- baixo nível ----------------------------------------------------------
    def _open(self, method: str, path: str, body: dict | None = None, auth: bool = True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if auth and self.sid:
            req.add_header("X-FTL-SID", self.sid)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read(2_000_000)
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read(65536)
            try:
                return e.code, json.loads(raw) if raw else {}
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise PiholeError(f"Pi-hole inalcançável: {e}") from e

    def login(self) -> None:
        st, body = self._open("POST", "/api/auth", {"password": self.password}, auth=False)
        sid = (body.get("session") or {}).get("sid") if isinstance(body, dict) else None
        if st != 200 or not sid:
            raise PiholeError(f"login recusado ({st})")
        self.sid = sid

    def logout(self) -> None:
        if self.sid:
            try:
                self._open("DELETE", "/api/auth")
            except PiholeError:
                pass
            self.sid = None

    def _call(self, method: str, path: str, body: dict | None = None):
        with self.lock:
            if not self.sid:
                self.login()
            st, resp = self._open(method, path, body)
            if st == 401:  # sessão expirou por inatividade
                self.sid = None
                self.login()
                st, resp = self._open(method, path, body)
            return st, resp

    # --- domínios -----------------------------------------------------------------
    @staticmethod
    def _p(list_: str, kind: str = "exact") -> str:
        if list_ not in ("allow", "deny") or kind != "exact":
            raise PiholeError("lista inválida")
        return f"/api/domains/{list_}/{kind}"

    def list_domains(self, list_: str) -> list[str]:
        st, body = self._call("GET", self._p(list_))
        if st != 200:
            raise PiholeError(f"listar falhou ({st})")
        items = body.get("domains", []) if isinstance(body, dict) else body
        return sorted(str(i.get("domain")) for i in items if isinstance(i, dict) and i.get("domain"))

    def list_entries(self, list_: str) -> list[dict]:
        """Como list_domains, mas com o comentário (quem criou a entrada)."""
        st, body = self._call("GET", self._p(list_))
        if st != 200:
            raise PiholeError(f"listar falhou ({st})")
        items = body.get("domains", []) if isinstance(body, dict) else body
        return [{"domain": str(i["domain"]), "comment": str(i.get("comment") or "")}
                for i in items if isinstance(i, dict) and i.get("domain")]

    def queries(self, since: float, client_ip: str, length: int = 1000, max_pages: int = 5) -> list[dict]:
        """Consultas de um cliente desde `since` (timestamp Unix). Filtra o status no chamador."""
        out: list[dict] = []
        for page in range(max_pages):
            qs = urllib.parse.urlencode({"from": f"{since:.6f}", "client_ip": client_ip, "length": length, "start": page * length})
            st, body = self._call("GET", "/api/queries?" + qs)
            if st != 200:
                raise PiholeError(f"consultas falharam ({st})")
            items = body.get("queries", []) if isinstance(body, dict) else []
            out.extend(i for i in items if isinstance(i, dict))
            if len(items) < length:
                break
        return out

    def list_names(self) -> dict[int, str]:
        """{id da lista de anúncios: endereço}. Melhor esforço: vazio se a rota não existir."""
        st, body = self._call("GET", "/api/lists")
        if st != 200 or not isinstance(body, dict):
            return {}
        return {int(i["id"]): str(i.get("address", ""))[:120] for i in body.get("lists", [])
                if isinstance(i, dict) and isinstance(i.get("id"), int)}

    def put_domain(self, list_: str, domain: str, comment: str = "") -> None:
        st, body = self._call("PUT", f"{self._p(list_)}/{urllib.parse.quote(domain, safe='')}",
                              {"comment": comment[:200], "groups": [0], "enabled": True})
        if st not in (200, 201):
            raise PiholeError(f"gravar falhou ({st})")

    def delete_domain(self, list_: str, domain: str) -> None:
        st, _ = self._call("DELETE", f"{self._p(list_)}/{urllib.parse.quote(domain, safe='')}")
        if st not in (200, 204, 404):  # 404: já não existia
            raise PiholeError(f"remover falhou ({st})")
