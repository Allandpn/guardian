"""Apps Android: o Pi busca as Releases do GitHub (repositório público ou privado), baixa o APK e calcula o SHA-256.

O aparelho nunca fala com o GitHub e não recebe token nenhum. O APK vai do Pi para o gateway (o executor o envia) e de lá para o aparelho,
mas só depois que o mestre assina `install_app` com este mesmo SHA-256. O aparelho confere o hash e o certificado do app antes de instalar.
"""
import hashlib
import json
import os
import re
import urllib.error
import urllib.request

API = "https://api.github.com"
MAX_APK_BYTES = 150 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class GitHub:
    """Cliente mínimo da API de Releases. O download de asset de repositório privado responde com redirecionamento para um endereço
    assinado: o token NÃO pode seguir junto (o armazenamento recusa), então o redirecionamento é seguido à mão, sem o cabeçalho."""

    def __init__(self, token: str | None = None, timeout: float = 60.0):
        self.token, self.timeout = token, timeout

    def _headers(self, accept: str) -> dict:
        h = {"Accept": accept, "User-Agent": "guardian-deployer", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def releases(self, repo: str) -> list[dict]:
        req = urllib.request.Request(f"{API}/repos/{repo}/releases?per_page=10", headers=self._headers("application/vnd.github+json"))
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read(4_000_000))
        return data if isinstance(data, list) else []

    def download(self, repo: str, asset_id: int, dest: str, max_bytes: int = MAX_APK_BYTES) -> tuple[str, int]:
        """Baixa o asset para `dest` e devolve (sha256, tamanho). Apaga o arquivo parcial se passar do limite ou falhar."""
        url, hdr = f"{API}/repos/{repo}/releases/assets/{asset_id}", self._headers("application/octet-stream")
        opener = urllib.request.build_opener(_NoRedirect)
        for _ in range(4):
            try:
                resp = opener.open(urllib.request.Request(url, headers=hdr), timeout=self.timeout)
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                    url, hdr = e.headers["Location"], {"User-Agent": "guardian-deployer"}   # endereço assinado: sem token
                    continue
                raise
            break
        else:
            raise RuntimeError("redirecionamentos demais")
        h, n = hashlib.sha256(), 0
        tmp = dest + ".part"
        try:
            with resp, open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > max_bytes:
                        raise RuntimeError("APK maior que o limite")
                    h.update(chunk)
                    f.write(chunk)
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        return h.hexdigest(), n


def pick_asset(release: dict, pattern: str) -> dict | None:
    rx = re.compile(pattern)
    for a in release.get("assets") or []:
        if isinstance(a, dict) and rx.search(str(a.get("name", ""))) and isinstance(a.get("id"), int):
            return a
    return None


def release_ts(release: dict) -> int:
    import datetime
    s = release.get("published_at") or release.get("created_at") or ""
    try:
        return int(datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0
