"""O que o agente faz no Windows depois de conferir a assinatura: instalar um programa ou rodar um script, como administrador.

Tudo que toca o sistema passa por `Sys`, para testar sem Windows. Os argumentos já foram validados por `commands.check_win_args`.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field

OUT_MAX = 4000
DOWNLOAD_MAX = 2 * 1024 ** 3
INSTALL_TIMEOUT_S = 600   # padrão; o pedido pode trazer timeout_s (60 a 3600)
DOWNLOAD_TIMEOUT_S = 600
_NOWIN = 0x08000000  # CREATE_NO_WINDOW


@dataclass
class Result:
    ok: bool
    rc: int | None
    out: str
    msg: str
    installed: list = field(default_factory=list)   # programas que apareceram (ou mudaram de versão) depois da instalação
    verified: bool | None = None                    # True: achei programa novo; False: código ok mas nada mudou, ou falhou; None: não deu para conferir


def clip(text: str, limit: int = OUT_MAX) -> str:
    """Saída longa: o começo e o fim (o erro costuma estar no fim)."""
    text = text.strip()
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + "\n[...]\n" + text[-half:]


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError("redirecionamento para fora de https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Sys:
    """A parte do sistema operacional. Os testes trocam por um falso."""

    def __init__(self, workroot: str):
        self.workroot = workroot

    def workdir(self) -> str:
        d = os.path.join(self.workroot, uuid.uuid4().hex)
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d

    def cleanup(self, d: str) -> None:
        shutil.rmtree(d, ignore_errors=True)

    def run(self, cmd, timeout: int, env: dict | None = None) -> tuple[int, str]:
        """Roda e devolve (código, saída). Estourou o tempo: mata a árvore de processos e devolve código -1."""
        kw = {"creationflags": _NOWIN} if sys.platform == "win32" else {}
        if env:
            kw["env"] = {**os.environ, **env}
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kw)
        try:
            out, _ = p.communicate(timeout=timeout)
            return p.returncode, out.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
            else:
                p.kill()
            out, _ = p.communicate()
            return -1, out.decode("utf-8", "replace") + "\n[tempo limite estourado]"

    def download(self, url: str, dest: str, max_bytes: int = DOWNLOAD_MAX) -> str:
        """Baixa por https e devolve o SHA-256 do que veio."""
        opener = urllib.request.build_opener(_HttpsOnly)
        h = hashlib.sha256()
        total = 0
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "guardian-agent"}), timeout=DOWNLOAD_TIMEOUT_S) as r, open(dest, "wb") as f:
            while True:
                chunk = r.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("instalador grande demais")
                h.update(chunk)
                f.write(chunk)
        return h.hexdigest()

    def copy_hashed(self, src: str, dst: str, max_bytes: int = DOWNLOAD_MAX) -> str:
        """Copia um arquivo para a pasta protegida lendo UMA vez e devolve o SHA-256 do que foi copiado. O que se confere e se executa é a cópia:
        a pessoa não consegue trocar o original depois (TOCTOU)."""
        h = hashlib.sha256()
        total = 0
        with open(src, "rb") as r, open(dst, "wb") as f:
            while True:
                chunk = r.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("instalador grande demais")
                h.update(chunk)
                f.write(chunk)
        return h.hexdigest()

    def signature(self, path: str) -> tuple[str, str]:
        """(estado, nome do assinante) da assinatura digital do arquivo. Estado "Valid" é o único bom. O caminho vai por variável de ambiente (sem aspas)."""
        script = ("$s = Get-AuthenticodeSignature -LiteralPath $env:GA_PATH; $n = ''; "
                  "if ($s.SignerCertificate) { $n = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }; Write-Output ($s.Status.ToString() + '|' + $n)")
        rc, out = self.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], 90, env={"GA_PATH": path})
        lines = out.strip().splitlines()
        status, _, signer = (lines[-1] if lines else "").partition("|")
        return status.strip() or "Desconhecido", signer.strip()

    def file_info(self, path: str) -> dict:
        """Tamanho, SHA-256 e assinatura de um arquivo, só para mostrar a quem vai pedir a instalação."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        status, signer = self.signature(path)
        return {"size": os.path.getsize(path), "sha256": h.hexdigest(), "status": status, "signer": signer}

    def installed_programs(self) -> dict[str, str]:
        """Programas instalados para todos os usuários (registro de desinstalação do Windows): {nome: versão}. Vazio fora do Windows."""
        if sys.platform != "win32":
            return {}
        import winreg
        out: dict[str, str] = {}
        for sub in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
            try:
                root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub)
            except OSError:
                continue
            with root:
                for i in range(winreg.QueryInfoKey(root)[0]):
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, i)) as k:
                            name = str(winreg.QueryValueEx(k, "DisplayName")[0]).strip()
                            try:
                                ver = str(winreg.QueryValueEx(k, "DisplayVersion")[0]).strip()
                            except OSError:
                                ver = ""
                    except OSError:
                        continue
                    if name:
                        out[name] = ver
        return out

    def winget(self) -> str:
        """O winget como SYSTEM não está no PATH: ele fica na pasta do App Installer."""
        import glob
        found = sorted(glob.glob(r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe"))
        return found[-1] if found else "winget"

    def tailscale_ips(self) -> list[str]:
        exe = r"C:\Program Files\Tailscale\tailscale.exe"
        ips: list[str] = []
        for flag in ("-4", "-6"):
            try:
                rc, out = self.run([exe, "ip", flag], 10)
            except OSError:
                return ips
            if rc == 0:
                ips += out.split()
        return ips


_NET_FAIL = re.compile(r"0x80072(ee7|ee2|efd|efe|f78)|InternetOpenUrl\(\) failed|name (could not be )?resolved", re.I)
_DOWNLOAD = re.compile(r"Downloading\s+https?://([^/\s]+)", re.I)


def download_blocked_host(out: str) -> str | None:
    """O winget falhou na rede: o domínio de onde ele tentava baixar (quase sempre é o Pi-hole bloqueando). None se for outro erro."""
    if not _NET_FAIL.search(out):
        return None
    m = _DOWNLOAD.search(out)
    return m.group(1).lower() if m else None


# Códigos de saída conhecidos de instaladores que recusam a linha de comando (e o que fazer).
KNOWN_EXIT_HINTS = {
    666660: " O instalador recusou os parâmetros. Para o DBeaver use /S /allusers (o /S sozinho não basta); outros instaladores NSIS usam só /S.",
}


def _timed_out(rc, out: str) -> str:
    """Instalador que estoura o tempo quase sempre espera uma janela que o SYSTEM não mostra (sem modo silencioso)."""
    if rc == -1 and "tempo limite" in out:
        return " Não terminou no tempo: provavelmente espera uma janela (esse instalador não tem modo silencioso). Peça à pessoa de confiança para instalar com a conta de administrador."
    return KNOWN_EXIT_HINTS.get(rc, "")


def _snapshot(system: Sys) -> dict[str, str]:
    try:
        return dict(system.installed_programs())
    except Exception:  # conferir é um extra: nunca derruba a instalação
        return {}


def install(system: Sys, a: dict) -> Result:
    """Instala e CONFERE o resultado: o código de saída 0 não prova que instalou (o Wireshark deu 0 sem o Npcap, com a saída vazia).
    Compara os programas instalados antes e depois: programa novo ou versão nova = verificado."""
    before = _snapshot(system)
    res = _install(system, a)
    after = _snapshot(system)
    if not before and not after:
        return res   # sem como conferir (fora do Windows)
    new = sorted((f"{n} {v}".strip() for n, v in after.items() if n not in before))
    changed = sorted((f"{n} {before[n] or '?'} -> {v or '?'}" for n, v in after.items() if n in before and before[n] != v))
    res.installed = [x[:100] for x in (new + changed)[:10]]
    res.verified = bool(res.installed) if res.ok else False
    if res.ok and not res.verified:
        res.msg += " Conferi o que está instalado antes e depois e não achei programa novo nem versão nova: ele já existia, ou a instalação não fez efeito."
    elif res.ok:
        res.msg += f" Conferido: {', '.join(res.installed[:3])}."
    return res


def _install(system: Sys, a: dict) -> Result:
    limit = a.get("timeout_s", INSTALL_TIMEOUT_S)
    if a["source"] == "winget":
        argv = [system.winget(), "install", "--id", a["id"], "--exact", "--silent", "--source", "winget",
                "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"]
        if a.get("version"):
            argv += ["--version", a["version"]]
        rc, out = system.run(argv, limit)
        msg = f"winget {a['id']}: código {rc}" + _timed_out(rc, out)
        if rc != 0:
            host = download_blocked_host(out)
            if host:
                msg += f". Não conseguiu baixar de {host}: o domínio deve estar bloqueado. Peça a liberação de {host.removeprefix('www.')} e peça a instalação de novo"
        return Result(rc == 0, rc, clip(out), msg)
    d = system.workdir()
    try:
        path = os.path.join(d, "setup." + a["kind"])
        local = a["source"] == "file"
        try:
            got = system.copy_hashed(a["path"], path) if local else system.download(a["url"], path)
        except (OSError, ValueError, urllib.error.URLError) as e:
            return Result(False, None, "", f"{'leitura do arquivo' if local else 'download'} falhou: {e}"[:300])
        if got != a["sha256"]:
            what = "do arquivo" if local else "do arquivo baixado"
            return Result(False, None, "", f"o SHA-256 {what} ({got[:12]}…) não é o aprovado ({a['sha256'][:12]}…): nada foi executado")
        if a.get("publisher"):  # exigido pelo guardião: assinatura digital válida desse nome, conferida na cópia protegida
            status, signer = system.signature(path)
            if status != "Valid" or signer.lower() != a["publisher"].lower():
                return Result(False, None, "", f"assinatura digital recusada (estado {status}, assinante '{signer}'; o aprovado era '{a['publisher']}'): nada foi executado")
        extra = f" {a['args']}" if a.get("args") else ""
        cmd = f'msiexec /i "{path}" /qn /norestart{extra}' if a["kind"] == "msi" else f'"{path}"{extra}'
        rc, out = system.run(cmd, limit)
        ok = rc in (0, 3010)  # 3010: instalou, precisa reiniciar
        return Result(ok, rc, clip(out), f"instalador {a['name']}: código {rc}" + (" (reiniciar)" if rc == 3010 else "") + _timed_out(rc, out))
    finally:
        system.cleanup(d)


def run_script(system: Sys, a: dict) -> Result:
    d = system.workdir()
    try:
        path = os.path.join(d, "script.ps1")
        with open(path, "w", encoding="utf-8-sig") as f:  # BOM: o PowerShell 5.1 só lê UTF-8 assim
            f.write(a["script"])
        argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path]
        rc, out = system.run(argv, a.get("timeout_s", 600))
        return Result(rc == 0, rc, clip(out), f"script: código {rc}")
    finally:
        system.cleanup(d)
