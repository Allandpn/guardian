"""Deployer: coloca no Pi uma versão que o guardião-mestre aprovou (comando assinado `deploy`).

Roda como root, fora do repositório que os desenvolvedores editam: este arquivo e o registro de projetos são instalados à mão
(veja docs/DEPLOY.md) e uma versão nova NÃO os atualiza. O deployer não confia no executor nem no pipeline: ele mesmo
  1. busca as etiquetas `<prefixo>*` do repositório num espelho (git bare);
  2. só instala um commit que seja a ponta de uma dessas etiquetas;
  3. calcula quais arquivos de segurança a versão toca (lista do registro) e só instala se o mestre confirmou o aviso;
  4. troca o código, roda os passos do projeto e confere a saúde; se falhar, volta sozinho para a versão anterior.
Voltar para uma versão que já estava no ar não afrouxa nada, então não pede assinatura.
"""
import fnmatch
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time

from . import policy

_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
KEEP_OFFERS = 5
KEEP_HISTORY = 20
HEALTH_TIMEOUT_S = 90


def check_request(req: dict) -> None:
    """O mesmo formato que o gateway e o executor conferem (protocol/commands.py::check_deploy_args), repetido aqui de propósito:
    o deployer é instalado fora do repositório e não importa nada dele."""
    if not isinstance(req, dict) or not isinstance(req.get("project"), str) or not _PROJECT.match(req["project"]):
        raise ValueError("projeto inválido")
    if not isinstance(req.get("commit"), str) or not _COMMIT.match(req["commit"]):
        raise ValueError("commit inválido")


def _atomic_write(path: str, data: dict) -> None:
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _run(argv, cwd=None, env=None, timeout=600):
    p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


class Deployer:
    def __init__(self, registry: dict, state_dir: str, run=_run, now=time.time, sleep=time.sleep, inbox_uid: int | None = None):
        self.reg, self.state_dir, self.run, self.now, self.sleep = registry, state_dir, run, now, sleep
        self.inbox_uid = inbox_uid
        for d in ("mirrors", "inbox", "done"):
            os.makedirs(os.path.join(state_dir, d), exist_ok=True)
        self.status = self._load("status.json", {"history": []})

    # --- apoio -----------------------------------------------------------------
    def _path(self, *p) -> str:
        return os.path.join(self.state_dir, *p)

    def _load(self, name: str, default):
        try:
            with open(self._path(name)) as f:
                return json.load(f)
        except (OSError, ValueError):
            return default

    def _env(self, proj: dict):
        env = dict(os.environ)
        if proj.get("ssh_key"):
            env["GIT_SSH_COMMAND"] = f"ssh -i {proj['ssh_key']} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory", GIT_CONFIG_VALUE_0="*")  # o diretório pode ser de outro usuário
        return env

    def _git(self, name: str, *args, cwd=None) -> tuple[int, str]:
        proj = self.reg[name]
        return self.run(["git", *args], cwd=cwd, env=self._env(proj), timeout=300)

    def _mirror(self, name: str) -> str:
        return self._path("mirrors", name + ".git")

    def _ensure_mirror(self, name: str) -> str:
        m = self._mirror(name)
        if not os.path.isdir(m):
            self._git(name, "init", "--bare", m)
            self._git(name, "--git-dir", m, "remote", "add", "origin", self.reg[name]["repo"])
        return m

    def _fetch_tags(self, name: str) -> str:
        m, pre = self._ensure_mirror(name), self.reg[name].get("tag_prefix", "release/")
        rc, out = self._git(name, "--git-dir", m, "fetch", "--force", "origin", f"+refs/tags/{pre}*:refs/tags/{pre}*")
        if rc != 0:
            raise RuntimeError(f"não consegui buscar o repositório de {name}: {out[-200:]}")
        return m

    def _deployed(self, name: str) -> str | None:
        rc, out = self._git(name, "-C", self.reg[name]["workdir"], "rev-parse", "HEAD")
        return out.strip() if rc == 0 and re.fullmatch(r"[0-9a-f]{40}", out.strip()) else None

    def _tagged_commits(self, name: str, m: str) -> dict[str, str]:
        """{commit: etiqueta} das etiquetas de versão (a ponta de cada uma)."""
        pre = self.reg[name].get("tag_prefix", "release/")
        rc, out = self._git(name, "--git-dir", m, "for-each-ref", "--sort=-creatordate", "--format=%(refname:short)", f"refs/tags/{pre}")
        res: dict[str, str] = {}
        for tag in out.split() if rc == 0 else []:
            rc2, c = self._git(name, "--git-dir", m, "rev-list", "-n1", tag)
            if rc2 == 0 and re.fullmatch(r"[0-9a-f]{40}", c.strip()):
                res.setdefault(c.strip(), tag)
        return res

    def _have(self, name: str, m: str, commit: str) -> bool:
        return self._git(name, "--git-dir", m, "cat-file", "-e", commit + "^{commit}")[0] == 0

    def _older(self, name: str, m: str, commit: str, cur: str | None) -> bool:
        """A versão já faz parte do que está no ar (é antepassada da atual)? Voltar a ela seria um downgrade, que o mestre não aprova por aqui."""
        if not cur or commit == cur:
            return False
        if not self._have(name, m, cur):
            self._git(name, "--git-dir", m, "fetch", self.reg[name]["workdir"], cur)
        return self._git(name, "--git-dir", m, "merge-base", "--is-ancestor", commit, cur)[0] == 0

    def changed_files(self, name: str, m: str, base: str | None, commit: str) -> list[str] | None:
        """Arquivos que a versão muda em relação ao que está no ar. None se não deu para comparar (tratado como sensível)."""
        if not base:
            return None
        if not self._have(name, m, base):  # o que está no ar pode não ter etiqueta: traz do próprio diretório de trabalho
            self._git(name, "--git-dir", m, "fetch", self.reg[name]["workdir"], base)
        if not self._have(name, m, base):
            return None
        rc, out = self._git(name, "--git-dir", m, "diff", "--name-only", base, commit)
        return out.splitlines() if rc == 0 else None

    def sensitive_of(self, name: str, files: list[str] | None) -> list[str]:
        pats = self.reg[name].get("sensitive", [])
        if files is None:
            return ["(não deu para comparar com a versão atual)"]
        return [f for f in files if any(fnmatch.fnmatch(f, p) for p in pats)]

    def compose_violations(self, name: str, m: str, commit: str) -> list[str]:
        """Projetos em contêiner: confere o docker-compose da versão contra a política de isolamento ANTES de qualquer instalação."""
        proj = self.reg[name]
        if proj.get("type") != "compose":
            return []
        tmp = tempfile.mkdtemp(prefix="guardian-policy-")
        try:
            tar = os.path.join(tmp, "src.tar")
            rc, out = self._git(name, "--git-dir", m, "archive", "--format=tar", "-o", tar, commit)
            if rc != 0:
                return [f"não consegui ler a versão: {out[-100:]}"]
            pdir = os.path.join(tmp, "p")
            os.makedirs(pdir)
            with tarfile.open(tar) as t:
                for mem in t.getmembers():  # só arquivos e pastas dentro do projeto (sem links nem caminhos absolutos)
                    n = os.path.normpath(mem.name)
                    if not (mem.isfile() or mem.isdir()) or n.startswith(("/", "..")):
                        continue
                    t.extract(mem, pdir)
            env = os.path.join(proj["workdir"], ".env")
            if os.path.isfile(env):
                shutil.copy(env, os.path.join(pdir, ".env"))
            cfile = os.path.join(pdir, proj.get("compose_file", "docker-compose.yml"))
            rc, out = self.run(["docker", "compose", "--project-directory", pdir, "-f", cfile, "config", "--format", "json", "--no-env-resolution"],
                               cwd=pdir, env=self._env(proj), timeout=120)
            if rc != 0:
                return [f"não consegui validar o compose: {out[-120:]}"]
            try:
                cfg = json.loads(out)
            except ValueError:
                return ["saída do compose ilegível"]
            return policy.violations(cfg, pdir, proj.get("allowed_binds"), proj.get("allowed_contexts"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # --- ofertas: o que o mestre pode aprovar -----------------------------------------------
    def refresh_offers(self) -> list[dict]:
        offers: list[dict] = []
        for name in self.reg:
            try:
                m = self._fetch_tags(name)
            except RuntimeError as e:
                offers.append({"project": name, "error": str(e)[:200]})
                continue
            cur = self._deployed(name)
            for commit, tag in list(self._tagged_commits(name, m).items())[:KEEP_OFFERS + 1]:
                if commit == cur or self._older(name, m, commit, cur):
                    continue
                files = self.changed_files(name, m, cur, commit)
                sens = self.sensitive_of(name, files)
                viol = self.compose_violations(name, m, commit)
                _, subj = self._git(name, "--git-dir", m, "log", "-1", "--format=%s", commit)
                _, who = self._git(name, "--git-dir", m, "log", "-1", "--format=%an", commit)
                _, ts = self._git(name, "--git-dir", m, "log", "-1", "--format=%ct", commit)
                offers.append({"project": name, "tag": tag, "commit": commit, "subject": subj[:80], "author": who[:40],
                               "ts": int(ts) if ts.isdigit() else 0, "files": len(files) if files is not None else None,
                               "sensitive": sens[:8], "sensitive_n": len(sens), "policy": viol[:6], "policy_n": len(viol)})
                if sum(1 for o in offers if o["project"] == name and "commit" in o) >= KEEP_OFFERS:
                    break
        _atomic_write(self._path("offers.json"), {"ts": int(self.now()), "offers": offers,
                                                  "current": {n: self._deployed(n) for n in self.reg}})
        return offers

    # --- instalar ---------------------------------------------------------------------
    def _steps(self, name: str, commit: str) -> tuple[bool, str]:
        proj = self.reg[name]
        sub = {"{commit}": commit, "{workdir}": proj["workdir"]}
        def fill(a):
            for k, v in sub.items():
                a = a.replace(k, v)
            return a
        for argv in proj.get("steps", []):
            rc, out = self.run([fill(a) for a in argv], cwd=proj["workdir"], env=self._env(proj), timeout=1200)
            if rc != 0:
                return False, f"passo falhou ({' '.join(argv)[:60]}): {out[-200:]}"
        deadline = self.now() + proj.get("health_timeout_s", HEALTH_TIMEOUT_S)
        health = proj.get("health", [])
        while True:
            bad = ""
            for argv in health:
                rc, out = self.run([fill(a) for a in argv], cwd=proj["workdir"], env=self._env(proj), timeout=60)
                if rc != 0:
                    bad = f"checagem de saúde falhou ({' '.join(argv)[:60]}): {out[-120:]}"
                    break
            if not bad:
                return True, "ok"
            if self.now() >= deadline:
                return False, bad
            self.sleep(3)

    def _checkout(self, name: str, m: str, commit: str) -> tuple[bool, str]:
        wd = self.reg[name]["workdir"]
        rc, out = self._git(name, "-C", wd, "fetch", m, commit)
        if rc != 0:
            return False, f"fetch falhou: {out[-150:]}"
        rc, out = self._git(name, "-C", wd, "checkout", "--detach", commit)
        return (rc == 0), ("ok" if rc == 0 else f"checkout falhou: {out[-150:]}")

    def deploy(self, req: dict) -> dict:
        name, commit = req["project"], req["commit"]
        res = {"ts": int(self.now()), "project": name, "commit": commit, "by": req.get("guardian", ""), "ok": False, "rolled_back": False}
        try:
            if name not in self.reg:
                raise RuntimeError("projeto não cadastrado no Pi")
            m = self._fetch_tags(name)
            tagged = self._tagged_commits(name, m)
            if commit not in tagged:
                raise RuntimeError("esse commit não é a ponta de uma etiqueta de versão")
            prev = self._deployed(name)
            res["from"] = prev
            if prev == commit:
                res.update(ok=True, msg="já estava nessa versão")
                return res
            if self._older(name, m, commit, prev):
                raise RuntimeError("essa versão é mais antiga que a que está no ar (downgrade não é aceito)")
            viol = self.compose_violations(name, m, commit)
            if viol:
                raise RuntimeError("a versão viola a política de isolamento: " + "; ".join(viol[:4]))
            sens = self.sensitive_of(name, self.changed_files(name, m, prev, commit))
            if sens and not req.get("sensitive_ok"):
                raise RuntimeError("a versão mexe em áreas de segurança e o mestre não confirmou o aviso")
            ok, msg = self._checkout(name, m, commit)
            if ok:
                ok, msg = self._steps(name, commit)
            if ok:
                res.update(ok=True, msg=f"versão {tagged[commit]} no ar")
                return res
            res["msg"] = msg
            if prev:  # volta para o que já estava no ar (não pede assinatura: não afrouxa nada)
                ok2, msg2 = self._checkout(name, m, prev)
                if ok2:
                    ok2, msg2 = self._steps(name, prev)
                res.update(rolled_back=True, msg=res["msg"] + (" | revertido para a versão anterior" if ok2 else f" | A REVERSÃO TAMBÉM FALHOU: {msg2}"))
            return res
        except RuntimeError as e:
            res["msg"] = str(e)[:300]
            return res
        except (OSError, subprocess.SubprocessError) as e:
            res["msg"] = f"erro: {str(e)[:200]}"
            return res

    def process_inbox(self) -> list[dict]:
        out = []
        inbox = self._path("inbox")
        for fn in sorted(os.listdir(inbox)):
            p = os.path.join(inbox, fn)
            try:
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError("não é um arquivo comum")  # link simbólico para outro lugar não vale
                if self.inbox_uid is not None and st.st_uid != self.inbox_uid:
                    raise ValueError("arquivo de outro usuário")
                with open(p) as f:
                    req = json.load(f)
                check_request(req)
            except (OSError, ValueError) as e:
                res = {"ts": int(self.now()), "project": "?", "commit": "?", "ok": False, "rolled_back": False, "msg": f"pedido inválido: {e}"[:200]}
            else:
                res = self.deploy(req)
            finally:
                try:
                    os.replace(p, self._path("done", fn))  # um pedido roda uma vez só
                except OSError:
                    pass
            self.status["history"] = ([res] + self.status.get("history", []))[:KEEP_HISTORY]
            out.append(res)
        if out:
            _atomic_write(self._path("status.json"), self.status)
            self.refresh_offers()
        return out

    def tick(self) -> None:
        self.process_inbox()
        self.refresh_offers()
