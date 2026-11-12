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
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error

from . import apps, policy, signed

_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
APP_REFRESH_S = 300   # a API do GitHub limita consultas sem token; as Releases mudam devagar
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


_GITHUB = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_PKG = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
# Arquivos que mudam política, restrições ou assinatura de um app Android: o mestre vê o aviso antes de instalar uma versão que os altere.
APP_SENSITIVE = [".github/workflows/*", "app/build.gradle.kts", "build.gradle.kts", "gradle/*", "gradle.properties", "app/src/main/AndroidManifest.xml"]


PI_MAX_SCRIPT_BYTES = 6000
PI_OUT_KEEP = 1500   # o fim da saída do script que fica no histórico (o relatório do executor ao gateway tem teto de 128 KB)
PI_OUT_RECENT = 3    # só os scripts mais recentes guardam a saída


def check_pi_run(req: dict) -> None:
    """Repetido de propósito (protocol/commands.py::check_pi_run_args): o deployer não importa nada do repositório."""
    s, n, t = req.get("script"), req.get("name", ""), req.get("timeout_s", 600)
    if not isinstance(s, str) or not s.strip() or "\x00" in s or len(s.encode("utf-8")) > PI_MAX_SCRIPT_BYTES:
        raise ValueError("script inválido")
    if not isinstance(n, str) or len(n) > 80 or any(ord(c) < 32 for c in n):
        raise ValueError("nome inválido")
    if not isinstance(t, int) or isinstance(t, bool) or not 5 <= t <= 3600:
        raise ValueError("tempo limite inválido")


def check_add_request(req: dict) -> None:
    """Repetido de propósito, como check_request (protocol/commands.py::check_project_add_args)."""
    if not isinstance(req.get("name"), str) or not _PROJECT.match(req["name"]):
        raise ValueError("nome inválido")
    if not isinstance(req.get("github"), str) or not _GITHUB.match(req["github"]) or req["github"].endswith(".git"):
        raise ValueError("repositório inválido")
    if not isinstance(req.get("pkg"), str) or len(req["pkg"]) > 200 or not _PKG.match(req["pkg"]):
        raise ValueError("pacote inválido")


# Rodam código sozinhos (o Python os carrega ao iniciar, o compose os lê sem ninguém pedir): sensíveis em qualquer projeto.
ALWAYS_SENSITIVE = ["*.pth", "*sitecustomize.py", "*usercustomize.py", ".venv/*", "venv/*", ".env", "*/.env", ".env.*", "*/.env.*",
                    "compose.y*ml", "*/compose.y*ml", "*docker-compose*.y*ml", "*compose.override*", "Dockerfile*", "*/Dockerfile*",
                    ".github/*", ".gitattributes", "*/.gitattributes", ".gitmodules"]


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
    def __init__(self, registry: dict, state_dir: str, run=_run, now=time.time, sleep=time.sleep, inbox_uid: int | None = None, github=None,
                 registry_path: str | None = None, policy_path: str | None = None, trusted_uid: int | None = None, trust_path: str | None = None):
        self.reg, self.state_dir, self.run, self.now, self.sleep = registry, state_dir, run, now, sleep
        self.registry_path, self.policy_path = registry_path, policy_path   # onde gravar um app cadastrado pelo mestre e a política de quem pode ser cadastrado
        # Rodando como root, só confia em pasta de deploy que é do root e que ninguém mais consegue trocar (nos testes, sem root, não confere).
        self.trusted_uid = (0 if os.geteuid() == 0 else None) if trusted_uid is None else trusted_uid
        self.github = github   # fábrica (token) -> cliente do GitHub; trocada nos testes
        self._app_ts = 0.0
        self.inbox_uid = inbox_uid
        # Com `trust_path` (o serviço sempre passa), só vale pedido com o comando assinado pelo mestre, conferido aqui (deployer/signed.py).
        self.signed = signed.SignedInbox(trust_path) if trust_path else None
        for d in ("mirrors", "inbox", "done", "apks"):
            os.makedirs(os.path.join(state_dir, d), exist_ok=True)
        with open(self._path("gitconfig"), "w") as f:
            f.write("[safe]\n\tdirectory = *\n")
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
        # Ambiente montado do zero: nada do ambiente do processo (GIT_*, DOCKER_*, proxies) muda o que o git e o docker fazem como root.
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
        if proj.get("ssh_key"):
            env["GIT_SSH_COMMAND"] = f"ssh -i {proj['ssh_key']} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
        env["GIT_TERMINAL_PROMPT"] = "0"
        tf = proj.get("token_file")
        if tf and str(proj.get("repo", "")).startswith("https://") and os.path.isfile(tf):  # repositório privado por https: o mesmo token da API
            import base64
            tok = open(tf).read().strip()
            if tok:
                env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraheader",
                           GIT_CONFIG_VALUE_0="Authorization: Basic " + base64.b64encode(f"x-access-token:{tok}".encode()).decode())
        env["GIT_CONFIG_GLOBAL"] = self._path("gitconfig")  # só do deployer: aceita repositórios de outro usuário (inclusive em git-upload-pack)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["HOME"] = os.environ.get("HOME") or self.state_dir   # o do root (credenciais do docker, known_hosts do ssh)
        return env

    def _git(self, name: str, *args, cwd=None) -> tuple[int, str]:
        proj = self.reg[name]
        # Sem hooks nem fsmonitor: o git roda como root dentro de uma pasta de projeto, e nada ali pode virar comando de root.
        return self.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args], cwd=cwd, env=self._env(proj), timeout=300)

    def untrusted_dir(self, path: str) -> str | None:
        """Motivo de a pasta não merecer confiança, ou None. O deploy roda git e docker como root nela: se um usuário comum puder escrever na pasta (ou
        trocá-la, por ser dona do diretório de cima), um arquivo plantado ali viraria código de root no próximo deploy assinado."""
        if self.trusted_uid is None:
            return None
        p, first = os.path.realpath(path), True
        while True:
            try:
                st = os.lstat(p)
            except OSError as e:
                return f"{p}: {e.strerror}"
            ok_owner = st.st_uid == self.trusted_uid if first else st.st_uid in (self.trusted_uid, 0)
            sticky_ok = bool(st.st_mode & 0o1000) and st.st_uid == 0 and not first   # tipo /tmp: ninguém renomeia o que não é seu
            if not ok_owner or (st.st_mode & 0o022 and not sticky_ok):
                return f"{p} não é só do root (dono {st.st_uid}, modo {oct(st.st_mode & 0o777)})"
            if p == "/":
                return None
            p, first = os.path.dirname(p), False

    def _unsafe_project_dirs(self, name: str) -> str | None:
        proj = self.reg[name]
        for d in [proj.get("workdir"), *(proj.get("allowed_contexts") or [])]:
            if d:
                why = self.untrusted_dir(d)
                if not why:   # o .git e o conteúdo da pasta também: um arquivo solto de outro dono já basta
                    for root, dirs, files in os.walk(d):
                        for n in dirs + files:
                            try:
                                st = os.lstat(os.path.join(root, n))
                            except OSError:
                                continue
                            if self.trusted_uid is not None and (st.st_uid != self.trusted_uid or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o002)):
                                why = f"{os.path.join(root, n)} não é só do root"
                                break
                        if why:
                            break
                if why:
                    return why
        return None

    def _escaping_links(self, name: str) -> set[str]:
        """Links simbólicos que já estão na pasta de deploy e apontam para fora dela (inclusive um que um contêiner criou numa pasta montada):
        caminhos relativos ao projeto. A política recusa a versão cujo compose passe por um deles."""
        proj = self.reg[name]
        top = proj.get("workdir")
        if not top or not os.path.isdir(top):
            return set()
        roots = [os.path.realpath(r) for r in (top, *(proj.get("allowed_binds") or []), *(proj.get("allowed_contexts") or []))]
        out = set()
        for root, dirs, files in os.walk(top):
            dirs[:] = [x for x in dirs if x != ".git" or os.path.islink(os.path.join(root, x))]   # o conteúdo do .git não é montado
            for n in dirs + files:
                p = os.path.join(root, n)
                if os.path.islink(p) and not any(policy._inside(os.path.realpath(p), r) for r in roots):
                    out.add(os.path.relpath(p, top))
        return out

    def _reserved_compose_names(self, name: str) -> set[str]:
        """Nomes de projeto do compose de OUTROS serviços do Pi (o Guardian sobe como `deploy`): usá-los daria os volumes e redes deles."""
        p = self.reg[name]
        own = {name.lower(), os.path.basename(str(p.get("workdir", "")).rstrip("/")).lower()}
        if p.get("compose_project"):   # nome declarado no registro do Pi (só o root edita): o do Guardian é "deploy"
            own.add(str(p["compose_project"]).lower())
        names = {"deploy"} | {n.lower() for n in self.reg}
        names |= {os.path.basename(str(p.get("workdir", "")).rstrip("/")).lower() for p in self.reg.values() if p.get("workdir")}
        return {n for n in names - own if n}

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
        rc, out = self._git(name, "--git-dir", m, "for-each-ref", "--sort=-creatordate", "--format=%(refname:short)", f"refs/tags/{pre}*")
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
        if not self._have(name, m, base) and self.reg[name].get("workdir"):  # o que está no ar pode não ter etiqueta: traz do diretório de trabalho
            self._git(name, "--git-dir", m, "fetch", self.reg[name]["workdir"], base)
        if not self._have(name, m, base):
            return None
        # --no-renames: mover um arquivo sensível para fora da pasta listaria só o nome novo; assim aparecem os dois (o que sumiu e o que surgiu)
        rc, out = self._git(name, "--git-dir", m, "diff", "--name-only", "--no-renames", base, commit)
        return out.splitlines() if rc == 0 else None

    def sensitive_of(self, name: str, files: list[str] | None) -> list[str]:
        """Arquivos da versão que pedem o aviso vermelho. Com `safe` no registro, vale o contrário: tudo é sensível, menos o que a lista diz
        que é seguro (documentação). Uma lista do que é sensível sempre esquece algo que roda código (um sitecustomize.py, um .pth, o
        __init__.py do pacote). E há o que é sensível em qualquer projeto, liste o registro ou não."""
        proj = self.reg[name]
        pats, safe = proj.get("sensitive", []), proj.get("safe")
        if files is None:
            return ["(não deu para comparar com a versão atual)"]
        match = lambda f, ps: any(fnmatch.fnmatch(f, p) for p in ps)   # noqa: E731
        pats = [*pats, *([os.path.normpath(proj["compose_env_file"])] if proj.get("compose_env_file") else [])]   # o arquivo de variáveis do compose
        return [f for f in files if match(f, pats) or match(f, ALWAYS_SENSITIVE) or (safe is not None and not match(f, safe))]

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
            links: set[str] = set()
            with tarfile.open(tar) as t:
                for mem in t.getmembers():  # só arquivos e pastas dentro do projeto (sem links nem caminhos absolutos)
                    n = os.path.normpath(mem.name)
                    if mem.issym() or mem.islnk():
                        links.add(n)   # não é extraído, mas o checkout de verdade o recria: a política recusa caminho que passe por ele
                        continue
                    if not (mem.isfile() or mem.isdir()) or n.startswith(("/", "..")):
                        continue
                    t.extract(mem, pdir, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
            links |= self._escaping_links(name)
            # Os arquivos de variáveis que o compose vai ler NO AR: o da versão, se ela traz um (o checkout troca o que está na pasta), senão o
            # que já está na pasta de deploy (não versionado, do root). Validar com outro daria outra interpolação (${PASTA} -> /).
            for rel in {os.path.join(os.path.dirname(self._compose_rel(name)), ".env"), *([proj["compose_env_file"]] if proj.get("compose_env_file") else [])}:
                live, here = os.path.join(proj["workdir"], rel), os.path.join(pdir, rel)
                if not os.path.lexists(here) and os.path.isfile(live):
                    os.makedirs(os.path.dirname(here), exist_ok=True)
                    shutil.copy(live, here)
            rc, out = self.run(self._compose_base(name, pdir) + ["config", "--format", "json", "--no-env-resolution"],
                               cwd=pdir, env=self._env(proj), timeout=120)
            if rc != 0:
                return [f"não consegui validar o compose: {out[-120:]}"]
            try:
                cfg = json.loads(out)
            except ValueError:
                return ["saída do compose ilegível"]
            return policy.violations(cfg, pdir, proj.get("allowed_binds"), proj.get("allowed_contexts"),
                                     symlinks=frozenset(links), forbidden_names=frozenset(self._reserved_compose_names(name)),
                                     allowed_names=frozenset(proj.get("compose_names") or []))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # --- ofertas: o que o mestre pode aprovar -----------------------------------------------
    def _code_projects(self) -> list[str]:
        return [n for n, p in self.reg.items() if p.get("type") != "android_app"]

    # --- apps Android: Releases do GitHub viram ofertas de instalação ---------------------------------
    def _dir_offers(self, name: str, proj: dict, keep: set) -> list[dict]:
        """Pasta local (só root escreve): cada .apk vira uma oferta. A etiqueta é o nome do arquivo; não há código para comparar, então exige atenção."""
        out = []
        d = proj["dir"]
        files = sorted((f for f in os.listdir(d) if f.endswith(".apk")), key=lambda f: -os.path.getmtime(os.path.join(d, f)))[:3]
        for f in files:
            src = os.path.join(d, f)
            size = os.path.getsize(src)
            if not 1 <= size <= apps.MAX_APK_BYTES:
                continue
            h = hashlib.sha256()
            with open(src, "rb") as fh:
                for chunk in iter(lambda: fh.read(64 * 1024), b""):
                    h.update(chunk)
            sha = h.hexdigest()
            dest = self._path("apks", sha + ".apk")
            if not os.path.isfile(dest):
                shutil.copyfile(src, dest + ".part")
                os.replace(dest + ".part", dest)
            keep.add(sha)
            stem = f[:-4]
            out.append({"kind": "app", "app": name, "pkg": proj["pkg"], "tag": stem[:40], "version_name": stem[:40], "sha256": sha, "size": size,
                        "asset": f[:80], "subject": "arquivo local no Pi", "author": "local", "ts": int(os.path.getmtime(src)), "files": None,
                        "sensitive": ["(origem local: sem código para comparar)"], "sensitive_n": 1})
        return out

    def refresh_app_offers(self, force: bool = False) -> list[dict]:
        """Releases dos apps (ou APKs numa pasta do Pi) viram ofertas de instalação em apk-offers.json; o APK fica guardado pelo SHA-256."""
        names = [n for n, p in self.reg.items() if p.get("type") == "android_app"]
        if not names or (not force and self.now() - self._app_ts < APP_REFRESH_S):
            return []
        self._app_ts = self.now()
        cache = self._load("apps-cache.json", {})
        offers: list[dict] = []
        errors: list[dict] = []
        keep: set[str] = set()
        for name in names:
            proj = self.reg[name]
            try:
                if proj.get("source") == "dir":   # APKs deixados à mão por root numa pasta do Pi (fora do GitHub)
                    offers.extend(self._dir_offers(name, proj, keep))
                else:
                    self._github_offers(name, proj, cache, keep, offers)   # vai acrescentando: o que já entrou fica, mesmo se a seguinte falhar
            except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError) as e:
                errors.append({"app": name, "error": str(e)[:200]})
        for f in os.listdir(self._path("apks")):   # só ficam os APKs das ofertas atuais
            if f.endswith(".apk") and f[:-4] not in keep and offers:
                os.remove(self._path("apks", f))
        _atomic_write(self._path("apps-cache.json"), {k: v for k, v in cache.items() if v["sha256"] in keep})
        _atomic_write(self._path("apk-offers.json"), {"ts": int(self.now()), "offers": offers, "errors": errors})
        return offers

    def _github_offers(self, name: str, proj: dict, cache: dict, keep: set, offers: list) -> None:
        token = None
        if proj.get("token_file") and os.path.isfile(proj["token_file"]):
            token = open(proj["token_file"]).read().strip() or None
        gh = self.github(token) if self.github else apps.GitHub(token)
        rels = [r for r in gh.releases(proj["github"]) if isinstance(r, dict) and not r.get("draft")
                and (proj.get("prerelease") or not r.get("prerelease")) and str(r.get("tag_name", "")).startswith(proj.get("tag_prefix", ""))]
        commit_of = {}
        if proj.get("repo"):  # o commit de cada etiqueta, para dizer se a versão mexe em arquivos de segurança
            m = self._fetch_tags(name)
            commit_of = {tag: c for c, tag in self._tagged_commits(name, m).items()}
        for i, rel in enumerate(rels[:3]):
            asset = apps.pick_asset(rel, proj.get("asset", r"\.apk$"))
            if not asset or int(asset.get("size", 0)) > apps.MAX_APK_BYTES:
                continue
            ent = self._cached_apk(name, proj, gh, asset, cache)
            keep.add(ent["sha256"])
            tag = rel["tag_name"]
            base = commit_of.get(rels[i + 1]["tag_name"]) if i + 1 < len(rels) else None   # comparada com a Release anterior
            m_ = self._mirror(name) if proj.get("repo") else None
            files = self.changed_files(name, m_, base, commit_of[tag]) if m_ and tag in commit_of else None
            sens = self.sensitive_of(name, files)
            body = (rel.get("body") or "").strip().splitlines()
            offers.append({"kind": "app", "app": name, "pkg": proj["pkg"], "tag": tag, "version_name": tag.lstrip("v")[:40],
                           "sha256": ent["sha256"], "size": ent["size"], "asset": asset["name"][:80],
                           "subject": (rel.get("name") or (body[0] if body else ""))[:80],
                           "author": str((rel.get("author") or {}).get("login", ""))[:40], "ts": apps.release_ts(rel),
                           "files": len(files) if files is not None else None, "sensitive": sens[:8], "sensitive_n": len(sens)})

    def _cached_apk(self, name: str, proj: dict, gh, asset: dict, cache: dict) -> dict:
        """{sha256, size} do APK da Release: baixa só se ainda não está guardado."""
        key = f"{name}:{asset['id']}"
        ent = cache.get(key)
        if not ent or not os.path.isfile(self._path("apks", ent["sha256"] + ".apk")):
            tmp = self._path("apks", f".dl-{asset['id']}")
            sha, size = gh.download(proj["github"], asset["id"], tmp)
            os.replace(tmp, self._path("apks", sha + ".apk"))
            ent = cache[key] = {"sha256": sha, "size": size}
        return ent

    def refresh_offers(self) -> list[dict]:
        offers: list[dict] = []
        for name in self._code_projects():
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
        _atomic_write(self._path("offers.json"), {"ts": int(self.now()), "offers": offers, "features": ["pi_run"],   # o site só libera o que o deployer sabe fazer
                                                  "current": {n: self._deployed(n) for n in self._code_projects()}})
        return offers

    # --- instalar ---------------------------------------------------------------------
    def _compose_rel(self, name: str) -> str:
        return os.path.normpath(self.reg[name].get("compose_file", "docker-compose.yml"))

    def _compose_base(self, name: str, root: str) -> list[str]:
        """`docker compose` com os arquivos EXPLÍCITOS: a validação e a instalação leem exatamente os mesmos. Sem `-f`, o compose prefere um
        compose.yaml e junta os *.override.* que a versão trouxer, e um COMPOSE_FILE no .env escolheria outro arquivo: nada disso foi validado."""
        proj = self.reg[name]
        cfile = os.path.join(root, self._compose_rel(name))
        argv = ["docker", "compose", "--project-directory", os.path.dirname(cfile), "-f", cfile]
        if proj.get("compose_env_file"):
            argv += ["--env-file", os.path.join(root, os.path.normpath(proj["compose_env_file"]))]
        if proj.get("compose_project"):   # fixo: um COMPOSE_PROJECT_NAME no .env da versão não troca o projeto (e os volumes) por outro
            argv += ["-p", str(proj["compose_project"])]
        return argv

    def _step_argv(self, name: str, argv: list[str]) -> list[str]:
        """Nos projetos em contêiner, todo passo `docker compose ...` roda com os mesmos arquivos que a política conferiu."""
        if self.reg[name].get("type") != "compose" or argv[:2] != ["docker", "compose"]:
            return argv
        rest, i = [], 2
        while i < len(argv):   # o que o registro tinha de arquivo/pasta é trocado pelo que foi validado
            a = argv[i]
            if a in ("-f", "--file", "--env-file", "--project-directory", "-p", "--project-name"):
                i += 2
                continue
            if a.startswith(("--file=", "--env-file=", "--project-directory=", "--project-name=")):
                i += 1
                continue
            rest.append(a)
            i += 1
        return self._compose_base(name, self.reg[name]["workdir"]) + rest

    def _steps(self, name: str, commit: str) -> tuple[bool, str]:
        proj = self.reg[name]
        sub = {"{commit}": commit, "{workdir}": proj["workdir"]}
        def fill(a):
            for k, v in sub.items():
                a = a.replace(k, v)
            return a
        for argv in proj.get("steps", []):
            rc, out = self.run(self._step_argv(name, [fill(a) for a in argv]), cwd=proj["workdir"], env=self._env(proj), timeout=1200)
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
        rc, out = self._git(name, "-C", wd, "checkout", "--force", "--detach", commit)
        return (rc == 0), ("ok" if rc == 0 else f"checkout falhou: {out[-150:]}")

    def deploy(self, req: dict) -> dict:
        name, commit = req["project"], req["commit"]
        res = {"ts": int(self.now()), "project": name, "commit": commit, "by": req.get("guardian", ""), "ok": False, "rolled_back": False}
        try:
            if name not in self.reg:
                raise RuntimeError("projeto não cadastrado no Pi")
            unsafe = self._unsafe_project_dirs(name)
            if unsafe:
                raise RuntimeError("pasta de deploy sem garantia de isolamento: " + unsafe)
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
                if self.signed is not None:
                    req = self.signed.check(req if isinstance(req, dict) else {}, self.now())   # vale o que está no comando assinado
                kind = req.get("kind") if isinstance(req, dict) else None
                if kind == "project_add":
                    check_add_request(req)
                elif kind == "pi_run":
                    if self.signed is None:   # sem a assinatura conferida aqui, ninguém roda script como root
                        raise ValueError("script só roda com a assinatura do mestre conferida pelo deployer")
                    check_pi_run(req)
                elif kind != "trust" or self.signed is None:   # mudança de confiança só existe com a assinatura conferida aqui
                    check_request(req)
            except (OSError, ValueError) as e:
                res = {"ts": int(self.now()), "project": "?", "commit": "?", "ok": False, "rolled_back": False, "msg": f"pedido inválido: {e}"[:200]}
            else:
                if req.get("kind") == "trust":
                    res = {"ts": int(self.now()), "project": "confiança", "commit": req["type"], "ok": True, "rolled_back": False,
                           "by": req["guardian"], "msg": f"confiança do deployer atualizada ({req['type']})"}
                else:
                    res = (self.project_add(req) if req.get("kind") == "project_add" else self.pi_run(req) if req.get("kind") == "pi_run" else self.deploy(req))
            finally:
                try:
                    os.replace(p, self._path("done", fn))  # um pedido roda uma vez só
                except OSError:
                    pass
            self.status["history"] = ([res] + self.status.get("history", []))[:KEEP_HISTORY]
            for old in [x for x in self.status["history"] if "out" in x][PI_OUT_RECENT:]:
                old.pop("out", None)
            out.append(res)
        if out:
            _atomic_write(self._path("status.json"), self.status)
            self.refresh_offers()
        return out

    def _policy(self) -> dict:
        try:
            with open(self.policy_path or "") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def pi_run(self, req: dict) -> dict:
        """Roda o script que o mestre assinou, como root, uma vez. Só chega aqui com a assinatura conferida (process_inbox)."""
        name = (req.get("name") or "script")[:80]
        t = req.get("timeout_s", 600)
        res = {"ts": int(self.now()), "project": "script", "commit": name, "by": req.get("guardian", ""), "ok": False, "rolled_back": False}
        d = self._path("scripts")
        os.makedirs(d, mode=0o700, exist_ok=True)
        fd, path = tempfile.mkstemp(dir=d, prefix="run-", suffix=".sh")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(req["script"])
            os.chmod(path, 0o700)
            env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}
            try:
                rc, out = self.run(["/bin/bash", path], cwd="/root", env=env, timeout=t)
                res["ok"] = rc == 0
                res["msg"] = "terminou sem erro" if rc == 0 else f"terminou com código {rc}"
            except subprocess.TimeoutExpired as e:
                out = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                res["msg"] = f"passou do tempo limite ({t} s) e foi interrompido"
            except OSError as e:
                out, res["msg"] = "", f"não consegui rodar: {e}"[:200]
            res["out"] = (out or "")[-PI_OUT_KEEP:]
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        return res

    def project_add(self, req: dict) -> dict:
        """Cadastra um app Android que o mestre pediu (assinado e conferido pelo executor; aqui confere de novo). Só app lido das Releases do GitHub,
        de um dono permitido pela política do Pi (público, ou privado se o token do Pi o enxerga), com pacote e nome ainda não usados. Nunca cria projeto com passos no Pi."""
        res = {"ts": int(self.now()), "project": req["name"], "commit": "cadastro", "ok": False, "rolled_back": False, "by": req.get("guardian")}

        def fail(msg: str) -> dict:
            res["msg"] = msg[:200]
            return res
        owners = {str(o).lower() for o in (self._policy().get("allowed_owners") or []) if isinstance(o, str)}
        if req["github"].split("/")[0].lower() not in owners:
            return fail("dono do repositório não permitido neste Pi (policy.json)")
        if not self.registry_path:
            return fail("o deployer não sabe onde gravar o cadastro")
        if req["name"] in self.reg:
            return fail("já existe um projeto com este nome")
        for n, p in self.reg.items():
            if p.get("pkg") == req["pkg"]:
                return fail(f"o pacote já pertence a {n}")
            if str(p.get("github", "")).lower() == req["github"].lower():
                return fail(f"o repositório já está cadastrado como {n}")
        entry_extra: dict = {}
        mk = lambda token: self.github(token) if self.github else apps.GitHub(token)
        try:   # primeiro sem token: se o repositório é público, nada de segredo entra no jogo
            mk(None).releases(req["github"])
        except Exception as e:
            tf = self._policy().get("token_file")
            if not (isinstance(tf, str) and os.path.isfile(tf)):
                return fail(f"não consegui ler o repositório: {e}. Se ele é privado, o Pi precisa do token de leitura (docs/DEPLOY.md)")
            try:   # repositório privado: o token único de leitura do Pi (o dono do token escolhe, no GitHub, quais repositórios ele enxerga)
                with open(tf) as f:
                    token = f.read().strip()
                mk(token or None).releases(req["github"])
            except Exception as e2:
                return fail(f"nem o token do Pi enxerga este repositório ({e2}): inclua-o no token em GitHub > Settings > Developer settings (Contents: leitura)")
            entry_extra["token_file"] = tf
        new = {**self.reg, req["name"]: {"type": "android_app", "github": req["github"], "repo": f"https://github.com/{req['github']}.git", "pkg": req["pkg"],
                                           "tag_prefix": "v", "asset": r"\.apk$", "sensitive": list(APP_SENSITIVE), **entry_extra}}
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.registry_path), prefix=".tmp-")
            with os.fdopen(fd, "w") as f:
                json.dump(new, f, indent=2, ensure_ascii=False)
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.registry_path)
        except OSError as e:
            return fail(f"não consegui gravar o registro: {e}")
        self.reg[req["name"]] = new[req["name"]]
        res.update(ok=True, msg=f"app cadastrado: {req['name']} ({req['github']}, {req['pkg']}, {'privado' if entry_extra else 'público'})")
        return res

    def tick(self) -> None:
        self.process_inbox()
        self.refresh_offers()
        self.refresh_app_offers()
