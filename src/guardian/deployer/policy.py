"""Política de isolamento dos projetos em contêiner (docker compose).

O deployer roda como root, então um `docker-compose.yml` vindo de um repositório poderia pedir poderes que dão a volta no Guardian:
contêiner privilegiado, rede ou PID do host, o socket do Docker, uma pasta do host (`/etc`, `/opt/guardian`), o volume do gateway
(`deploy_gateway-data`) ou um arquivo de senhas do host como `env_file`. Esta função recebe a saída de
`docker compose config --format json --no-env-resolution` e devolve o que viola a política. Qualquer violação recusa o deploy.
Recebe só dados (nada é executado), então não depende de PyYAML.

Caminhos dentro do projeto que passam por um link simbólico da versão (`symlinks`, relativos ao projeto) também são violação: a política
confere uma cópia sem links, mas o checkout de verdade recria o link, e o Docker o segue ao montar a pasta (`./dados -> /` montaria o host).
"""
import os

# Serviço: campos que, preenchidos, dão acesso ao host (a mensagem diz qual).
_FORBID_TRUE = ("privileged", "oom_kill_disable")
_FORBID_SET = ("cap_add", "devices", "device_cgroup_rules", "network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup", "cgroup_parent",
               "sysctls", "runtime", "gpus", "group_add", "volumes_from", "external_links", "extra_hosts_host_gateway")
_BAD_OPT = ("unconfined", "disable", "no-new-privileges:false")
# Lista do que é PERMITIDO (o resto é recusado): o Compose ganha campos novos a cada versão, e um campo que a política não conhece
# (use_api_socket, provider, models, entitlements...) passaria direto por uma lista do que é proibido.
_SVC_OK = {"build", "image", "command", "entrypoint", "environment", "env_file", "labels", "logging", "restart", "depends_on", "healthcheck",
           "networks", "network_mode", "ports", "expose", "volumes", "tmpfs", "read_only", "user", "working_dir", "hostname", "domainname",
           "container_name", "cap_drop", "security_opt", "mem_limit", "mem_reservation", "memswap_limit", "cpus", "cpu_shares", "cpu_quota",
           "cpu_period", "cpuset", "pids_limit", "shm_size", "stop_grace_period", "stop_signal", "init", "tty", "stdin_open", "ulimits",
           "platform", "pull_policy", "profiles", "scale", "deploy", "secrets", "configs", "extra_hosts", "dns", "dns_search", "dns_opt",
           "mac_address", "attach", "annotations", "post_start", "pre_stop", "develop"}
_BUILD_OK = {"context", "dockerfile", "dockerfile_inline", "args", "target", "labels", "cache_from", "cache_to", "no_cache", "pull", "tags",
             "platforms", "shm_size", "extra_hosts", "additional_contexts", "network", "secrets", "ulimits", "isolation"}
_DEPLOY_OK = {"resources", "restart_policy", "replicas", "update_config", "rollback_config", "labels", "mode"}
_TOP_OK = {"name", "services", "networks", "volumes", "secrets", "configs"}


def _inside(path: str, root: str) -> bool:
    p, r = os.path.normpath(path), os.path.normpath(root)
    return p == r or p.startswith(r + os.sep)


def _allowed_bind(source: str, project_dir: str, allowed: list[str]) -> bool:
    if _inside(source, project_dir):
        return True
    return any(_inside(source, a) for a in allowed)


def _via_link(path: str, project_dir: str, symlinks) -> bool:
    """O caminho (dentro do projeto) passa por um link simbólico da versão?"""
    if not symlinks or not _inside(path, project_dir):
        return False
    parts = os.path.relpath(os.path.normpath(path), os.path.normpath(project_dir)).split(os.sep)
    return any("/".join(parts[:i]) in symlinks for i in range(1, len(parts) + 1))


# Contexto extra do build que não é pasta local: imagem ou outro serviço do mesmo projeto.
_REMOTE_CTX = ("docker-image://", "service:")


class _Check:
    """Uma conferência: o projeto, o que o registro permite e a lista de violações que vai sendo preenchida."""

    def __init__(self, project_dir: str, allowed_binds, allowed_contexts, symlinks, services=(), names=()):
        self.project_dir, self.symlinks = project_dir, symlinks
        self.services, self.names = set(services), set(names)   # names: nomes fixos que o registro do Pi (root) permite a ESTE projeto
        self.allowed = [a.rstrip("/") or "/" for a in (allowed_binds or [])]
        self.ctxs = [a.rstrip("/") or "/" for a in (allowed_contexts or [])]
        self.out: list[str] = []

    def link(self, path: str, what: str) -> None:
        if _via_link(path, self.project_dir, self.symlinks):
            self.out.append(f"{what} passa por link simbólico ({os.path.relpath(path, self.project_dir)})")

    def service(self, name: str, svc) -> None:
        if not isinstance(svc, dict):
            self.out.append(f"{name}: serviço ilegível")
            return
        for k in _FORBID_TRUE:
            if svc.get(k):
                self.out.append(f"{name}: {k}")
        for k in _FORBID_SET:
            v = svc.get(k)
            # network_mode só "none" ou a rede de OUTRO serviço deste mesmo projeto (o gateway usa a do contêiner do Tailscale)
            if v and not (k == "network_mode" and (v == "none" or (str(v).startswith("service:") and str(v)[8:] in self.services))):
                self.out.append(f"{name}: {k}")
        for k in svc:
            if k not in _SVC_OK and k not in _FORBID_TRUE and k not in _FORBID_SET and not str(k).startswith("x-"):
                self.out.append(f"{name}: campo não permitido ({k})")
        for hook in ("post_start", "pre_stop"):   # rodam dentro do contêiner, mas com privilégio próprio: só sem ele
            for x in svc.get(hook) or []:
                if isinstance(x, dict) and x.get("privileged"):
                    self.out.append(f"{name}: {hook} com privilégios")
        self.deploy(name, svc.get("deploy"))
        for o in svc.get("security_opt") or []:
            if any(b in str(o) for b in _BAD_OPT):
                self.out.append(f"{name}: security_opt {o}")
        self.volumes(name, svc.get("volumes") or [])
        self.env_files(name, svc.get("env_file") or [])
        if isinstance(svc.get("build"), dict):
            self.build(name, svc["build"])

    def deploy(self, name: str, d) -> None:
        if d is None:
            return
        if not isinstance(d, dict):
            self.out.append(f"{name}: deploy ilegível")
            return
        for k in d:
            if k not in _DEPLOY_OK:
                self.out.append(f"{name}: deploy.{k} não permitido")
        res = d.get("resources") or {}
        if not isinstance(res, dict) or set(res) - {"limits", "reservations"}:
            self.out.append(f"{name}: deploy.resources não permitido")
            return
        r = res.get("reservations") or {}
        if not isinstance(r, dict) or set(r) - {"cpus", "memory", "pids"}:   # devices / generic_resources: GPU e dispositivos do host
            self.out.append(f"{name}: deploy.resources.reservations não permitido")

    def volumes(self, name: str, vols) -> None:
        for v in vols:
            if not isinstance(v, dict):
                self.out.append(f"{name}: volume ilegível")
            elif v.get("type") == "bind" and not _allowed_bind(str(v.get("source", "")), self.project_dir, self.allowed):
                self.out.append(f"{name}: monta {v.get('source')}")
            elif v.get("type") == "bind":
                self.link(str(v.get("source", "")), f"{name}: montagem")
            elif v.get("type") not in ("bind", "volume", "tmpfs"):
                self.out.append(f"{name}: volume do tipo {v.get('type')}")

    def env_files(self, name: str, files) -> None:
        for e in files:
            path = e.get("path") if isinstance(e, dict) else e
            if not isinstance(path, str) or not _inside(path, self.project_dir):
                self.out.append(f"{name}: env_file {path}")
            else:
                self.link(path, f"{name}: env_file")

    def build(self, name: str, b: dict) -> None:
        for k in b:
            if k not in _BUILD_OK and k not in ("privileged", "ssh"):
                self.out.append(f"{name}: build.{k} não permitido")
        if b.get("network") not in (None, "default", "none"):
            self.out.append(f"{name}: build com rede {b.get('network')}")
        extra = b.get("additional_contexts") or {}
        if isinstance(extra, list):  # forma "nome=valor"
            extra = dict(str(x).split("=", 1) if "=" in str(x) else ("?", str(x)) for x in extra)
        local = [str(v) for v in extra.values() if not str(v).startswith(_REMOTE_CTX)] if isinstance(extra, dict) else ["?"]
        for c in [str(b.get("context", "")), *local]:   # outra pasta do host no build seria copiada para dentro da imagem (/etc, segredos do Pi)
            if not os.path.isabs(c) or not (_inside(c, self.project_dir) or any(_inside(c, x) for x in self.ctxs)):
                self.out.append(f"{name}: build fora do projeto ({c})")
            else:
                self.link(c, f"{name}: build")
        if b.get("privileged") or b.get("network") in ("host",):
            self.out.append(f"{name}: build com privilégios ou rede do host")
        if b.get("ssh"):  # repassaria as chaves SSH do root ao build
            self.out.append(f"{name}: build com ssh")

    def top_level(self, cfg: dict, proj) -> None:
        for k in cfg:
            if k not in _TOP_OK and not str(k).startswith("x-"):
                self.out.append(f"campo de topo não permitido ({k})")
        for key in ("secrets", "configs"):
            for n, d in (cfg.get(key) or {}).items():
                f = d.get("file") if isinstance(d, dict) else None
                if (isinstance(d, dict) and (d.get("external") or d.get("environment"))) or (f and not _inside(str(f), self.project_dir)):
                    self.out.append(f"{key} {n}: fora do projeto")
                elif f:
                    self.link(str(f), f"{key} {n}")
        # volume: driver_opts monta pasta do host; rede: attachable deixa outro contêiner entrar
        for key, what, driver, extra, bad in (("volumes", "volume", "local", "driver_opts", "externo ou com driver especial"),
                                              ("networks", "rede", "bridge", "attachable", "externa ou especial")):
            for n, d in (cfg.get(key) or {}).items():
                d = d or {}
                if d.get("external") or (d.get("driver") not in (None, driver)) or d.get(extra):
                    self.out.append(f"{what} {n}: {bad}")
                elif d.get("name") not in (None, f"{proj}_{n}") and d.get("name") not in self.names:  # `name:` pega um que já existe (o volume do gateway, a rede de outro projeto)
                    self.out.append(f"{what} {n}: nome de outro dono ({d.get('name')})")

def violations(cfg: dict, project_dir: str, allowed_binds: list[str] | None = None, allowed_contexts: list[str] | None = None,
               symlinks=frozenset(), forbidden_names=frozenset(), allowed_names=frozenset()) -> list[str]:
    """`forbidden_names`: nomes de projeto do compose que pertencem a outro serviço do Pi (o do Guardian é `deploy`): um projeto que se
    chamasse assim herdaria os volumes e as redes dele."""
    if not isinstance(cfg, dict):
        return ["configuração ilegível"]
    services = cfg.get("services") if isinstance(cfg.get("services"), dict) else {}
    c = _Check(project_dir, allowed_binds, allowed_contexts, symlinks, services, allowed_names)
    proj = cfg.get("name")
    if proj is not None and (not isinstance(proj, str) or proj.lower() in forbidden_names):
        c.out.append(f"nome de projeto do compose reservado ({proj})")
    for name, svc in (cfg.get("services") or {}).items():
        c.service(name, svc)
    c.top_level(cfg, proj)
    return c.out
