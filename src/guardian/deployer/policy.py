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

# Serviço: campos que, preenchidos, dão acesso ao host.
_FORBID_TRUE = ("privileged", "oom_kill_disable")
_FORBID_SET = ("cap_add", "devices", "device_cgroup_rules", "network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup", "cgroup_parent",
               "sysctls", "runtime", "gpus", "group_add", "volumes_from", "external_links", "extra_hosts_host_gateway")
_BAD_OPT = ("unconfined", "disable", "no-new-privileges:false")


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


def violations(cfg: dict, project_dir: str, allowed_binds: list[str] | None = None, allowed_contexts: list[str] | None = None,
               symlinks=frozenset(), forbidden_names=frozenset()) -> list[str]:
    """`forbidden_names`: nomes de projeto do compose que pertencem a outro serviço do Pi (o do Guardian é `deploy`): um projeto que se
    chamasse assim herdaria os volumes e as redes dele."""
    allowed = [a.rstrip("/") or "/" for a in (allowed_binds or [])]
    ctxs = [a.rstrip("/") or "/" for a in (allowed_contexts or [])]
    out: list[str] = []
    if not isinstance(cfg, dict):
        return ["configuração ilegível"]
    proj = cfg.get("name")
    if proj is not None and (not isinstance(proj, str) or proj.lower() in forbidden_names):
        out.append(f"nome de projeto do compose reservado ({proj})")

    def link(path: str, what: str) -> None:
        if _via_link(path, project_dir, symlinks):
            out.append(f"{what} passa por link simbólico ({os.path.relpath(path, project_dir)})")
    for name, svc in (cfg.get("services") or {}).items():
        if not isinstance(svc, dict):
            out.append(f"{name}: serviço ilegível")
            continue
        for k in _FORBID_TRUE:
            if svc.get(k):
                out.append(f"{name}: {k}")
        for k in _FORBID_SET:
            v = svc.get(k)
            if v and not (k == "network_mode" and v == "none"):
                out.append(f"{name}: {k}")
        for o in svc.get("security_opt") or []:
            if any(b in str(o) for b in _BAD_OPT):
                out.append(f"{name}: security_opt {o}")
        for v in svc.get("volumes") or []:
            if not isinstance(v, dict):
                out.append(f"{name}: volume ilegível")
            elif v.get("type") == "bind" and not _allowed_bind(str(v.get("source", "")), project_dir, allowed):
                out.append(f"{name}: monta {v.get('source')}")
            elif v.get("type") == "bind":
                link(str(v.get("source", "")), f"{name}: montagem")
            elif v.get("type") not in ("bind", "volume", "tmpfs"):
                out.append(f"{name}: volume do tipo {v.get('type')}")
        for e in svc.get("env_file") or []:
            path = e.get("path") if isinstance(e, dict) else e
            if not isinstance(path, str) or not _inside(path, project_dir):
                out.append(f"{name}: env_file {path}")
            else:
                link(path, f"{name}: env_file")
        b = svc.get("build")
        if isinstance(b, dict):
            ctx = str(b.get("context", ""))
            extra = b.get("additional_contexts") or {}
            if isinstance(extra, list):  # forma "nome=valor"
                extra = dict(str(x).split("=", 1) if "=" in str(x) else ("?", str(x)) for x in extra)
            local = [str(v) for v in extra.values() if not str(v).startswith(_REMOTE_CTX)] if isinstance(extra, dict) else ["?"]
            for c in [ctx, *local]:   # outra pasta do host no build seria copiada para dentro da imagem (/etc, segredos do Pi)
                if not os.path.isabs(c) or not (_inside(c, project_dir) or any(_inside(c, x) for x in ctxs)):
                    out.append(f"{name}: build fora do projeto ({c})")
                else:
                    link(c, f"{name}: build")
            if b.get("privileged") or b.get("network") in ("host",):
                out.append(f"{name}: build com privilégios ou rede do host")
            if b.get("ssh"):  # repassaria as chaves SSH do root ao build
                out.append(f"{name}: build com ssh")
    for key in ("secrets", "configs"):
        for n, d in (cfg.get(key) or {}).items():
            f = d.get("file") if isinstance(d, dict) else None
            if (isinstance(d, dict) and (d.get("external") or d.get("environment"))) or (f and not _inside(str(f), project_dir)):
                out.append(f"{key} {n}: fora do projeto")
            elif f:
                link(str(f), f"{key} {n}")
    for n, d in (cfg.get("volumes") or {}).items():
        d = d or {}
        if d.get("external") or (d.get("driver") not in (None, "local")) or d.get("driver_opts"):
            out.append(f"volume {n}: externo ou com driver especial")
        elif d.get("name") not in (None, f"{proj}_{n}"):  # `name:` pega um volume que já existe (o do gateway, o de outro projeto)
            out.append(f"volume {n}: nome de outro dono ({d.get('name')})")
    for n, d in (cfg.get("networks") or {}).items():
        d = d or {}
        if d.get("external") or (d.get("driver") not in (None, "bridge")) or d.get("attachable"):
            out.append(f"rede {n}: externa ou especial")
        elif d.get("name") not in (None, f"{proj}_{n}"):
            out.append(f"rede {n}: nome de outro dono ({d.get('name')})")
    return out
