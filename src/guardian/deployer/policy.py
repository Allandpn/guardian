"""Política de isolamento dos projetos em contêiner (docker compose).

O deployer roda como root, então um `docker-compose.yml` vindo de um repositório poderia pedir poderes que dão a volta no Guardian:
contêiner privilegiado, rede ou PID do host, o socket do Docker, uma pasta do host (`/etc`, `/opt/guardian`), o volume do gateway
(`deploy_gateway-data`) ou um arquivo de senhas do host como `env_file`. Esta função recebe a saída de
`docker compose config --format json --no-env-resolution` e devolve o que viola a política. Qualquer violação recusa o deploy.
Recebe só dados (nada é executado), então não depende de PyYAML.
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


def violations(cfg: dict, project_dir: str, allowed_binds: list[str] | None = None, allowed_contexts: list[str] | None = None) -> list[str]:
    allowed = [a.rstrip("/") or "/" for a in (allowed_binds or [])]
    ctxs = [a.rstrip("/") or "/" for a in (allowed_contexts or [])]
    out: list[str] = []
    if not isinstance(cfg, dict):
        return ["configuração ilegível"]
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
            elif v.get("type") not in ("bind", "volume", "tmpfs"):
                out.append(f"{name}: volume do tipo {v.get('type')}")
        for e in svc.get("env_file") or []:
            path = e.get("path") if isinstance(e, dict) else e
            if not isinstance(path, str) or not _inside(path, project_dir):
                out.append(f"{name}: env_file {path}")
        b = svc.get("build")
        if isinstance(b, dict):
            ctx = str(b.get("context", ""))
            if not os.path.isabs(ctx) or not (_inside(ctx, project_dir) or any(_inside(ctx, c) for c in ctxs)):
                out.append(f"{name}: build fora do projeto ({ctx})")
            if b.get("privileged") or b.get("network") in ("host",):
                out.append(f"{name}: build com privilégios ou rede do host")
    for key in ("secrets", "configs"):
        for n, d in (cfg.get(key) or {}).items():
            f = d.get("file") if isinstance(d, dict) else None
            if (isinstance(d, dict) and d.get("external")) or (f and not _inside(str(f), project_dir)):
                out.append(f"{key} {n}: fora do projeto")
    for n, d in (cfg.get("volumes") or {}).items():
        d = d or {}
        if d.get("external") or (d.get("driver") not in (None, "local")) or d.get("driver_opts"):
            out.append(f"volume {n}: externo ou com driver especial")
    for n, d in (cfg.get("networks") or {}).items():
        d = d or {}
        if d.get("external") or (d.get("driver") not in (None, "bridge")) or d.get("attachable"):
            out.append(f"rede {n}: externa ou especial")
    return out
