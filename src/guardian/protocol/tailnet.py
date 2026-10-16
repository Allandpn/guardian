"""IPs de aparelhos na Tailscale: validação e mapeamento IP -> aparelho (o executor liga as consultas do Pi-hole ao aparelho)."""
import ipaddress

TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")
TAILNET_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")
MAX_IPS = 4


def valid_ips(raw) -> list[str]:
    """Só endereços da Tailscale, em forma canônica, sem repetição. Qualquer outra coisa é ignorada."""
    out: list[str] = []
    if not isinstance(raw, list):
        return out
    for x in raw[:MAX_IPS * 2]:
        try:
            ip = ipaddress.ip_address(x.strip()) if isinstance(x, str) else None
        except ValueError:
            continue
        if ip is not None and ip in (TAILNET_V4 if ip.version == 4 else TAILNET_V6) and str(ip) not in out:
            out.append(str(ip))
    return out[:MAX_IPS]


def ip_map(claims: dict[str, list]) -> dict[str, str]:
    """{aparelho: IPs declarados} -> {IP: aparelho}. Um IP declarado por mais de um aparelho é ambíguo e não vale para nenhum."""
    owners: dict[str, set[str]] = {}
    for dev, ips in claims.items():
        for ip in valid_ips(ips):
            owners.setdefault(ip, set()).add(dev)
    return {ip: next(iter(d)) for ip, d in owners.items() if len(d) == 1}
