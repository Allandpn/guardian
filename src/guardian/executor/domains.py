import re

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize(domain) -> str:
    """Domínio exato ASCII (LDH) em minúsculas. Levanta ValueError se não servir. Sem curinga, regex ou IP."""
    if not isinstance(domain, str):
        raise ValueError("domínio inválido")
    d = domain.strip().lower().rstrip(".")
    if not d or len(d) > 253 or not d.isascii():
        raise ValueError("domínio inválido")
    labels = d.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        raise ValueError("domínio inválido")
    if labels[-1].isdigit():
        raise ValueError("endereço IP não é domínio")
    return d
