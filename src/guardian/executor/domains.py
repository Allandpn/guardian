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


# Regra regex que o executor grava no Pi-hole para um domínio: o domínio e os seus subdomínios, nada mais.
# O guardião só vê e aprova o domínio simples; a regex é gerada aqui (ninguém digita regex) e só é reconhecida de volta nesta forma exata.
_PREFIX = r"^([a-zA-Z0-9-]+\.)*"
_SHAPE = re.compile(r"^\^\(\[a-zA-Z0-9-\]\+\\\.\)\*((?:[a-z0-9-]+\\\.)+[a-z0-9-]+)\$$")


def to_regex(domain: str) -> str:
    return _PREFIX + normalize(domain).replace(".", r"\.") + "$"


def from_regex(pattern) -> str | None:
    """O domínio de uma regex gerada por to_regex; None para qualquer outra (regras escritas à mão não são tocadas nem listadas)."""
    m = _SHAPE.match(pattern) if isinstance(pattern, str) else None
    if not m:
        return None
    try:
        d = normalize(m.group(1).replace("\\.", "."))
    except ValueError:
        return None
    return d if to_regex(d) == pattern else None
