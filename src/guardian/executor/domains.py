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


def rule_domain(domain: str) -> str:
    """O domínio que a regra cobre: sem o "www." da frente (www.science.org e science.org são o mesmo site)."""
    d = normalize(domain)
    base = d[4:] if d.startswith("www.") else d
    return base if "." in base else d


def to_regex(domain: str) -> str:
    return _PREFIX + rule_domain(domain).replace(".", r"\.") + "$"


def regex_forms(domain: str) -> list[str]:
    """Todas as formas que o executor já gravou para o domínio: a atual (sem "www.") e a antiga (com o host todo)."""
    d = normalize(domain)
    return list(dict.fromkeys([to_regex(d), _PREFIX + d.replace(".", r"\.") + "$"]))


def from_regex(pattern) -> str | None:
    """O domínio de uma regex gerada por to_regex; None para qualquer outra (regras escritas à mão não são tocadas nem listadas)."""
    m = _SHAPE.match(pattern) if isinstance(pattern, str) else None
    if not m:
        return None
    try:
        d = normalize(m.group(1).replace("\\.", "."))
    except ValueError:
        return None
    return d if pattern in regex_forms(d) else None
