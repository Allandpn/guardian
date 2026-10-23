"""Veto de liberações: o que está nas listas de conteúdo adulto do Pi-hole (ou o mestre proibiu) nunca vira liberação nem pedido.

No Pi-hole uma liberação vence qualquer lista, então as listas só protegem se o Guardian se recusar a liberar o que elas cobrem.
O índice sai do gravity.db (somente leitura) e é refeito quando o arquivo muda (o `pihole -g` troca o arquivo todo dia).
"""
import os
import re
import sqlite3
import threading

from . import domains

_LDH = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def _clean(raw: str) -> str | None:
    """Uma linha do gravity como domínio: `||exemplo.com^` (ABP, cobre subdomínios) e `exemplo.com` (hosts). None para o que não é domínio."""
    d = raw.strip().lower()
    if d.startswith("||"):
        d = d[2:]
    d = d.rstrip("^")
    return d if _LDH.match(d) else None


def suffixes(d: str) -> list[str]:
    """O domínio e os pais dele com ao menos dois rótulos: a.b.com -> [a.b.com, b.com]."""
    p = d.split(".")
    return [".".join(p[i:]) for i in range(len(p) - 1)]


class Veto:
    def __init__(self, gravity_path: str | None, parents: list | None = None):
        self.path = gravity_path
        self.parents: list[str] = list(parents or [])  # sites vetados pelo mestre (o próprio domínio e tudo abaixo dele)
        self.lock = threading.Lock()
        self._mtime = None
        self.listed: set[str] = set()   # domínios das listas
        self.above: set[str] = set()    # pais de algum domínio listado: liberá-los (com subdomínios) abriria o que está listado
        self.loaded = False

    @property
    def enabled(self) -> bool:
        return bool(self.path)

    def refresh(self) -> None:
        """Recarrega se o gravity.db mudou. Se não der para ler, vale o último índice bom."""
        if not self.path:
            return
        try:
            m = os.stat(self.path).st_mtime_ns
        except OSError:
            return
        if m == self._mtime and self.loaded:
            return
        try:
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5)
            try:
                listed, above = set(), set()
                for (raw,) in conn.execute("SELECT domain FROM gravity"):
                    d = _clean(raw)
                    if d is None:
                        continue
                    listed.add(d)
                    above.update(suffixes(d)[1:])
            finally:
                conn.close()
        except sqlite3.Error:
            return
        with self.lock:
            self.listed, self.above, self._mtime, self.loaded = listed, above, m, True

    def reason(self, domain: str, regex_mode: bool = True) -> str | None:
        """Por que este domínio não pode ser liberado (None: pode). `domain` já normalizado."""
        for p in self.parents:
            if domain == p or domain.endswith("." + p):
                return f"site vetado pelo mestre ({p})"
        if not self.path:
            return None
        self.refresh()
        if not self.loaded:
            return "listas de conteúdo adulto indisponíveis"  # sem índice não dá para conferir: recusa em vez de liberar às cegas
        for s in suffixes(domain):
            if s in self.listed:
                return f"está nas listas de conteúdo adulto ({s})"
        if regex_mode and domains.rule_domain(domain) in self.above:
            return f"{domains.rule_domain(domain)} cobre domínios das listas de conteúdo adulto"
        return None

    def master_parent(self, domain: str) -> str | None:
        """O site vetado pelo mestre que cobre este domínio (None: nenhum). Não depende do índice das listas."""
        for p in self.parents:
            if domain == p or domain.endswith("." + p):
                return p
        return None

    def add_parent(self, domain: str) -> bool:
        d = domains.rule_domain(domain)  # www.reddit.com e reddit.com são o mesmo site
        if "." not in d or domains.is_public_suffix(d):
            raise ValueError("informe o domínio do site (como reddit.com), não só o final")
        if d in self.parents:
            return False
        self.parents.append(d)
        return True

    def remove_parent(self, domain: str) -> bool:
        d = domains.rule_domain(domain)
        if d not in self.parents:
            return False
        self.parents.remove(d)
        return True
