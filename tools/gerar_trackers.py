#!/usr/bin/env python3
"""Gera a lista de domínios de trackers de torrent para o Pi-hole (deploy/pihole/torrent-trackers.txt).

Fontes: listas públicas de trackers (URLs). Só o nome do host entra, sem IP, e só o host exato (sem subdomínios).
Uso: python3 tools/gerar_trackers.py [saida]
"""
import ipaddress
import sys
import urllib.parse
import urllib.request

FONTES = [
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/all.txt",
]
# Trackers históricos que as listas de "melhores" já não trazem, mas os clientes ainda usam.
EXTRAS = [
    "tracker.openbittorrent.com", "open.demonii.com", "tracker.coppersurfer.tk", "tracker.leechers-paradise.org",
    "tracker.internetwarriors.net", "exodus.desync.com", "tracker.opentrackr.org", "tracker.torrent.eu.org",
    "9.rarbg.to", "9.rarbg.me", "p4p.arenabg.com", "tracker.tiny-vps.com", "tracker.cyberia.is",
    "opentor.org", "explodie.org", "tracker.moeking.me", "retracker.lanta-net.ru",
]


def host(url: str) -> str | None:
    h = urllib.parse.urlparse(url.strip()).hostname
    if not h or "." not in h:
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        return h.lower()


def main() -> None:
    hosts = set(EXTRAS)
    for src in FONTES:
        with urllib.request.urlopen(src, timeout=30) as r:
            for line in r.read().decode("utf-8", "replace").splitlines():
                h = host(line)
                if h:
                    hosts.add(h)
    out = sys.argv[1] if len(sys.argv) > 1 else "deploy/pihole/torrent-trackers.txt"
    with open(out, "w") as f:
        f.write("# Trackers de torrent (host exato). Gerado por tools/gerar_trackers.py\n")
        f.write("\n".join(sorted(hosts)) + "\n")
    print(f"{len(hosts)} domínios em {out}")


if __name__ == "__main__":
    main()
