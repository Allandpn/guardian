"""python -m guardian.gateway [serve|init --name NOME]"""
import argparse
import sys

from .config import Config
from .db import Store
from .server import create_invite, make_server


def main(argv=None):
    p = argparse.ArgumentParser(prog="guardian.gateway")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("serve")
    i = sub.add_parser("init", help="gera o convite do primeiro guardião (válido por 24 h)")
    i.add_argument("--name", required=True)
    a = p.parse_args(argv)
    cfg = Config.from_env()
    if a.cmd == "init":
        token = create_invite(Store(cfg.db_path), "new_guardian", None, a.name, cfg.invite_ttl_s)
        print(f"Abra {cfg.origin}/#invite={token}")
        return 0
    srv = make_server(cfg)
    print(f"gateway em {cfg.bind}:{cfg.port} origem={cfg.origin} rp_id={cfg.rp_id}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
