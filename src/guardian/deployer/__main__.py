"""python -m guardian.deployer run|once --registry /etc/guardian-deploy/projects.json --state /var/lib/guardian-deploy [--inbox-uid N]"""
import argparse
import json
import sys
import time

from .core import Deployer


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardian.deployer")
    ap.add_argument("cmd", choices=["run", "once"])
    ap.add_argument("--registry", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--inbox-uid", type=int)
    ap.add_argument("--every", type=int, default=20)
    a = ap.parse_args(argv)
    with open(a.registry) as f:
        reg = json.load(f)
    d = Deployer(reg, a.state, inbox_uid=a.inbox_uid)
    while True:
        try:
            d.tick()
        except Exception as e:  # o laço não pode morrer por um erro de rede
            print("deployer:", e, file=sys.stderr, flush=True)
        if a.cmd == "once":
            return 0
        time.sleep(a.every)


if __name__ == "__main__":
    sys.exit(main())
