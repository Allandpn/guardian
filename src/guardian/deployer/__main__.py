"""python -m guardian.deployer run|once --registry /etc/guardian-deploy/projects.json --state /var/lib/guardian-deploy [--inbox-uid N]
python -m guardian.deployer init-trust --state /var/lib/guardian-deploy --from /var/lib/guardian-executor/state.json [--force]"""
import argparse
import json
import os
import sys
import time

from . import signed
from .core import Deployer


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardian.deployer")
    ap.add_argument("cmd", choices=["run", "once", "init-trust"])
    ap.add_argument("--registry")
    ap.add_argument("--state", required=True)
    ap.add_argument("--inbox-uid", type=int)
    ap.add_argument("--every", type=int, default=20)
    ap.add_argument("--from", dest="src", help="init-trust: estado do executor (state.json)")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    trust = os.path.join(a.state, "trust.json")
    if a.cmd == "init-trust":
        try:
            c = signed.init_trust(trust, a.src or "", a.force)
        except (OSError, ValueError) as e:
            print("init-trust:", e, file=sys.stderr)
            return 1
        print(f"Confiança do deployer criada em {trust}. Confira os guardiões e as passkeys:")
        for gid, g in c.trust.guardians.items():
            print(f"  {gid} {g.name} ({g.role}): {len(g.creds)} passkey(s)")
        return 0
    if not a.registry:
        ap.error("--registry é obrigatório")
    with open(a.registry) as f:
        reg = json.load(f)
    d = Deployer(reg, a.state, inbox_uid=a.inbox_uid, registry_path=a.registry, policy_path=os.path.join(os.path.dirname(a.registry), "policy.json"),
                 trust_path=trust)
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
