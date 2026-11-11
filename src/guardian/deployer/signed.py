"""O deployer confere ele mesmo a assinatura do mestre: não confia no executor só porque o pedido veio do usuário dele.

O executor deixa na caixa o comando assinado inteiro (`envelope`: payload + assinaturas das passkeys). O deployer tem a SUA cópia da
confiança (`trust.json`, do root): os guardiões, as passkeys, os papéis, as janelas e o contador de cada um. Ela nasce na instalação
(`init-trust`, a partir do estado do executor naquele momento) e depois só muda por comando de confiança assinado que o executor também
encaminha (passkey nova do mestre, mestre novo). O que vale para instalar é o que está DENTRO do comando assinado; os campos que o
executor escreve ao lado são ignorados.
"""
import json
import os
import tempfile

try:
    from .protocol import commands as cmds   # instalado: cópia do protocolo dentro do pacote do deployer (deploy/install-deployer.sh)
except ImportError:
    from ..protocol import commands as cmds  # no repositório (testes)


class SignedInbox:
    def __init__(self, path: str):
        self.path = path
        self.consumer: cmds.Consumer | None = None
        if os.path.exists(path):
            with open(path) as f:
                self.consumer = cmds.Consumer.from_json(json.load(f))

    def save(self) -> None:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path) or ".", prefix=".tmp-")
        with os.fdopen(fd, "w") as f:
            json.dump(self.consumer.to_json(), f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def check(self, req: dict, now: float) -> dict:
        """O pedido que o comando assinado autoriza (deploy, cadastro de app ou mudança de confiança). Levanta ValueError se não autoriza."""
        if self.consumer is None:
            raise ValueError("o deployer ainda não tem a confiança dos guardiões: rode deploy/install-deployer.sh como root")
        try:
            v = self.consumer.accept(req.get("envelope"), now=now)   # assinatura, papel (deploy é só do mestre), horário, destino, contador
        except cmds.CommandError as e:
            raise ValueError(f"assinatura recusada: {e}") from e
        try:
            t, a, who = v.cmd["type"], v.cmd["args"], v.cmd["guardian"]
            if t in cmds.TRUST_TYPES:
                self.consumer.apply_trust(v.cmd)
                return {"kind": "trust", "type": t, "guardian": who}
            if t == cmds.T_DEPLOY:
                cmds.check_deploy_args(a)
                return {"project": a["project"], "commit": a["commit"], "sensitive_ok": a.get("sensitive_ok") is True, "guardian": who}
            if t == cmds.T_PI_RUN:
                cmds.check_pi_run_args(a)
                return {"kind": "pi_run", "script": a["script"], "name": a.get("name", ""), "timeout_s": a.get("timeout_s", 600), "guardian": who}
            if t == cmds.T_PROJECT_ADD:
                cmds.check_project_add_args(a)
                return {"kind": "project_add", "name": a["name"], "github": a["github"], "pkg": a["pkg"], "guardian": who}
            raise ValueError(f"comando que o deployer não executa: {t}")
        finally:
            self.save()   # contador consumido, deu certo ou não: o mesmo comando não vale duas vezes


def init_trust(path: str, executor_state: str, force: bool = False) -> cmds.Consumer:
    """Cria a confiança do deployer a partir do estado do executor (rodado pelo root, na instalação)."""
    if os.path.exists(path) and not force:
        raise ValueError(f"{path} já existe (use --force para trocar)")
    with open(executor_state) as f:
        data = json.load(f)
    if not data.get("consumer"):
        raise ValueError("o executor ainda não foi pareado")
    box = SignedInbox(path)
    box.consumer = cmds.Consumer.from_json(data["consumer"])
    box.save()
    return box.consumer
