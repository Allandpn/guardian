"""Comandos assinados pelos guardiões e o estado de confiança de quem os recebe.

Um comando são bytes JSON; o `payload` do envelope é o base64url desses bytes exatos (nada de canonicalizar).
A asserção do passkey usa challenge = SHA-256(bytes). Veja protocol/SPEC.md.
"""
import datetime
import hashlib
import json
import re
import time
from dataclasses import dataclass, field

from . import b64, webauthn

VERSION = 1
MAX_PAYLOAD = 8 * 1024

# Comandos que mexem na confiança (tratados aqui, iguais em todo consumidor).
T_ADD_GUARDIAN = "add_guardian"
T_ADD_CREDENTIAL = "add_credential"
T_REMOVE_GUARDIAN = "remove_guardian"
T_REMOVE_CREDENTIAL = "remove_credential"
T_SET_ROLE = "set_role"
TRUST_TYPES = {T_ADD_GUARDIAN, T_ADD_CREDENTIAL, T_REMOVE_GUARDIAN, T_REMOVE_CREDENTIAL, T_SET_ROLE}
# Pedem a assinatura de dois guardiões-mor distintos (se houver dois ou mais) ENQUANTO NÃO EXISTE UM MESTRE (modo antigo).
# Com mestre, quem mexe em guardiões é só ele, sozinho (veja docs/PAPEIS.md).
# set_role não entra: o primeiro mestre nasce com uma assinatura (é a montagem do sistema); depois só um mestre muda papéis.
TWO_SIG_TYPES = {T_REMOVE_GUARDIAN, T_REMOVE_CREDENTIAL}

# Papéis. O papel fica fixado na confiança de cada consumidor, junto com as passkeys (veja docs/PAPEIS.md).
ROLE_MASTER = "master"    # guardião-mestre: inclui e remove guardiões (inclusive outro mestre), sozinho; tem tudo do guardião-mor
ROLE_ADMIN = "admin"      # guardião-mor: tudo, menos incluir e remover guardiões
ROLE_DOMAINS = "domains"  # guardião: domínios e apps
ROLES = {ROLE_MASTER, ROLE_ADMIN, ROLE_DOMAINS}
ADMINISH = {ROLE_MASTER, ROLE_ADMIN}  # papéis com poderes de guardião-mor
# O que um guardião pode assinar (além de add_credential para si mesmo).
DOMAIN_TYPES = {"pihole_allow", "pihole_deny", "pihole_remove", "pihole_batch"}
# Aprovar app novo e revogar app (o que ele mesmo aprovou, pela tela) também são do guardião comum (decisão de 2026-10-16);
# regras, PIN, janelas, pessoas etc. continuam só do guardião-mor.
GUARDIAN_TYPES = DOMAIN_TYPES | {"approve_app", "revoke_app"}
# Vetar (ou desvetar) um site pai: nenhum guardião pode liberar o domínio nem o que está abaixo dele. Só o mestre, sozinho.
T_PARENT_BLOCK = "pihole_parent_block"
# Colocar uma versão de um projeto em produção no Pi: só o mestre, sozinho, dentro do horário dele. O comando leva só o projeto e o hash do
# commit (e a confirmação de que a versão mexe em áreas de segurança); quem instala é o "deployer" do Pi, que roda como root e confere tudo de novo.
T_DEPLOY = "deploy"
# Instalar ou atualizar um app no aparelho (também o próprio NotToday): só o mestre. O comando leva o pacote e o SHA-256 do APK; o aparelho baixa
# o arquivo do gateway, confere o hash (e o certificado do app) e instala em silêncio como Device Owner. Um APK sem comando assinado nunca é instalado.
T_INSTALL_APP = "install_app"
EXECUTOR_MASTER_TYPES = {T_PARENT_BLOCK, T_DEPLOY}   # os que o executor do Pi executa
MASTER_TYPES = EXECUTOR_MASTER_TYPES | {T_INSTALL_APP}
MAX_APK_BYTES = 150 * 1024 * 1024
_PKG = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def check_install_args(args: dict) -> None:
    """pkg (nome do pacote Android), sha256 e size do APK; version_name e version_code são opcionais e só informativos."""
    if not isinstance(args, dict) or set(args) - {"pkg", "sha256", "size", "version_name", "version_code"}:
        raise CommandError("argumentos da instalação inválidos")
    if not isinstance(args.get("pkg"), str) or len(args["pkg"]) > 200 or not _PKG.match(args["pkg"]):
        raise CommandError("pacote inválido")
    if not isinstance(args.get("sha256"), str) or not _SHA256.match(args["sha256"]):
        raise CommandError("sha256 inválido")
    sz = args.get("size")
    if not isinstance(sz, int) or isinstance(sz, bool) or not 1 <= sz <= MAX_APK_BYTES:
        raise CommandError("tamanho do APK inválido")
    if "version_name" in args and (not isinstance(args["version_name"], str) or len(args["version_name"]) > 40):
        raise CommandError("versão inválida")
    vc = args.get("version_code")
    if "version_code" in args and (not isinstance(vc, int) or isinstance(vc, bool) or vc < 1):
        raise CommandError("version_code inválido")


def check_deploy_args(args: dict) -> None:
    """project (nome do projeto no registro do Pi), commit (hash completo) e sensitive_ok (o mestre viu o aviso de segurança)."""
    if not isinstance(args, dict) or set(args) - {"project", "commit", "sensitive_ok"}:
        raise CommandError("argumentos do deploy inválidos")
    if not isinstance(args.get("project"), str) or not _PROJECT.match(args["project"]):
        raise CommandError("projeto inválido")
    if not isinstance(args.get("commit"), str) or not _COMMIT.match(args["commit"]):
        raise CommandError("commit inválido: use o hash completo")
    if "sensitive_ok" in args and not isinstance(args["sensitive_ok"], bool):
        raise CommandError("sensitive_ok inválido")

# Comandos para o agente do Windows (o computador deixa de ter senha de administrador na mão de quem o usa).
# Só guardião-mor ou mestre, com uma passkey; o guardião comum fica só com domínios. Veja docs/AGENTE.md.
T_WIN_INSTALL = "win_install"   # instalar um programa: pacote do winget, ou instalador por link com SHA-256
T_WIN_RUN = "win_run"           # rodar um script do PowerShell como administrador, uma vez
WIN_TYPES = {T_WIN_INSTALL, T_WIN_RUN}
WIN_MAX_AGE_S = 7 * 24 * 3600   # um comando aprovado e não executado (agente desligado) deixa de valer depois de `not_after`
WIN_MAX_SCRIPT_BYTES = 6000
WIN_MAX_ARGS = 200
_WINGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{1,100}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WIN_PATH = re.compile(r"^[A-Za-z]:\\[^<>\"|?*]+$")
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


def _win_text(args: dict, key: str, lo: int, hi: int, required: bool = True) -> str:
    v = args.get(key)
    if v is None and not required:
        return ""
    if not isinstance(v, str) or not lo <= len(v) <= hi or any(ord(c) < 32 for c in v):
        raise CommandError(f"campo '{key}' inválido")
    return v


def check_win_request(type_: str, args: dict) -> None:
    """Valida o que o programa ou script faz (o que a pessoa pede e o guardião aprova). Sem a validade (`not_after`)."""
    if not isinstance(args, dict):
        raise CommandError("argumentos inválidos")
    if type_ == T_WIN_INSTALL:
        _win_text(args, "name", 1, 80)
        ti = args.get("timeout_s")
        if ti is not None and (not isinstance(ti, int) or isinstance(ti, bool) or not 60 <= ti <= 3600):
            raise CommandError("tempo limite da instalação de 60 s a 1 h")
        idle = args.get("idle_s")   # desistir se o instalador ficar parado (sem CPU nem disco) por tanto tempo; 0 desliga
        if idle is not None and (not isinstance(idle, int) or isinstance(idle, bool) or not (idle == 0 or 30 <= idle <= 1800)):
            raise CommandError("tempo parado de 30 s a 30 min, ou 0 para desligar")
        source = args.get("source")
        if source == "winget":
            if not _WINGET_ID.match(_win_text(args, "id", 3, 101)):
                raise CommandError("id do winget inválido")
            if args.get("version") is not None and not _VERSION.match(_win_text(args, "version", 1, 41)):
                raise CommandError("versão inválida")
        elif source == "url":
            url = _win_text(args, "url", 12, 500)
            m = re.match(r"^https://([^/?#:@\s]+)(/[^\s]*)?$", url)
            if not m or not _HOST.match(m.group(1).lower()):
                raise CommandError("o instalador precisa de um endereço https com nome de domínio")
            if not _SHA256.match(_win_text(args, "sha256", 64, 64)):
                raise CommandError("sha256 inválido (64 caracteres hexadecimais em minúsculas)")
            if args.get("kind") not in ("msi", "exe"):
                raise CommandError("tipo do instalador deve ser msi ou exe")
            _win_text(args, "args", 0, WIN_MAX_ARGS, required=False)
        elif source == "file":
            # Um instalador que já está no computador (baixado antes). O agente o copia para uma pasta protegida ANTES de conferir o hash,
            # então trocar o arquivo depois da aprovação não adianta. `publisher` (opcional) exige assinatura digital válida desse nome.
            path = _win_text(args, "path", 4, 400)
            if not _WIN_PATH.match(path) or ".." in path.replace("/", "\\").split("\\"):
                raise CommandError("caminho inválido (use um caminho completo com letra de unidade, como C:\\Users\\...)")
            ext = path.lower().rsplit(".", 1)[-1]
            if ext not in ("msi", "exe") or args.get("kind") != ext:
                raise CommandError("o arquivo precisa ser .msi ou .exe e o tipo tem de combinar com a extensão")
            if not _SHA256.match(_win_text(args, "sha256", 64, 64)):
                raise CommandError("sha256 inválido (64 caracteres hexadecimais em minúsculas)")
            _win_text(args, "args", 0, WIN_MAX_ARGS, required=False)
            if args.get("publisher") is not None:
                _win_text(args, "publisher", 1, 120)
        else:
            raise CommandError("origem do programa inválida")
    elif type_ == T_WIN_RUN:
        if args.get("shell", "powershell") != "powershell":
            raise CommandError("só PowerShell")
        script = args.get("script")
        if not isinstance(script, str) or not script.strip() or "\x00" in script or len(script.encode("utf-8")) > WIN_MAX_SCRIPT_BYTES:
            raise CommandError(f"script inválido (até {WIN_MAX_SCRIPT_BYTES} bytes)")
        _win_text(args, "name", 0, 80, required=False)
        t = args.get("timeout_s", 600)
        if not isinstance(t, int) or isinstance(t, bool) or not 5 <= t <= 3600:
            raise CommandError("tempo limite de 5 s a 1 h")
    else:
        raise CommandError("comando do Windows desconhecido")


def check_win_args(type_: str, args: dict, now: float | None = None, creating: bool = False) -> None:
    """Valida o comando inteiro. `creating`: o gateway ao receber (a validade tem de estar no futuro e dentro de 7 dias);
    senão é o agente ao executar (só confere que ainda não venceu)."""
    check_win_request(type_, args)
    now = time.time() if now is None else now
    na = args.get("not_after")
    if not isinstance(na, int) or isinstance(na, bool):
        raise CommandError("falta a validade do comando (not_after)")
    if na < now:
        raise CommandError("o comando venceu (not_after)")
    if creating and na > now + WIN_MAX_AGE_S:
        raise CommandError("validade longe demais (no máximo 7 dias)")


class CommandError(ValueError):
    pass


def check_window(w) -> dict | None:
    """Janela de horário de um guardião: {days: [0..6, segunda=0], from: min, to: min, utc_offset_min}. None = sem janela.

    O fuso é um deslocamento fixo (Brasil não tem horário de verão desde 2019): igual no Python, no Kotlin e sem banco de fusos."""
    if w is None:
        return None
    try:
        days, a, b, off = w["days"], w["from"], w["to"], w["utc_offset_min"]
        ok = (isinstance(days, list) and days and all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in days)
              and all(isinstance(x, int) and not isinstance(x, bool) for x in (a, b, off)) and 0 <= a < b <= 1440 and -840 <= off <= 840)
    except (KeyError, TypeError):
        ok = False
    if not ok:
        raise CommandError("janela de horário inválida")
    return {"days": sorted(set(days)), "from": a, "to": b, "utc_offset_min": off}


def in_window(w: dict | None, now_s: float) -> bool:
    if not w:
        return True
    t = datetime.datetime.fromtimestamp(now_s + w["utc_offset_min"] * 60, datetime.timezone.utc)
    return t.weekday() in w["days"] and w["from"] <= t.hour * 60 + t.minute < w["to"]


@dataclass
class Guardian:
    name: str
    creds: dict[str, str] = field(default_factory=dict)  # credId (b64url) -> SPKI (b64url)
    role: str = ROLE_ADMIN                                # pareamentos antigos (sem papel) são de guardiões-mor
    allow_sync: bool = True                               # False: só passkey presa ao aparelho (flag BE ausente). Definido na criação.
    window: dict | None = None                            # horário em que os comandos deste guardião valem. Definido na criação.


@dataclass
class Trust:
    """Guardiões em quem este consumidor confia + o contexto WebAuthn."""
    rp_id: str
    origin: str
    guardians: dict[str, Guardian] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"rp_id": self.rp_id, "origin": self.origin,
                "guardians": {g: {"name": v.name, "creds": v.creds, "role": v.role, "allow_sync": v.allow_sync, "window": v.window}
                              for g, v in self.guardians.items()}}

    @staticmethod
    def from_json(d: dict) -> "Trust":
        return Trust(d["rp_id"], d["origin"],
                     {g: Guardian(v["name"], dict(v["creds"]), _role(v.get("role", ROLE_ADMIN)),
                                  _bool(v.get("allow_sync", True)), check_window(v.get("window")))
                      for g, v in d.get("guardians", {}).items()})

    def admins(self) -> set:
        """Guardiões com poderes de guardião-mor (inclui o mestre)."""
        return {g for g, v in self.guardians.items() if v.role in ADMINISH}

    def masters(self) -> set:
        return {g for g, v in self.guardians.items() if v.role == ROLE_MASTER}


def _bool(b) -> bool:
    if not isinstance(b, bool):
        raise CommandError("valor lógico inválido")
    return b


def _role(r) -> str:
    if r not in ROLES:
        raise CommandError("papel inválido")
    return r


@dataclass
class Verified:
    cmd: dict
    payload: bytes
    signers: set


def challenge_of(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def parse_payload(payload: bytes) -> dict:
    if len(payload) > MAX_PAYLOAD:
        raise CommandError("comando grande demais")
    try:
        cmd = json.loads(payload)
    except ValueError as e:
        raise CommandError("comando não é JSON") from e
    if not isinstance(cmd, dict) or cmd.get("v") != VERSION:
        raise CommandError("versão do comando não suportada")
    for k, t in (("dev", str), ("guardian", str), ("type", str), ("args", dict)):
        if not isinstance(cmd.get(k), t):
            raise CommandError(f"campo '{k}' ausente ou inválido")
    ctr = cmd.get("ctr")
    if not isinstance(ctr, int) or isinstance(ctr, bool) or ctr < 1:
        raise CommandError("contador inválido")
    return cmd


def verify_sigs(trust: Trust, payload: bytes, sigs: list) -> set:
    """Confere cada assinatura contra os passkeys conhecidos. Devolve os guardiões que assinaram."""
    if not isinstance(sigs, list) or not 1 <= len(sigs) <= 4:
        raise CommandError("assinaturas ausentes")
    challenge = challenge_of(payload)
    signers = set()
    for s in sigs:
        try:
            gid, cred = s["guardian"], s["cred"]
            g = trust.guardians[gid]
            spki = b64.dec(g.creds[cred])
            webauthn.verify_assertion(
                spki, b64.dec(s["authenticatorData"]), b64.dec(s["clientDataJSON"]), b64.dec(s["signature"]),
                challenge, trust.rp_id, trust.origin, allow_sync=g.allow_sync)
        except (KeyError, TypeError, ValueError) as e:  # WebAuthnError é ValueError
            raise CommandError(f"assinatura recusada: {e}") from e
        signers.add(gid)
    return signers


def required_signers(trust: Trust, cmd: dict) -> int:
    """Quantos guardiões-mor precisam assinar. Se o autor é o mestre, ele basta; senão vale o modo antigo (dois, se houver dois)."""
    author = trust.guardians.get(cmd["guardian"])
    if author is not None and author.role == ROLE_MASTER:
        return 1
    return 2 if cmd["type"] in TWO_SIG_TYPES and len(trust.admins()) >= 2 else 1


def check_author(trust: Trust, cmd: dict, now: float | None = None) -> Guardian:
    """O autor pode mandar este comando agora? (papel e janela de horário; o quórum é conferido à parte)

    A janela de horário do autor vale na hora em que QUEM CONSOME o comando o recebe, pelo relógio dele (não o do navegador).
    Guardião: domínios, aprovar app e passkey nova para si mesmo."""
    author = trust.guardians.get(cmd["guardian"])
    if author is None:
        raise CommandError("autor desconhecido")
    if not in_window(author.window, time.time() if now is None else now):
        raise CommandError("fora da janela de horário deste guardião")
    t = cmd["type"]
    if t in GUARDIAN_TYPES:
        return author
    if t == T_ADD_CREDENTIAL and cmd["args"].get("id") == cmd["guardian"]:
        return author  # qualquer guardião inclui passkey para si mesmo
    if author.role not in ADMINISH:
        raise CommandError("o guardião não pode mandar este comando")
    if t in MASTER_TYPES and author.role != ROLE_MASTER:
        raise CommandError("só o guardião-mestre veta sites, coloca versões em produção e instala apps")
    if t in TRUST_TYPES and author.role != ROLE_MASTER:
        tg = trust.guardians.get(cmd["args"].get("id"))
        target = tg.role if tg else None
        promotion = t == T_SET_ROLE and cmd["args"].get("role") == ROLE_MASTER
        # Sem mestre: modo antigo, e a única mudança de papel possível é promover um guardião-mor a mestre.
        # (Com mestre, a promoção que ainda está em andamento nos outros destinos continua valendo: o alvo já é mestre aqui.)
        if trust.masters():
            if not (promotion and target == ROLE_MASTER):
                raise CommandError("só o guardião-mestre inclui, remove ou muda guardiões")
        elif t == T_SET_ROLE and not (promotion and target == ROLE_ADMIN):
            raise CommandError("sem mestre, só dá para promover um guardião-mor a mestre")
    return author


def authorize(trust: Trust, cmd: dict, signers: set, now: float | None = None) -> None:
    author = check_author(trust, cmd, now)
    if cmd["type"] in GUARDIAN_TYPES or author.role not in ADMINISH:
        return
    if len(signers & trust.admins()) < required_signers(trust, cmd):
        raise CommandError("faltam assinaturas de outro guardião-mor")


def verify_envelope(trust: Trust, env: dict, now: float | None = None) -> Verified:
    """Criptografia e quórum. O contador e o aparelho de destino são conferidos por quem tem estado (Consumer)."""
    if not isinstance(env, dict):
        raise CommandError("envelope inválido")
    try:
        payload = b64.dec(env["payload"])
    except (KeyError, ValueError) as e:
        raise CommandError("payload inválido") from e
    cmd = parse_payload(payload)
    signers = verify_sigs(trust, payload, env.get("sigs"))
    if cmd["guardian"] not in signers:
        raise CommandError("o autor do comando não assinou")
    authorize(trust, cmd, signers, now)
    return Verified(cmd, payload, signers)


class Consumer:
    """Estado de quem recebe comandos: confiança fixada, contador por guardião e destino (`dev`).

    O aparelho (Kotlin) reproduz isto; aqui é a referência e é o que o executor usa.
    """

    def __init__(self, dev: str, trust: Trust, last_ctr: dict | None = None):
        self.dev = dev
        self.trust = trust
        self.last_ctr: dict[str, int] = dict(last_ctr or {})

    def accept(self, env: dict, now: float | None = None) -> Verified:
        v = verify_envelope(self.trust, env, now)
        if v.cmd["dev"] != self.dev:
            raise CommandError("comando de outro destino")
        gid = v.cmd["guardian"]
        if v.cmd["ctr"] <= self.last_ctr.get(gid, 0):
            raise CommandError("contador repetido (replay)")
        self.last_ctr[gid] = v.cmd["ctr"]
        return v

    def apply_trust(self, cmd: dict) -> None:
        """Aplica add_guardian / add_credential / remove_guardian já aceitos."""
        a, t = cmd["args"], cmd["type"]
        try:
            if t == T_ADD_GUARDIAN:
                gid = a["id"]
                if gid in self.trust.guardians:
                    raise CommandError("guardião já existe")
                self.trust.guardians[gid] = Guardian(str(a["name"])[:64], {a["cred"]: a["spki"]}, _role(a["role"]),
                                                     _bool(a["allow_sync"]), check_window(a.get("window")))
            elif t == T_ADD_CREDENTIAL:
                self.trust.guardians[a["id"]].creds[a["cred"]] = a["spki"]
            elif t == T_REMOVE_CREDENTIAL:
                g = self.trust.guardians.get(a["id"])
                if g is None or a["cred"] not in g.creds:
                    raise CommandError("passkey inexistente")
                if len(g.creds) <= 1:
                    raise CommandError("não remove a última passkey: remova o guardião")
                del g.creds[a["cred"]]
            elif t == T_REMOVE_GUARDIAN:
                if a["id"] not in self.trust.guardians:
                    raise CommandError("guardião inexistente")
                if self.trust.admins() == {a["id"]}:
                    raise CommandError("não remove o último guardião-mor")
                if self.trust.masters() == {a["id"]}:
                    raise CommandError("não remove o último mestre")
                del self.trust.guardians[a["id"]]
                self.last_ctr.pop(a["id"], None)
            elif t == T_SET_ROLE:
                g = self.trust.guardians.get(a["id"])
                role = _role(a["role"])
                if g is None:
                    raise CommandError("guardião inexistente")
                if self.trust.masters() == {a["id"]} and role != ROLE_MASTER:
                    raise CommandError("não rebaixa o último mestre")
                g.role = role
            else:
                raise CommandError("não é comando de confiança")
        except KeyError as e:
            raise CommandError(f"argumento ausente: {e}") from e

    def to_json(self) -> dict:
        return {"dev": self.dev, "trust": self.trust.to_json(), "last_ctr": self.last_ctr}

    @staticmethod
    def from_json(d: dict) -> "Consumer":
        return Consumer(d["dev"], Trust.from_json(d["trust"]), d.get("last_ctr"))
