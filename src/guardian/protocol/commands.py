"""Comandos assinados pelos guardiões e o estado de confiança de quem os recebe.

Um comando são bytes JSON; o `payload` do envelope é o base64url desses bytes exatos (nada de canonicalizar).
A asserção do passkey usa challenge = SHA-256(bytes). Veja protocol/SPEC.md.
"""
import datetime
import hashlib
import json
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
TRUST_TYPES = {T_ADD_GUARDIAN, T_ADD_CREDENTIAL, T_REMOVE_GUARDIAN, T_REMOVE_CREDENTIAL}
# Pedem a assinatura de dois guardiões-mor distintos (se houver dois ou mais).
TWO_SIG_TYPES = {T_REMOVE_GUARDIAN, T_REMOVE_CREDENTIAL}

# Papéis. O papel fica fixado na confiança de cada consumidor, junto com as passkeys (veja docs/PAPEIS.md).
ROLE_ADMIN = "admin"
ROLE_DOMAINS = "domains"
ROLES = {ROLE_ADMIN, ROLE_DOMAINS}
# O que um guardião pode assinar (além de add_credential para si mesmo).
DOMAIN_TYPES = {"pihole_allow", "pihole_deny", "pihole_remove", "pihole_batch"}
# Aprovar app novo também é do guardião comum (decisão de 2026-10-16); revogar, regras, PIN etc. continuam só do guardião-mor.
GUARDIAN_TYPES = DOMAIN_TYPES | {"approve_app"}


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
        return {g for g, v in self.guardians.items() if v.role == ROLE_ADMIN}


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


def required_signers(trust: Trust, cmd_type: str) -> int:
    """Quantos guardiões-mor precisam assinar (comandos de domínio e aprovar app: o autor basta)."""
    return 2 if cmd_type in TWO_SIG_TYPES and len(trust.admins()) >= 2 else 1


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
    if author.role != ROLE_ADMIN:
        if t == T_ADD_CREDENTIAL and cmd["args"].get("id") == cmd["guardian"]:
            return author
        raise CommandError("o guardião não pode mandar este comando")
    return author


def authorize(trust: Trust, cmd: dict, signers: set, now: float | None = None) -> None:
    author = check_author(trust, cmd, now)
    if cmd["type"] in GUARDIAN_TYPES or author.role != ROLE_ADMIN:
        return
    if len(signers & trust.admins()) < required_signers(trust, cmd["type"]):
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
                del self.trust.guardians[a["id"]]
                self.last_ctr.pop(a["id"], None)
            else:
                raise CommandError("não é comando de confiança")
        except KeyError as e:
            raise CommandError(f"argumento ausente: {e}") from e

    def to_json(self) -> dict:
        return {"dev": self.dev, "trust": self.trust.to_json(), "last_ctr": self.last_ctr}

    @staticmethod
    def from_json(d: dict) -> "Consumer":
        return Consumer(d["dev"], Trust.from_json(d["trust"]), d.get("last_ctr"))
