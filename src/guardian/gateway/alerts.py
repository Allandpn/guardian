"""Avisos aos guardiões: transições de estado dos aparelhos e pedidos novos, enviados por Web Push."""
import json
import sys
import time

from ..protocol import b64
from . import webpush

SILENT_S = 300
MAX_PER_MINUTE = 30
LOOSEN_KINDS = {"SETTINGS": "afrouxar configurações", "RELEASE": "remover o Device Owner",
                "MAINTENANCE": "janela de manutenção", "GUARDIAN": "remover guardião"}


class Alerts:
    """`evaluate()` compara o estado atual com o anterior e devolve os avisos novos. A 1ª rodada só memoriza (sem avisos)."""

    def __init__(self, store, now=time.time):
        self.store, self.now = store, now
        self.state: dict[str, dict] = {}
        self.seen_requests: set[int] | None = None
        self.seen_awaiting: set[int] | None = None

    def evaluate(self) -> list[dict]:
        notes: list[dict] = []
        now = int(self.now())
        names = {}
        for d in self.store.devices():
            names[d["id"]] = d["name"]
            name = d["name"]
            st = self.state.setdefault(d["id"], {"silent": None, "filter": None, "apps": None, "pend": None, "pihole": None})
            r = json.loads(d["report"]) if d["report"] else {}
            if not isinstance(r, dict):
                r = {}
            silent = now - (d["last_seen"] or d["created"]) > SILENT_S
            if st["silent"] is not None and silent != st["silent"]:
                notes.append(self._note(f"silent:{d['id']}", "Aparelho sem sinal" if silent else "Aparelho voltou",
                                        f"{name} não consulta o gateway há mais de {SILENT_S // 60} min" if silent else f"{name} voltou a responder"))
            st["silent"] = silent

            if d["kind"] == "device":
                fa = r.get("filterActive")
                if isinstance(fa, bool):
                    if st["filter"] is not None and fa != st["filter"]:
                        why = str(r.get("filterReason", ""))[:120]
                        notes.append(self._note(f"filter:{d['id']}", "Filtro caiu" if not fa else "Filtro voltou",
                                                f"{name}: {why}" if not fa else f"{name}: filtro confirmado"))
                    st["filter"] = fa
                apps = {a["pkg"]: a for a in r.get("pendingApps", []) if isinstance(a, dict) and isinstance(a.get("pkg"), str)}
                if st["apps"] is not None:
                    for pkg in sorted(set(apps) - st["apps"]):
                        a = apps[pkg]
                        risks = a.get("risks") if isinstance(a.get("risks"), list) else []
                        notes.append(self._note(f"app:{d['id']}:{pkg}", "App novo pendente",
                                                f"{name}: {str(a.get('label') or pkg)[:60]}" + (" ⚠ " + ", ".join(map(str, risks[:3])) if risks else "")))
                st["apps"] = set(apps)
                pend = {(str(p.get("kind")), str(p.get("summary", ""))) for p in r.get("pending", []) if isinstance(p, dict)}
                if st["pend"] is not None:
                    for kind, summary in sorted(pend - st["pend"]):
                        notes.append(self._note(f"pend:{d['id']}:{kind}", "Pedido de afrouxar",
                                                f"{name}: {LOOSEN_KINDS.get(kind, kind)} — {summary[:100]}"))
                st["pend"] = pend
            elif d["kind"] == "executor":
                ok = r.get("pihole_ok")
                if isinstance(ok, bool):
                    if st["pihole"] is not None and ok != st["pihole"]:
                        notes.append(self._note(f"pihole:{d['id']}", "Pi-hole inacessível" if not ok else "Pi-hole voltou",
                                                f"{name}: " + (str(r.get("pihole_error", ""))[:120] if not ok else "respondendo")))
                    st["pihole"] = ok

        reqs = {q["id"]: q for q in self.store.requests_open()}
        if self.seen_requests is not None:
            for rid in sorted(set(reqs) - self.seen_requests):
                q = reqs[rid]
                notes.append(self._note(f"req:{rid}", "Pedido do usuário", f"{names.get(q['dev'], q['dev'])}: [{q['kind']}] {q['text'][:120]}"))
        self.seen_requests = set(reqs)

        aw = {c["id"]: c for c in self.store.awaiting()}
        if self.seen_awaiting is not None:
            for cid in sorted(set(aw) - self.seen_awaiting):
                c = aw[cid]
                try:
                    kind = json.loads(b64.dec(json.loads(c["envelope"])["payload"])).get("type", "?")
                except (ValueError, KeyError, TypeError):
                    kind = "?"
                n = self._note(f"cosign:{cid}", "Co-assinatura pendente", f"{names.get(c['dev'], c['dev'])}: {kind}")
                n["exclude"] = c["guardian"]
                notes.append(n)
        self.seen_awaiting = set(aw)
        return notes

    @staticmethod
    def _note(tag: str, title: str, body: str) -> dict:
        return {"tag": tag, "title": title, "body": body, "exclude": None}


class Notifier:
    def __init__(self, store, vapid_priv, subject: str, allow_any_endpoint: bool = False, send=webpush.send):
        self.store, self.vapid, self.subject = store, vapid_priv, subject
        self.allow_any, self.send = allow_any_endpoint, send
        self._window: list[float] = []

    def _budget(self) -> bool:
        t = time.monotonic()
        self._window = [x for x in self._window if t - x < 60]
        if len(self._window) >= MAX_PER_MINUTE:
            return False
        self._window.append(t)
        return True

    def notify(self, notes: list[dict], guardian: str | None = None) -> int:
        sent = 0
        for n in notes:
            payload = {"title": n["title"], "body": n["body"], "tag": n["tag"], "url": "/"}
            for s in self.store.push_subs(guardian=guardian, exclude=n.get("exclude")):
                if not self._budget():
                    return sent
                try:
                    self.send({"endpoint": s["endpoint"], "p256dh": s["p256dh"], "auth": s["auth"]}, payload, self.vapid,
                              self.subject, allow_any_endpoint=self.allow_any)
                    sent += 1
                except webpush.PushGone:
                    self.store.delete_push(s["endpoint"])
                except Exception as e:  # um serviço de push fora do ar não pode derrubar o resto
                    print("push falhou:", type(e).__name__, str(e)[:100], file=sys.stderr)
        return sent
