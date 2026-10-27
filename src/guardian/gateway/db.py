"""Armazenamento SQLite do gateway. Só dados públicos: chaves públicas, fila e relatórios."""
import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS guardians(id TEXT PRIMARY KEY, name TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS credentials(cred TEXT PRIMARY KEY, guardian TEXT NOT NULL, spki TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS invites(hash TEXT PRIMARY KEY, kind TEXT NOT NULL, guardian TEXT, name TEXT, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pairings(hash TEXT PRIMARY KEY, kind TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, spki TEXT NOT NULL,
  created INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0, report TEXT, report_ts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY AUTOINCREMENT, dev TEXT NOT NULL, guardian TEXT NOT NULL,
  ctr INTEGER NOT NULL, envelope TEXT NOT NULL, status TEXT NOT NULL, ready_seq INTEGER, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS commands_dev ON commands(dev, status, ready_seq);
CREATE TABLE IF NOT EXISTS ctrs(dev TEXT NOT NULL, guardian TEXT NOT NULL, last INTEGER NOT NULL, PRIMARY KEY(dev, guardian));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, dev TEXT, ts INTEGER NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS push_subs(endpoint TEXT PRIMARY KEY, guardian TEXT NOT NULL, p256dh TEXT NOT NULL,
  auth TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, dev TEXT NOT NULL, ts INTEGER NOT NULL,
  kind TEXT NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open');
CREATE TABLE IF NOT EXISTS blocked(dev TEXT NOT NULL, domain TEXT NOT NULL, src TEXT NOT NULL, list TEXT NOT NULL DEFAULT '',
  cname INTEGER NOT NULL DEFAULT 0, count INTEGER NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, PRIMARY KEY(dev, domain));
CREATE INDEX IF NOT EXISTS blocked_last ON blocked(dev, last);
CREATE TABLE IF NOT EXISTS queried(dev TEXT NOT NULL, domain TEXT NOT NULL, count INTEGER NOT NULL, blocked INTEGER NOT NULL,
  first INTEGER NOT NULL, last INTEGER NOT NULL, PRIMARY KEY(dev, domain));
CREATE INDEX IF NOT EXISTS queried_last ON queried(dev, last);
CREATE TABLE IF NOT EXISTS net_clients(id TEXT PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS app_refusals(dev TEXT NOT NULL, pkg TEXT NOT NULL, ts INTEGER NOT NULL, guardian TEXT NOT NULL, PRIMARY KEY(dev, pkg));
CREATE TABLE IF NOT EXISTS app_approvals(dev TEXT NOT NULL, pkg TEXT NOT NULL, guardian TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(dev, pkg));
CREATE TABLE IF NOT EXISTS app_vetos(dev TEXT NOT NULL, pkg TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', guardian TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(dev, pkg));
CREATE TABLE IF NOT EXISTS allow_origins(domain TEXT NOT NULL, dev TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(domain, dev));
CREATE TABLE IF NOT EXISTS apks(sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS apk_grants(dev TEXT NOT NULL, sha256 TEXT NOT NULL, pkg TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(dev, sha256));
CREATE TABLE IF NOT EXISTS app_asks(dev TEXT NOT NULL, pkg TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(dev, pkg));
CREATE TABLE IF NOT EXISTS analyses(dev TEXT NOT NULL, ctr INTEGER NOT NULL, ts INTEGER NOT NULL, status TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '', PRIMARY KEY(dev, ctr));
CREATE TABLE IF NOT EXISTS request_domains(rid INTEGER NOT NULL, domain TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open',
  ttl_s INTEGER, by TEXT, ts INTEGER NOT NULL, PRIMARY KEY(rid, domain));
"""

AUDIT_MAX = 5000
REQUESTS_MAX = 200
DELIVERED_KEEP_S = 7 * 24 * 3600
BLOCKED_KEEP_S = 24 * 3600
BLOCKED_MAX_PER_DEV = 1000
REQUEST_DOMAINS_MAX = 20


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)
            for table, col in (("guardians", "role TEXT NOT NULL DEFAULT 'admin'"), ("guardians", "see TEXT NOT NULL DEFAULT '{}'"),
                               ("invites", "role TEXT NOT NULL DEFAULT 'admin'"),
                               ("guardians", "allow_sync INTEGER NOT NULL DEFAULT 1"), ("guardians", "window TEXT NOT NULL DEFAULT ''"),
                               ("invites", "allow_sync INTEGER NOT NULL DEFAULT 1"), ("invites", "window TEXT NOT NULL DEFAULT ''"),
                               ("credentials", "be INTEGER NOT NULL DEFAULT 0"),
                               ("requests", "payload TEXT NOT NULL DEFAULT ''")):
                try:  # bancos criados antes dos papéis
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col}")
                except sqlite3.OperationalError:
                    pass
            # liberações de pedidos que já existiam: de qual aparelho veio cada uma
            self.db.execute("INSERT OR IGNORE INTO allow_origins(domain,dev,ts) SELECT rd.domain, r.dev, MAX(rd.ts) FROM request_domains rd "
                            "JOIN requests r ON r.id=rd.rid WHERE rd.state='allowed' GROUP BY rd.domain, r.dev")

    def q(self, sql: str, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def one(self, sql: str, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args=()):
        with self.lock:
            return self.db.execute(sql, args)

    # --- guardiões e credenciais -----------------------------------------------
    def guardian_count(self) -> int:
        return self.one("SELECT COUNT(*) c FROM guardians")["c"]

    def add_guardian(self, gid: str, name: str, cred: str, spki: str, role: str = "admin", be: bool = False,
                     allow_sync: bool = True, window: dict | None = None):
        with self.lock:
            self.db.execute("BEGIN")
            try:
                self.db.execute("INSERT INTO guardians(id,name,created,role,allow_sync,window) VALUES(?,?,?,?,?,?)",
                                (gid, name, int(time.time()), role, 1 if allow_sync else 0, json.dumps(window) if window else ""))
                self.db.execute("INSERT INTO credentials(cred,guardian,spki,created,be) VALUES(?,?,?,?,?)",
                                (cred, gid, spki, int(time.time()), 1 if be else 0))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def add_credential(self, gid: str, cred: str, spki: str, be: bool = False):
        self.x("INSERT INTO credentials(cred,guardian,spki,created,be) VALUES(?,?,?,?,?)", (cred, gid, spki, int(time.time()), 1 if be else 0))

    def credentials_of(self, gid: str):
        return self.q("SELECT cred, created, be FROM credentials WHERE guardian=? ORDER BY created", (gid,))

    def delete_credential(self, gid: str, cred: str) -> bool:
        """Tira uma passkey do gateway. Nunca a última do guardião."""
        with self.lock:
            if self.one("SELECT COUNT(*) c FROM credentials WHERE guardian=?", (gid,))["c"] <= 1:
                return False
            return self.db.execute("DELETE FROM credentials WHERE guardian=? AND cred=?", (gid, cred)).rowcount == 1

    def credential(self, cred: str):
        return self.one("SELECT * FROM credentials WHERE cred=?", (cred,))

    def trust_dict(self) -> dict:
        """{gid: {name, creds:{cred: spki}}} do que o gateway conhece."""
        out = {r["id"]: {"name": r["name"], "creds": {}, "role": r["role"], "allow_sync": bool(r["allow_sync"]),
                         "window": json.loads(r["window"]) if r["window"] else None}
               for r in self.q("SELECT * FROM guardians ORDER BY created")}
        for r in self.q("SELECT * FROM credentials ORDER BY created"):
            if r["guardian"] in out:
                out[r["guardian"]]["creds"][r["cred"]] = r["spki"]
        return out

    def guardian(self, gid: str):
        return self.one("SELECT * FROM guardians WHERE id=?", (gid,))

    def admin_count(self) -> int:
        return self.one("SELECT COUNT(*) c FROM guardians WHERE role IN ('admin','master')")["c"]

    def master_count(self) -> int:
        return self.one("SELECT COUNT(*) c FROM guardians WHERE role='master'")["c"]

    def set_role(self, gid: str, role: str) -> None:
        self.x("UPDATE guardians SET role=? WHERE id=?", (role, gid))

    def set_see(self, gid: str, see: dict):
        self.x("UPDATE guardians SET see=? WHERE id=?", (json.dumps(see), gid))

    def delete_guardian(self, gid: str):
        with self.lock:
            self.db.execute("DELETE FROM credentials WHERE guardian=?", (gid,))
            self.db.execute("DELETE FROM push_subs WHERE guardian=?", (gid,))
            self.db.execute("DELETE FROM guardians WHERE id=?", (gid,))

    # --- convites e pareamentos ---------------------------------------------------
    def put_invite(self, h: str, kind: str, guardian: str | None, name: str | None, expires: int, role: str = "admin",
                   allow_sync: bool = True, window: dict | None = None):
        self.x("DELETE FROM invites WHERE expires<?", (int(time.time()),))
        self.x("INSERT INTO invites(hash,kind,guardian,name,expires,role,allow_sync,window) VALUES(?,?,?,?,?,?,?,?)",
               (h, kind, guardian, name, expires, role, 1 if allow_sync else 0, json.dumps(window) if window else ""))

    def invite(self, h: str):
        return self.one("SELECT * FROM invites WHERE hash=? AND expires>?", (h, int(time.time())))

    def consume_invite(self, h: str) -> bool:
        return self.x("DELETE FROM invites WHERE hash=? AND expires>?", (h, int(time.time()))).rowcount == 1

    def put_pairing(self, h: str, kind: str, expires: int):
        self.x("DELETE FROM pairings WHERE expires<?", (int(time.time()),))
        self.x("INSERT INTO pairings VALUES(?,?,?)", (h, kind, expires))

    def consume_pairing(self, h: str, kind: str) -> bool:
        return self.x("DELETE FROM pairings WHERE hash=? AND kind=? AND expires>?", (h, kind, int(time.time()))).rowcount == 1

    # --- aparelhos ----------------------------------------------------------------
    def add_device(self, dev: str, kind: str, name: str, spki: str):
        self.x("INSERT INTO devices(id,kind,name,spki,created) VALUES(?,?,?,?,?)", (dev, kind, name, spki, int(time.time())))

    def device(self, dev: str):
        return self.one("SELECT * FROM devices WHERE id=?", (dev,))

    def devices(self):
        return self.q("SELECT d.*, (SELECT COUNT(*) FROM commands c WHERE c.dev=d.id AND c.status IN ('ready','awaiting')) AS pending "
                      "FROM devices d ORDER BY d.created")

    def forget_device(self, dev: str):
        with self.lock:
            for t in ("commands", "ctrs", "requests", "blocked", "queried", "apk_grants", "allow_origins", "app_vetos", "app_refusals", "app_approvals", "app_asks"):
                self.db.execute(f"DELETE FROM {t} WHERE dev=?", (dev,))
            self.db.execute("DELETE FROM request_domains WHERE rid NOT IN (SELECT id FROM requests)")
            self.db.execute("DELETE FROM devices WHERE id=?", (dev,))

    def save_report(self, dev: str, report: dict):
        now = int(time.time())
        self.x("UPDATE devices SET report=?, report_ts=?, last_seen=? WHERE id=?", (json.dumps(report), now, now, dev))

    def touch(self, dev: str):
        self.x("UPDATE devices SET last_seen=? WHERE id=?", (int(time.time()), dev))

    # --- comandos -----------------------------------------------------------------
    def last_ctr(self, dev: str, guardian: str) -> int:
        r = self.one("SELECT last FROM ctrs WHERE dev=? AND guardian=?", (dev, guardian))
        return r["last"] if r else 0

    def pending_count(self, dev: str) -> int:
        return self.one("SELECT COUNT(*) c FROM commands WHERE dev=? AND status IN ('ready','awaiting')", (dev,))["c"]

    def _next_seq(self) -> int:
        return self.one("SELECT COALESCE(MAX(ready_seq),0)+1 n FROM commands")["n"]

    def enqueue(self, dev: str, guardian: str, ctr: int, envelope: dict, ready: bool) -> int | None:
        """Grava o comando se o contador avança. Devolve o id, ou None se o contador é repetido."""
        with self.lock:
            if ctr <= self.last_ctr(dev, guardian):
                return None
            self.db.execute("INSERT INTO ctrs VALUES(?,?,?) ON CONFLICT(dev,guardian) DO UPDATE SET last=excluded.last",
                            (dev, guardian, ctr))
            cur = self.db.execute(
                "INSERT INTO commands(dev,guardian,ctr,envelope,status,ready_seq,created) VALUES(?,?,?,?,?,?,?)",
                (dev, guardian, ctr, json.dumps(envelope), "ready" if ready else "awaiting",
                 self._next_seq() if ready else None, int(time.time())))
            return cur.lastrowid

    def command(self, cid: int):
        return self.one("SELECT * FROM commands WHERE id=?", (cid,))

    def awaiting(self):
        return self.q("SELECT * FROM commands WHERE status='awaiting' ORDER BY id")

    def make_ready(self, cid: int, envelope: dict):
        with self.lock:
            self.db.execute("UPDATE commands SET envelope=?, status='ready', ready_seq=? WHERE id=? AND status='awaiting'",
                            (json.dumps(envelope), self._next_seq(), cid))

    def ready_after(self, dev: str, after: int, limit: int = 50):
        return self.q("SELECT id, ready_seq, envelope FROM commands WHERE dev=? AND status='ready' AND ready_seq>? "
                      "ORDER BY ready_seq LIMIT ?", (dev, after, limit))

    def purge(self):
        cutoff = int(time.time()) - DELIVERED_KEEP_S
        self.x("DELETE FROM commands WHERE created<?", (cutoff,))
        self.x("DELETE FROM blocked WHERE last<?", (int(time.time()) - BLOCKED_KEEP_S,))
        self.x("DELETE FROM queried WHERE last<?", (int(time.time()) - BLOCKED_KEEP_S,))
        self.x("DELETE FROM net_clients WHERE id NOT IN (SELECT dev FROM blocked) AND id NOT IN (SELECT dev FROM queried)")
        self.x("DELETE FROM requests WHERE status<>'open' AND ts<?", (cutoff,))
        self.x("DELETE FROM request_domains WHERE rid NOT IN (SELECT id FROM requests)")
        self.x("DELETE FROM app_refusals WHERE ts<?", (int(time.time()) - 90 * 24 * 3600,))
        self.x("DELETE FROM app_asks WHERE ts<?", (int(time.time()) - 30 * 24 * 3600,))
        self.x("DELETE FROM app_approvals WHERE ts<?", (int(time.time()) - 365 * 24 * 3600,))
        self.x("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT ?)", (AUDIT_MAX,))

    # --- meta e inscrições de push ------------------------------------------------
    def meta_get(self, k: str) -> str | None:
        r = self.one("SELECT v FROM meta WHERE k=?", (k,))
        return r["v"] if r else None

    def meta_set(self, k: str, v: str):
        self.x("INSERT INTO meta VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    def add_push(self, endpoint: str, guardian: str, p256dh: str, auth: str, keep: int = 5):
        with self.lock:
            self.db.execute("INSERT INTO push_subs VALUES(?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET "
                            "guardian=excluded.guardian, p256dh=excluded.p256dh, auth=excluded.auth",
                            (endpoint, guardian, p256dh, auth, int(time.time())))
            self.db.execute("DELETE FROM push_subs WHERE guardian=? AND endpoint NOT IN "
                            "(SELECT endpoint FROM push_subs WHERE guardian=? ORDER BY created DESC, rowid DESC LIMIT ?)",
                            (guardian, guardian, keep))

    def delete_push(self, endpoint: str, guardian: str | None = None):
        if guardian:
            self.x("DELETE FROM push_subs WHERE endpoint=? AND guardian=?", (endpoint, guardian))
        else:
            self.x("DELETE FROM push_subs WHERE endpoint=?", (endpoint,))

    def push_subs(self, guardian: str | None = None, exclude: str | None = None):
        if guardian:
            return self.q("SELECT * FROM push_subs WHERE guardian=?", (guardian,))
        if exclude:
            return self.q("SELECT * FROM push_subs WHERE guardian<>?", (exclude,))
        return self.q("SELECT * FROM push_subs")

    # --- auditoria e pedidos ---------------------------------------------------------
    def record_approval(self, dev: str, pkg: str, gid: str) -> None:
        self.x("INSERT INTO app_approvals(dev,pkg,guardian,ts) VALUES(?,?,?,?) ON CONFLICT(dev,pkg) DO UPDATE SET guardian=excluded.guardian, ts=excluded.ts",
               (dev, pkg, gid, int(time.time())))
        self.x("DELETE FROM app_refusals WHERE dev=? AND pkg=?", (dev, pkg))
        self.x("DELETE FROM app_asks WHERE dev=? AND pkg=?", (dev, pkg))

    def ask_app(self, dev: str, pkg: str) -> None:
        """A pessoa pediu de novo a liberação de um app suspenso: ele volta às solicitações dos guardiões."""
        self.x("INSERT INTO app_asks(dev,pkg,ts) VALUES(?,?,?) ON CONFLICT(dev,pkg) DO UPDATE SET ts=excluded.ts", (dev, pkg, int(time.time())))
        self.x("DELETE FROM app_refusals WHERE dev=? AND pkg=?", (dev, pkg))

    def asked_apps(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for r in self.q("SELECT dev, pkg FROM app_asks WHERE ts>?", (int(time.time()) - 14 * 24 * 3600,)):
            out.setdefault(r["dev"], set()).add(r["pkg"])
        return out

    def veto_app(self, dev: str, pkg: str, label: str, gid: str) -> None:
        """Veto permanente de um app: ninguém o aprova nem o pede até o guardião-mor tirar o veto."""
        self.x("INSERT INTO app_vetos(dev,pkg,label,guardian,ts) VALUES(?,?,?,?,?) ON CONFLICT(dev,pkg) DO UPDATE SET label=excluded.label, guardian=excluded.guardian, ts=excluded.ts",
               (dev, pkg, label, gid, int(time.time())))
        self.x("DELETE FROM app_refusals WHERE dev=? AND pkg=?", (dev, pkg))
        self.x("DELETE FROM app_asks WHERE dev=? AND pkg=?", (dev, pkg))

    def unveto_app(self, dev: str, pkg: str) -> None:
        self.x("DELETE FROM app_vetos WHERE dev=? AND pkg=?", (dev, pkg))

    def is_app_vetoed(self, dev: str, pkg: str) -> bool:
        return bool(self.one("SELECT 1 FROM app_vetos WHERE dev=? AND pkg=?", (dev, pkg)))

    def app_vetos(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for r in self.q("SELECT dev, pkg, label, guardian, ts FROM app_vetos ORDER BY ts DESC"):
            out.setdefault(r["dev"], {})[r["pkg"]] = {"label": r["label"], "by": r["guardian"], "ts": r["ts"]}
        return out

    def refused_of(self, dev: str) -> list[str]:
        return [r["pkg"] for r in self.q("SELECT pkg FROM app_refusals WHERE dev=? ORDER BY ts DESC", (dev,))]

    def drop_approval(self, dev: str, pkg: str) -> None:
        self.x("DELETE FROM app_approvals WHERE dev=? AND pkg=?", (dev, pkg))

    def approvals_by(self, gid: str):
        return self.q("SELECT dev, pkg, ts FROM app_approvals WHERE guardian=? ORDER BY ts DESC LIMIT 200", (gid,))

    def denied_by(self, gid: str, since: int, limit: int = 100):
        """Domínios que o guardião recusou (mais recente primeiro, um por aparelho e domínio)."""
        rows = self.q("SELECT r.dev AS dev, rd.domain AS domain, MAX(rd.ts) AS ts FROM request_domains rd JOIN requests r ON r.id=rd.rid "
                      "WHERE rd.by=? AND rd.state='denied' AND rd.ts>? GROUP BY r.dev, rd.domain ORDER BY ts DESC LIMIT ?", (gid, since, limit))
        return rows

    def refuse_app(self, dev: str, pkg: str, gid: str) -> None:
        self.x("INSERT INTO app_refusals(dev,pkg,ts,guardian) VALUES(?,?,?,?) ON CONFLICT(dev,pkg) DO UPDATE SET ts=excluded.ts, guardian=excluded.guardian",
               (dev, pkg, int(time.time()), gid))

    def unrefuse_app(self, dev: str, pkg: str) -> None:
        self.x("DELETE FROM app_refusals WHERE dev=? AND pkg=?", (dev, pkg))

    def app_marks(self) -> tuple[dict, dict]:
        """({aparelho: {pacote: guardião que aprovou}}, {aparelho: {pacote: guardião que recusou}})."""
        ok: dict[str, dict] = {}
        no: dict[str, dict] = {}
        for r in self.q("SELECT dev, pkg, guardian FROM app_approvals"):
            ok.setdefault(r["dev"], {})[r["pkg"]] = r["guardian"]
        for r in self.q("SELECT dev, pkg, guardian FROM app_refusals"):
            no.setdefault(r["dev"], {})[r["pkg"]] = r["guardian"]
        return ok, no

    def refused_apps(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for r in self.q("SELECT dev, pkg FROM app_refusals ORDER BY ts DESC"):
            out.setdefault(r["dev"], []).append(r["pkg"])
        return out

    def audit(self, dev: str | None, kind: str, text: str):
        self.x("INSERT INTO audit(dev,ts,kind,text) VALUES(?,?,?,?)", (dev, int(time.time()), kind, text[:300]))

    def audit_list(self, limit: int):
        return self.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    def add_request(self, dev: str, kind: str, text: str, payload: str = "") -> bool:
        with self.lock:
            if self.one("SELECT COUNT(*) c FROM requests WHERE status='open'")["c"] >= REQUESTS_MAX:
                return False
            self.db.execute("INSERT INTO requests(dev,ts,kind,text,payload) VALUES(?,?,?,?,?)", (dev, int(time.time()), kind, text[:500], payload))
            return True

    def admin_requests_open(self, dev: str) -> int:
        return self.one("SELECT COUNT(*) c FROM requests WHERE dev=? AND kind IN ('install','command') AND status='open'", (dev,))["c"]

    def device_admin_requests(self, dev: str, limit: int = 20):
        """Pedidos de instalação e de comando do computador, com o estado (open, approved, denied)."""
        return [{"id": r["id"], "ts": r["ts"], "kind": r["kind"], "text": r["text"], "status": r["status"]}
                for r in self.q("SELECT * FROM requests WHERE dev=? AND kind IN ('install','command') ORDER BY id DESC LIMIT ?", (dev, limit))]

    def set_request_status(self, rid: int, status: str):
        self.x("UPDATE requests SET status=? WHERE id=?", (status, rid))

    def requests_open(self):
        return self.q("SELECT * FROM requests WHERE status='open' ORDER BY id DESC")

    def dismiss_request(self, rid: int):
        self.x("UPDATE requests SET status='done' WHERE id=?", (rid,))

    # --- bloqueios e pedidos de liberação ---------------------------------------------
    def merge_blocked(self, dev: str, items: list[dict]) -> None:
        """Soma as contagens recebidas do executor e mantém só os BLOCKED_MAX_PER_DEV mais recentes."""
        with self.lock:
            self.db.execute("BEGIN")
            try:
                for it in items:
                    self.db.execute(
                        "INSERT INTO blocked(dev,domain,src,list,cname,count,first,last) VALUES(?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(dev,domain) DO UPDATE SET count=count+excluded.count, last=MAX(last,excluded.last), "
                        "first=MIN(first,excluded.first), src=excluded.src, list=excluded.list, cname=excluded.cname",
                        (dev, it["domain"], it["src"], it["list"], it["cname"], it["count"], it["first"], it["last"]))
                self.db.execute("DELETE FROM blocked WHERE dev=? AND last<?", (dev, int(time.time()) - BLOCKED_KEEP_S))
                self.db.execute("DELETE FROM blocked WHERE dev=? AND domain NOT IN "
                                "(SELECT domain FROM blocked WHERE dev=? ORDER BY last DESC LIMIT ?)", (dev, dev, BLOCKED_MAX_PER_DEV))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def merge_queried(self, dev: str, items: list[dict]) -> None:
        """Soma as consultas recebidas (todas, não só bloqueios) e mantém só os BLOCKED_MAX_PER_DEV domínios mais recentes."""
        with self.lock:
            self.db.execute("BEGIN")
            try:
                for it in items:
                    self.db.execute(
                        "INSERT INTO queried(dev,domain,count,blocked,first,last) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(dev,domain) DO UPDATE SET count=count+excluded.count, blocked=blocked+excluded.blocked, "
                        "last=MAX(last,excluded.last), first=MIN(first,excluded.first)",
                        (dev, it["domain"], it["count"], it["blocked"], it["first"], it["last"]))
                self.db.execute("DELETE FROM queried WHERE dev=? AND last<?", (dev, int(time.time()) - BLOCKED_KEEP_S))
                self.db.execute("DELETE FROM queried WHERE dev=? AND domain NOT IN "
                                "(SELECT domain FROM queried WHERE dev=? ORDER BY last DESC LIMIT ?)", (dev, dev, BLOCKED_MAX_PER_DEV))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def queried_list(self, dev: str | None = None, per_dev: int = 300):
        """As consultas mais recentes de cada aparelho (ou só de um), do mais novo para o mais antigo."""
        sql = ("SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY dev ORDER BY last DESC) rn FROM queried WHERE last>=?"
               + (" AND dev=?" if dev else "") + ") WHERE rn<=? ORDER BY last DESC")
        return self.q(sql, [int(time.time()) - BLOCKED_KEEP_S] + ([dev] if dev else []) + [per_dev if not dev else BLOCKED_MAX_PER_DEV])

    # --- APKs: o Pi os entrega ao gateway; o aparelho só baixa o que um comando install_app assinado citou -------------
    def add_apk(self, sha256: str, size: int) -> None:
        self.x("INSERT INTO apks(sha256,size,ts) VALUES(?,?,?) ON CONFLICT(sha256) DO UPDATE SET ts=excluded.ts", (sha256, size, int(time.time())))

    def apk_hashes(self) -> list[str]:
        return [r["sha256"] for r in self.q("SELECT sha256 FROM apks")]

    def grant_apk(self, dev: str, sha256: str, pkg: str) -> None:
        self.x("INSERT INTO apk_grants(dev,sha256,pkg,ts) VALUES(?,?,?,?) ON CONFLICT(dev,sha256) DO UPDATE SET ts=excluded.ts", (dev, sha256, pkg, int(time.time())))

    def apk_granted(self, dev: str, sha256: str) -> bool:
        return bool(self.one("SELECT 1 FROM apk_grants WHERE dev=? AND sha256=?", (dev, sha256)))

    def prune_apks(self, keep: int) -> list[str]:
        """Guarda só os `keep` APKs mais recentes (os que ainda têm uma instalação autorizada para um aparelho ficam). Devolve os apagados."""
        rows = self.q("SELECT sha256 FROM apks WHERE sha256 NOT IN (SELECT sha256 FROM apk_grants WHERE ts>?) ORDER BY ts DESC", (int(time.time()) - 7 * 86400,))
        drop = [r["sha256"] for r in rows][keep:]
        for h in drop:
            self.x("DELETE FROM apks WHERE sha256=?", (h,))
        return drop

    def note_origin(self, domain: str, dev: str) -> None:
        """Guarda para qual aparelho (ou cliente da rede) uma liberação foi feita; a lista de Liberados mostra isso."""
        self.x("INSERT INTO allow_origins(domain,dev,ts) VALUES(?,?,?) ON CONFLICT(domain,dev) DO UPDATE SET ts=excluded.ts", (domain, dev, int(time.time())))
        self.x("DELETE FROM allow_origins WHERE rowid IN (SELECT rowid FROM allow_origins ORDER BY ts DESC LIMIT -1 OFFSET 20000)")

    def allow_origins(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for r in self.q("SELECT domain, dev FROM allow_origins ORDER BY ts DESC"):
            out.setdefault(r["domain"], []).append(r["dev"])
        return out

    def clear_history(self, what: str, dev: str | None = None) -> int:
        """Zera o histórico guardado no gateway ('blocked', 'queried' ou 'both'), de um aparelho ou de todos. Não toca no Pi-hole."""
        n = 0
        with self.lock:
            for t in (("blocked", "queried") if what == "both" else (what,)):
                cur = self.db.execute(f"DELETE FROM {t}" + (" WHERE dev=?" if dev else ""), (dev,) if dev else ())
                n += cur.rowcount
        self.x("DELETE FROM net_clients WHERE id NOT IN (SELECT dev FROM blocked) AND id NOT IN (SELECT dev FROM queried)")
        return n

    def put_net_client(self, id_: str, name: str, ip: str) -> None:
        """Cliente da rede que não é aparelho pareado: o Pi-hole o vê (nome e IP), mas ele não tem passkey nem pede liberação."""
        self.x("INSERT INTO net_clients(id,name,ip,seen) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, ip=excluded.ip, seen=excluded.seen",
               (id_, name, ip, int(time.time())))

    def net_clients(self):
        return self.q("SELECT id, name, ip FROM net_clients ORDER BY name")

    def drop_blocked(self, dev: str, domains: list[str]) -> None:
        """Apaga bloqueios guardados (o executor vetou estes domínios: não podem ser liberados, então não viram pedido)."""
        if domains:
            with self.lock:
                self.db.executemany("DELETE FROM blocked WHERE dev=? AND domain=?", [(dev, d) for d in domains])

    # --- análise por IA das instalações (advisor.py) ---------------------------------------
    def analysis_claim(self, dev: str, ctr: int, now: int) -> bool:
        """Reserva a análise desta execução (uma só por execução). False se já existe."""
        with self.lock:
            cur = self.db.execute("INSERT OR IGNORE INTO analyses(dev,ctr,ts,status) VALUES(?,?,?,'pending')", (dev, ctr, now))
            return cur.rowcount == 1

    def analysis_done(self, dev: str, ctr: int, status: str, model: str, result: str) -> None:
        self.x("UPDATE analyses SET status=?, model=?, result=?, ts=? WHERE dev=? AND ctr=?", (status, model, result[:6000], int(time.time()), dev, ctr))

    def analyses_called_since(self, ts: int) -> int:
        """Quantas consultas à IA foram feitas desde `ts` (as puladas por limite não contam)."""
        return self.one("SELECT COUNT(*) c FROM analyses WHERE ts>=? AND status IN ('done','error','pending') AND model!='regras locais'", (ts,))["c"]

    def analyses_for(self, dev: str | None = None, limit: int = 20):
        rows = self.q("SELECT * FROM analyses WHERE (?1 IS NULL OR dev=?1) ORDER BY ts DESC LIMIT ?2", (dev, limit))
        out = []
        for r in rows:
            try:
                res = json.loads(r["result"]) if r["result"] else None
            except ValueError:
                res = None
            out.append({"dev": r["dev"], "ctr": r["ctr"], "ts": r["ts"], "status": r["status"], "result": res})
        return out

    def blocked_pairs(self, limit: int = 20000):
        """Todos os (aparelho, domínio) guardados: o executor confere quais não podem mais ser pedidos (veto)."""
        return self.q("SELECT dev, domain FROM blocked WHERE last>=? LIMIT ?", (int(time.time()) - BLOCKED_KEEP_S, limit))

    def blocked_list(self, dev: str | None = None, src: str | None = None, limit: int = 500):
        sql, args = "SELECT * FROM blocked WHERE last>=?", [int(time.time()) - BLOCKED_KEEP_S]
        if dev:
            sql += " AND dev=?"
            args.append(dev)
        if src:
            sql += " AND src=?"
            args.append(src)
        return self.q(sql + " ORDER BY last DESC LIMIT ?", args + [limit])

    def blocked_list_each(self, src: str | None = None, per_dev: int = 300):
        """Os bloqueios mais recentes de CADA aparelho (até per_dev), do mais novo para o mais antigo. Um aparelho muito barulhento
        não empurra os outros para fora do limite."""
        sql = ("SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY dev ORDER BY last DESC) rn FROM blocked WHERE last>=?"
               + (" AND src=?" if src else "") + ") WHERE rn<=? ORDER BY last DESC")
        args = [int(time.time()) - BLOCKED_KEEP_S] + ([src] if src else []) + [per_dev]
        return self.q(sql, args)

    def blocked_has(self, dev: str, domain: str) -> bool:
        return self.one("SELECT 1 FROM blocked WHERE dev=? AND domain=? AND last>=?",
                        (dev, domain, int(time.time()) - BLOCKED_KEEP_S)) is not None

    def blocked_under(self, dev: str, domain: str, src: str | None = None) -> bool:
        """O domínio foi bloqueado ou é o pai de algo bloqueado (cloudlinks.cn para advertise.cloudlinks.cn).
        `domain` já vem normalizado (letras, dígitos, hífen e ponto), então não tem curinga de LIKE.
        Com `src`, só conta o bloqueio dessa origem ('own' = regra própria; 'list' = lista de bloqueio)."""
        sql, args = "SELECT 1 FROM blocked WHERE dev=? AND (domain=? OR domain LIKE ?) AND last>=?", [dev, domain, "%." + domain, int(time.time()) - BLOCKED_KEEP_S]
        if src:
            sql += " AND src=?"
            args.append(src)
        return self.one(sql, tuple(args)) is not None

    def add_unblock_request(self, dev: str, domains: list[str]) -> int | None:
        """Cria o pedido com os domínios que ainda não têm pedido aberto. None se nada novo ou se há pedidos demais."""
        with self.lock:
            if self.one("SELECT COUNT(*) c FROM requests WHERE status='open'")["c"] >= REQUESTS_MAX:
                return None
            fresh = [d for d in domains if not self.one(
                "SELECT 1 FROM request_domains rd JOIN requests r ON r.id=rd.rid "
                "WHERE r.dev=? AND rd.domain=? AND rd.state='open'", (dev, d))]
            if not fresh:
                return 0
            now = int(time.time())
            cur = self.db.execute("INSERT INTO requests(dev,ts,kind,text) VALUES(?,?,?,?)",
                                  (dev, now, "unblock", ("liberar: " + ", ".join(fresh))[:500]))
            for d in fresh:
                self.db.execute("INSERT INTO request_domains(rid,domain,ts) VALUES(?,?,?)", (cur.lastrowid, d, now))
            return cur.lastrowid

    def request_items(self, rid: int):
        return self.q("SELECT * FROM request_domains WHERE rid=? ORDER BY domain", (rid,))

    def request(self, rid: int):
        return self.one("SELECT * FROM requests WHERE id=?", (rid,))

    def resolve_domains(self, rid: int, states: dict[str, tuple[str, int | None]], by: str) -> None:
        """states: {domínio: (estado, ttl_s)}. Fecha o pedido quando nenhum domínio sobra aberto."""
        with self.lock:
            for d, (state, ttl) in states.items():
                self.db.execute("UPDATE request_domains SET state=?, ttl_s=?, by=?, ts=? WHERE rid=? AND domain=? AND state='open'",
                                (state, ttl, by, int(time.time()), rid, d))
            if not self.one("SELECT 1 FROM request_domains WHERE rid=? AND state='open'", (rid,)):
                self.db.execute("UPDATE requests SET status='done' WHERE id=?", (rid,))

    def fail_allowed(self, dev: str, doms: list) -> None:
        """O executor não aplicou estes domínios: o que o pedido mostrava como liberado passa a 'failed'."""
        with self.lock:
            for d in doms:
                if isinstance(d, str):
                    self.db.execute("UPDATE request_domains SET state='failed' WHERE state='allowed' AND domain=? AND ts>? AND rid IN "
                                    "(SELECT id FROM requests WHERE dev=?)", (d.strip().lower(), int(time.time()) - 3600, dev))

    def cancel_request(self, rid: int, dev: str) -> bool:
        with self.lock:
            if not self.one("SELECT 1 FROM requests WHERE id=? AND dev=? AND status='open'", (rid, dev)):
                return False
            self.db.execute("UPDATE request_domains SET state='cancelled', ts=? WHERE rid=? AND state='open'", (int(time.time()), rid))
            self.db.execute("UPDATE requests SET status='done' WHERE id=?", (rid,))
            return True

    def device_requests(self, dev: str, limit: int = 20):
        rows = self.q("SELECT * FROM requests WHERE dev=? AND kind='unblock' ORDER BY id DESC LIMIT ?", (dev, limit))
        return [{"id": r["id"], "ts": r["ts"], "status": r["status"],
                 "items": [{"domain": i["domain"], "state": i["state"], "ttl_s": i["ttl_s"]} for i in self.request_items(r["id"])]}
                for r in rows]
