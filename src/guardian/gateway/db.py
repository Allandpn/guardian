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
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, dev TEXT NOT NULL, ts INTEGER NOT NULL,
  kind TEXT NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open');
"""

AUDIT_MAX = 5000
REQUESTS_MAX = 200
DELIVERED_KEEP_S = 7 * 24 * 3600


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)

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

    def add_guardian(self, gid: str, name: str, cred: str, spki: str):
        with self.lock:
            self.db.execute("BEGIN")
            try:
                self.db.execute("INSERT INTO guardians VALUES(?,?,?)", (gid, name, int(time.time())))
                self.db.execute("INSERT INTO credentials VALUES(?,?,?,?)", (cred, gid, spki, int(time.time())))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def add_credential(self, gid: str, cred: str, spki: str):
        self.x("INSERT INTO credentials VALUES(?,?,?,?)", (cred, gid, spki, int(time.time())))

    def credential(self, cred: str):
        return self.one("SELECT * FROM credentials WHERE cred=?", (cred,))

    def trust_dict(self) -> dict:
        """{gid: {name, creds:{cred: spki}}} do que o gateway conhece."""
        out = {r["id"]: {"name": r["name"], "creds": {}} for r in self.q("SELECT * FROM guardians ORDER BY created")}
        for r in self.q("SELECT * FROM credentials ORDER BY created"):
            if r["guardian"] in out:
                out[r["guardian"]]["creds"][r["cred"]] = r["spki"]
        return out

    # --- convites e pareamentos ---------------------------------------------------
    def put_invite(self, h: str, kind: str, guardian: str | None, name: str | None, expires: int):
        self.x("DELETE FROM invites WHERE expires<?", (int(time.time()),))
        self.x("INSERT INTO invites VALUES(?,?,?,?,?)", (h, kind, guardian, name, expires))

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
            for t in ("commands", "ctrs", "requests"):
                self.db.execute(f"DELETE FROM {t} WHERE dev=?", (dev,))
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
        self.x("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT ?)", (AUDIT_MAX,))

    # --- auditoria e pedidos ---------------------------------------------------------
    def audit(self, dev: str | None, kind: str, text: str):
        self.x("INSERT INTO audit(dev,ts,kind,text) VALUES(?,?,?,?)", (dev, int(time.time()), kind, text[:300]))

    def audit_list(self, limit: int):
        return self.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    def add_request(self, dev: str, kind: str, text: str) -> bool:
        with self.lock:
            if self.one("SELECT COUNT(*) c FROM requests WHERE status='open'")["c"] >= REQUESTS_MAX:
                return False
            self.db.execute("INSERT INTO requests(dev,ts,kind,text) VALUES(?,?,?,?)", (dev, int(time.time()), kind, text[:500]))
            return True

    def requests_open(self):
        return self.q("SELECT * FROM requests WHERE status='open' ORDER BY id DESC")

    def dismiss_request(self, rid: int):
        self.x("UPDATE requests SET status='done' WHERE id=?", (rid,))
