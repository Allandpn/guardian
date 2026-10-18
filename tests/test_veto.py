import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, pair  # noqa: E402
from guardian.executor.veto import Veto, suffixes  # noqa: E402
from guardian.protocol import commands as cmds  # noqa: E402
from test_executor import pairing_string  # noqa: E402

NOW = float(int(time.time()))


def make_gravity(path, rows):
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE gravity (domain TEXT NOT NULL, adlist_id INTEGER NOT NULL)")
    c.executemany("INSERT INTO gravity VALUES (?, 1)", [(r,) for r in rows])
    c.commit()
    c.close()


ROWS = ["pornhub.com", "||adulto.example^", "sexy.globo.example", "||*.curinga^", "sozinho", "UPPER.Example", "x y.com"]


class VetoUnit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "gravity.db")
        make_gravity(self.path, ROWS)

    def tearDown(self):
        self.tmp.cleanup()

    def test_suffixes(self):
        self.assertEqual(suffixes("a.b.c.com"), ["a.b.c.com", "b.c.com", "c.com"])
        self.assertEqual(suffixes("c.com"), ["c.com"])

    def test_listed_and_children_are_vetoed(self):
        v = Veto(self.path)
        self.assertIn("nas listas", v.reason("pornhub.com"))
        self.assertIn("nas listas", v.reason("cdn.pornhub.com"))          # filho de domínio listado
        self.assertIn("nas listas", v.reason("x.y.adulto.example"))       # ABP cobre subdomínios
        self.assertIn("nas listas", v.reason("upper.example"))            # caixa não importa
        self.assertIn("nas listas", v.reason("sexy.globo.example"))
        for ok in ("google.com", "pornhub.com.evil.net", "exemplo.org"):
            self.assertIsNone(v.reason(ok), ok)

    def test_parent_covering_listed_domain_is_vetoed_only_in_regex_mode(self):
        v = Veto(self.path)
        self.assertIn("cobre", v.reason("globo.example", True))
        self.assertIn("cobre", v.reason("www.globo.example", True))       # a regra do executor tira o www.
        self.assertIsNone(v.reason("globo.example", False))               # liberação exata só cobre ela mesma
        self.assertIsNone(v.reason("outro.globo.example", True))

    def test_junk_lines_are_ignored(self):
        v = Veto(self.path)
        v.refresh()
        self.assertEqual(v.listed, {"pornhub.com", "adulto.example", "sexy.globo.example", "upper.example"})

    def test_reloads_when_the_file_changes(self):
        v = Veto(self.path)
        self.assertIsNone(v.reason("novo.example"))
        make_gravity(self.path, ["novo.example"])
        os.utime(self.path, (time.time() + 5, time.time() + 5))
        self.assertIn("nas listas", v.reason("novo.example"))
        self.assertIsNone(v.reason("pornhub.com"))

    def test_unreadable_gravity_refuses_but_keeps_last_good_index(self):
        v = Veto(os.path.join(self.tmp.name, "nao-existe.db"))
        self.assertIn("indisponíveis", v.reason("qualquer.example"))      # nunca carregou: recusa em vez de liberar às cegas
        w = Veto(self.path)
        self.assertIn("nas listas", w.reason("pornhub.com"))
        os.remove(self.path)
        self.assertIn("nas listas", w.reason("pornhub.com"))              # arquivo sumiu: vale o último índice bom

    def test_disabled_without_a_path(self):
        v = Veto(None)
        self.assertFalse(v.enabled)
        self.assertIsNone(v.reason("pornhub.com"))

    def test_master_parents_cover_the_site_and_below(self):
        v = Veto(None)
        self.assertTrue(v.add_parent("WWW.Reddit.com"))
        self.assertFalse(v.add_parent("reddit.com"))
        self.assertEqual(v.parents, ["reddit.com"])
        for bad in ("reddit.com", "old.reddit.com", "a.b.reddit.com"):
            self.assertIn("vetado pelo mestre", v.reason(bad), bad)
        for ok in ("reddit.com.evil.net", "notreddit.com", "redd.it"):
            self.assertIsNone(v.reason(ok), ok)
        for bad_input in ("com", "co.uk", "", "*.x.com"):
            with self.assertRaises(ValueError):
                v.add_parent(bad_input)
        self.assertTrue(v.remove_parent("reddit.com"))
        self.assertFalse(v.remove_parent("reddit.com"))
        self.assertIsNone(v.reason("old.reddit.com"))


class ProtocolRole(unittest.TestCase):
    def test_only_the_master_may_veto_a_site(self):
        trust = cmds.Trust("rp", "https://rp", {
            "m": cmds.Guardian("Mestre", {}, cmds.ROLE_MASTER), "a": cmds.Guardian("Mor", {}, cmds.ROLE_ADMIN),
            "d": cmds.Guardian("Guardião", {}, cmds.ROLE_DOMAINS)})
        cmd = lambda g: {"guardian": g, "type": cmds.T_PARENT_BLOCK, "args": {"action": "add", "domain": "reddit.com"}}
        self.assertEqual(cmds.check_author(trust, cmd("m")).name, "Mestre")
        for g in ("a", "d"):
            with self.assertRaises(cmds.CommandError):
                cmds.check_author(trust, cmd(g))
        cmds.authorize(trust, cmd("m"), {"m"})  # um mestre basta (sem co-assinatura)


class ExecutorVeto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.fake = FakePihole()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.grav = os.path.join(cls.tmp.name, "gravity.db")
        make_gravity(cls.grav, ROWS)
        cls.k1, cls.d1 = cls.env.pair_device(cls.c)
        cls.cfg = ExecConfig(cls.tmp.name, cls.fake.url, "senha-app", "canario.example", allow_mode="regex", gravity_db=cls.grav)
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "executor"})
        pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]))
        cls.ex = Executor(cls.cfg, now=lambda: NOW)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.fake.close()
        cls.tmp.cleanup()

    def cmd(self, type_, args):
        return {"type": type_, "args": args, "guardian": self.gid}

    def rx_allowed(self):
        return {e["domain"] for e in self.ex._entries("allow")}

    def test_01_allow_is_vetoed_for_adult_lists_and_parents(self):
        for d in ("pornhub.com", "cdn.pornhub.com", "globo.example"):
            with self.assertRaisesRegex(ValueError, "vetado"):
                self.ex.apply(self.cmd("pihole_allow", {"domain": d}))
        self.assertEqual(self.rx_allowed(), set())
        self.ex.apply(self.cmd("pihole_allow", {"domain": "escola.example"}))
        self.assertEqual(self.rx_allowed(), {"escola.example"})

    def test_02_deny_and_remove_are_never_vetoed(self):
        self.ex.apply(self.cmd("pihole_deny", {"domain": "pornhub.com"}))
        self.ex.apply(self.cmd("pihole_remove", {"list": "deny", "domain": "pornhub.com"}))

    def test_03_batch_refuses_only_the_vetoed_items(self):
        out = self.ex.apply(self.cmd("pihole_batch", {"items": [{"domain": "lote-bom.example"}, {"domain": "x.adulto.example"}]}))
        self.assertIn("lote-bom.example", self.rx_allowed())
        self.assertNotIn("x.adulto.example", self.rx_allowed())
        self.assertIn("vetado", out)

    def test_04_master_parent_list_persists_and_is_enforced(self):
        self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "add", "domain": "reddit.com"}))
        with self.assertRaisesRegex(ValueError, "vetado pelo mestre"):
            self.ex.apply(self.cmd("pihole_allow", {"domain": "old.reddit.com"}))
        again = Executor(self.cfg, now=lambda: NOW)                       # reinício
        self.assertEqual(again.veto.parents, ["reddit.com"])
        with self.assertRaises(ValueError):
            self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "add", "domain": "com"}))
        with self.assertRaises(ValueError):
            self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "talvez", "domain": "x.com"}))
        self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "remove", "domain": "reddit.com"}))
        self.ex.apply(self.cmd("pihole_allow", {"domain": "old.reddit.com"}))
        self.assertIn("old.reddit.com", self.rx_allowed())

    def test_04b_many_sites_in_one_command(self):
        out = self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "add", "domains": ["Discord.com", "x.com", "WWW.t.me", "com", "x.com"]}))
        self.assertIn("vetados: discord.com, x.com, t.me", out)
        self.assertIn("já estavam vetados: x.com", out)               # repetido na mesma lista
        self.assertIn("falharam: com", out)
        self.assertEqual(self.ex.veto.parents, ["discord.com", "x.com", "t.me"])
        for bad in ({"action": "add", "domains": []}, {"action": "add", "domains": "x.com"}, {"action": "add", "domains": ["a.com"] * 81},
                    {"action": "add", "domains": ["com", "net"]}):
            with self.assertRaises(ValueError, msg=str(bad)[:40]):
                self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, bad))
        out = self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "remove", "domains": ["discord.com", "x.com", "t.me", "nao-vetado.com"]}))
        self.assertIn("vetos removidos: discord.com, x.com, t.me", out)
        self.assertIn("não estavam vetados: nao-vetado.com", out)
        self.assertEqual(self.ex.veto.parents, [])

    def test_05_audit_lists_allowances_the_lists_would_veto_today(self):
        self.fake.lists["allow"]["cdn.pornhub.com"] = ""                   # liberada antes de a lista conhecer o domínio
        rep = self.ex._veto_report(self.ex._entries("allow"))
        self.assertTrue(rep["on"])
        self.assertIn("cdn.pornhub.com", {x["domain"] for x in rep["audit"]})
        self.assertNotIn("escola.example", {x["domain"] for x in rep["audit"]})
        self.assertEqual(rep["audit_total"], len(rep["audit"]))

    def test_06_vetoed_domains_do_not_become_requests_and_old_ones_vanish(self):
        k, d = self.k1, self.d1
        st, r, _ = self.env.client().signed(k, "POST", f"/v1/devices/{d}/report", {"kind": "device", "tsIps": ["100.64.0.7"]})
        self.assertEqual(st, 200, r)
        q = lambda t, dom: {"time": t, "domain": dom, "status": "REGEX", "client": {"ip": "100.64.0.7"}}
        off = Executor(ExecConfig(self.tmp.name, self.fake.url, "senha-app", "canario.example", allow_mode="regex"), now=lambda: NOW)  # sem veto
        self.fake.queries += [q(NOW - 40, "cdn.pornhub.com"), q(NOW - 39, "bom.example")]
        off.state.data["blocked_since"] = 0
        off.collect_blocks()
        got = lambda: {i["domain"] for i in self.env.client().signed(k, "GET", f"/v1/devices/{d}/blocked")[1]["items"]}
        self.assertEqual(got(), {"cdn.pornhub.com", "bom.example"})
        self.ex.state.data["blocked_since"] = 0
        self.fake.queries += [q(NOW - 20, "cdn.pornhub.com"), q(NOW - 19, "globo.example"), q(NOW - 18, "outro.example")]
        self.ex.collect_blocks()
        self.assertEqual(got(), {"bom.example", "outro.example"})


    def test_07_sweep_removes_stored_blocks_that_became_vetoed(self):
        k, d = self.k1, self.d1
        got = lambda: {i["domain"] for i in self.env.client().signed(k, "GET", f"/v1/devices/{d}/blocked")[1]["items"]}
        off = Executor(ExecConfig(self.tmp.name, self.fake.url, "senha-app", "canario.example", allow_mode="regex"), now=lambda: NOW)  # sem veto
        self.fake.queries.append({"time": NOW - 5, "domain": "cdn.vetar-depois.example", "status": "REGEX", "client": {"ip": "100.64.0.7"}})
        off.state.data["blocked_since"] = 0
        off.collect_blocks()
        self.assertIn("cdn.vetar-depois.example", got())
        self.ex.sweep_vetoed()
        self.assertIn("cdn.vetar-depois.example", got())                                                              # ainda não vetado: a varredura deixa
        self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "add", "domain": "vetar-depois.example"}))             # o mestre veta o site
        self.assertGreaterEqual(self.ex.sweep_vetoed(), 1)                                                            # ninguém consultou de novo: a varredura apaga
        self.assertNotIn("cdn.vetar-depois.example", got())
        self.assertIn("bom.example", got())                                                                           # o resto fica
        self.ex.apply(self.cmd(cmds.T_PARENT_BLOCK, {"action": "remove", "domain": "vetar-depois.example"}))

    def test_08_only_the_executor_reads_the_index(self):
        st, _, _ = self.env.client().signed(self.k1, "GET", f"/v1/devices/{self.d1}/blocked-index")
        self.assertEqual(st, 403)


if __name__ == "__main__":
    unittest.main()
