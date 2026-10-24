import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, pair  # noqa: E402
from guardian.protocol import b64  # noqa: E402
from test_executor import pairing_string  # noqa: E402

import time
NOW = float(int(time.time()))


def q(t, domain, status, ip="100.64.0.7", **extra):
    return {"time": t, "domain": domain, "status": status, "client": {"ip": ip}, **extra}


class UnblockFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.fake = FakePihole()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.devkey, cls.dev = cls.env.pair_device(cls.c)
        cls.cfg = ExecConfig(cls.tmp.name, cls.fake.url, "senha-app", "canario.example",
                             clients={"100.64.0.7": cls.dev, "fd7a::7": cls.dev})
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "executor"})
        pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]))
        cls.now = [NOW]
        cls.ex = Executor(cls.cfg, now=lambda: cls.now[0])

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.fake.close()
        cls.tmp.cleanup()

    def blocked(self, src=None):
        qs = f"?src={src}" if src else ""
        st, r, _ = self.env.client().signed(self.devkey, "GET", f"/v1/devices/{self.dev}/blocked{qs}")
        self.assertEqual(st, 200, r)
        return {i["domain"]: i for i in r["items"]}

    def test_01_executor_reports_only_blocked_of_paired_clients(self):
        t = NOW - 60
        self.fake.queries += [
            q(t, "cdn.exemplo.com", "REGEX"), q(t + 1, "cdn.exemplo.com", "DENYLIST"),
            q(t + 2, "ads.tracker.net", "GRAVITY", list_id=7),
            q(t + 3, "permitido.com", "FORWARDED"),
            q(t + 4, "alvo.com", "REGEX_CNAME", cname="cdn.alvo.com", domain_note=1),
            q(t + 5, "de-outro.com", "REGEX", ip="192.168.1.5"),
            q(t + 6, "ipv6.exemplo.org", "REGEX", ip="fd7a::7"),
            q(t + 7, "*.invalido", "REGEX"),
            q(t + 8, "canario.example", "DENYLIST"),  # o canário nunca entra na lista de bloqueios
        ]
        self.assertEqual(self.ex.collect_blocks(), 4)
        got = self.blocked()
        self.assertEqual(set(got), {"cdn.exemplo.com", "ads.tracker.net", "cdn.alvo.com", "ipv6.exemplo.org"})
        self.assertEqual(got["cdn.exemplo.com"]["count"], 2)
        self.assertEqual(got["cdn.exemplo.com"]["src"], "own")
        self.assertEqual(got["ads.tracker.net"]["src"], "list")
        self.assertEqual(got["ads.tracker.net"]["list"], "listas.example")
        self.assertTrue(got["cdn.alvo.com"]["cname"])
        self.assertNotIn("de-outro.com", got)
        self.assertNotIn("canario.example", got)
        self.assertEqual(set(self.blocked("own")), {"cdn.exemplo.com", "cdn.alvo.com", "ipv6.exemplo.org"})

    def test_02_no_double_count_on_next_poll(self):
        self.assertEqual(self.ex.collect_blocks(), 0)
        self.assertEqual(self.blocked()["cdn.exemplo.com"]["count"], 2)
        self.fake.queries.append(q(NOW - 10, "cdn.exemplo.com", "REGEX"))
        self.ex.collect_blocks()
        self.assertEqual(self.blocked()["cdn.exemplo.com"]["count"], 3)

    def test_03_guardian_sees_log_with_filters(self):
        st, r, _ = self.c.call("GET", f"/v1/blocked?dev={self.dev}&src=own")
        self.assertEqual(st, 200)
        self.assertTrue(all(i["src"] == "own" and i["dev"] == self.dev for i in r["items"]))
        self.assertEqual(self.c.call("GET", "/v1/blocked?src=x")[0], 400)
        self.assertEqual(self.c.call("GET", "/v1/blocked?dev=../x")[0], 400)
        self.assertEqual(self.env.client().call("GET", "/v1/blocked")[0], 401)

    def test_04_only_executor_can_post_blocked_and_device_cannot_forge(self):
        body = {"dev": self.dev, "items": [{"domain": "forjado.com", "src": "own", "count": 1, "first": 5, "last": 5}]}
        st, r, _ = self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/blocked", body)
        self.assertEqual(st, 403)
        self.assertNotIn("forjado.com", self.blocked())

    def test_05_request_only_for_observed_domains(self):
        def post(domains):
            return self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/requests",
                                            {"kind": "unblock", "domains": domains})
        self.assertEqual(post(["nunca-visto.com"])[0], 400)
        self.assertEqual(post(["*.x.com"])[0], 400)
        self.assertEqual(post([])[0], 400)
        self.assertEqual(post(["a.com"] * 1 + [f"d{i}.com" for i in range(25)])[0], 400)
        st, r, _ = post(["cdn.exemplo.com", "ipv6.exemplo.org"])
        self.assertEqual(st, 200, r)
        st, r2, _ = post(["cdn.exemplo.com"])  # já existe pedido aberto: não duplica
        self.assertEqual((st, r2["id"]), (200, None))

    def test_06_guardian_resolves_with_one_batch_command(self):
        reqs = self.c.call("GET", "/v1/requests")[1]["items"]
        r = next(x for x in reqs if x["kind"] == "unblock")
        self.assertEqual({i["domain"] for i in r["items"]}, {"cdn.exemplo.com", "ipv6.exemplo.org"})
        ex_dev = self.ex.dev
        (st, resp, _), _ = self.env.sign_post(self.c, self.a, self.gid, ex_dev, "pihole_batch",
                                              {"items": [{"domain": "cdn.exemplo.com"}]})
        self.assertEqual(st, 200, resp)
        st, rr, _ = self.c.call("POST", f"/v1/requests/{r['id']}/resolve", {"cmd": resp["id"], "deny": ["ipv6.exemplo.org"]})
        self.assertEqual(st, 200, rr)
        self.ex.step(wait_s=0)
        self.assertIn("cdn.exemplo.com", self.fake.lists["allow"])
        self.assertNotIn("ipv6.exemplo.org", self.fake.lists["allow"])
        st, rq, _ = self.env.client().signed(self.devkey, "GET", f"/v1/devices/{self.dev}/requests")
        states = {i["domain"]: i["state"] for i in rq["requests"][0]["items"]}
        self.assertEqual(states, {"cdn.exemplo.com": "allowed", "ipv6.exemplo.org": "denied"})
        self.assertEqual(rq["requests"][0]["status"], "done")
        self.assertEqual(self.c.call("POST", f"/v1/requests/{r['id']}/resolve", {"deny": ["x.com"]})[0], 404)

    def test_07_resolve_rejects_foreign_or_wrong_commands(self):
        post = lambda d: self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/requests",  # noqa: E731
                                                  {"kind": "unblock", "domains": d})
        self.assertEqual(post(["cdn.alvo.com"])[0], 200)
        rid = next(x["id"] for x in self.c.call("GET", "/v1/requests")[1]["items"] if x["kind"] == "unblock")
        (st, resp, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.ex.dev, "pihole_allow", {"domain": "ads.tracker.net"})
        self.assertEqual(st, 200)
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/resolve", {"cmd": resp["id"]})[0], 400)  # não é lote
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/resolve", {"cmd": 99999})[0], 400)
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/resolve", {})[0], 400)
        c2, a2, g2 = self.env.register_guardian("Bia")
        (st, other, _), _ = self.env.sign_post(c2, a2, g2, self.ex.dev, "pihole_batch", {"items": [{"domain": "ads.tracker.net"}]})
        self.assertEqual(st, 200)
        self.assertEqual(self.c.call("POST", f"/v1/requests/{rid}/resolve", {"cmd": other["id"]})[0], 400)  # comando de outro guardião
        self.ex.step(wait_s=0)

    def test_07a_list_blocked_domain_cannot_be_requested(self):
        """Domínio bloqueado por lista aparece para o aparelho, mas só o guardião pode liberar (à mão), não por pedido."""
        post = lambda d: self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/requests",  # noqa: E731
                                                  {"kind": "unblock", "domains": d})
        st, r, _ = post(["ads.tracker.net"])
        self.assertEqual(st, 400, r)
        self.assertIn("lista", r["error"])
        self.assertEqual(self.blocked("list")["ads.tracker.net"]["src"], "list")  # continua visível

    def test_08_device_cancels_its_request(self):
        rid = next(x["id"] for x in self.c.call("GET", "/v1/requests")[1]["items"] if x["kind"] == "unblock")
        cl = self.env.client()
        self.assertEqual(cl.signed(self.devkey, "POST", f"/v1/devices/{self.dev}/requests/{rid}/cancel")[0], 200)
        self.assertEqual(cl.signed(self.devkey, "POST", f"/v1/devices/{self.dev}/requests/{rid}/cancel")[0], 404)
        rq = cl.signed(self.devkey, "GET", f"/v1/devices/{self.dev}/requests")[1]["requests"]
        self.assertEqual(next(r for r in rq if r["id"] == rid)["items"][0]["state"], "cancelled")

    def test_09_batch_with_ttl_and_remove_again(self):
        (st, _, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.ex.dev, "pihole_batch",
                                           {"items": [{"domain": "um.example"}, {"domain": "dois.example", "ttl_s": 3600},
                                                      {"domain": "*.ruim.example"}]})
        self.assertEqual(st, 200)
        self.ex.step(wait_s=0)
        self.assertIn("um.example", self.fake.lists["allow"])
        self.assertIn("dois.example", self.fake.lists["allow"])
        self.assertNotIn("*.ruim.example", self.fake.lists["allow"])
        self.assertEqual([t["domain"] for t in self.ex.state.data["temp"]], ["dois.example"])
        self.ex.report()
        rep = [d for d in self.c.call("GET", "/v1/devices")[1]["devices"] if d["id"] == self.ex.dev][0]["report"]
        self.assertTrue(rep["allow_by"]["um.example"])  # só o que o guardião criou é "gerenciado"
        self.fake.lists["allow"]["manual.example"] = "criado no pi-hole"
        self.ex.report()
        rep = [d for d in self.c.call("GET", "/v1/devices")[1]["devices"] if d["id"] == self.ex.dev][0]["report"]
        self.assertIn("manual.example", rep["allow"])
        self.assertNotIn("manual.example", rep["allow_by"])
        (st, _, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.ex.dev, "pihole_remove", {"list": "allow", "domain": "um.example"})
        self.ex.step(wait_s=0)
        self.assertNotIn("um.example", self.fake.lists["allow"])

    def test_09b_canary_is_hidden_and_cannot_be_requested(self):
        self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/report", {
            "kind": "device", "snapshot": {"canary": "Canario.Exemplo.com"}, "trust": {}, "ctrs": {}})
        now = int(time.time())
        self.env.store.merge_blocked(self.dev, [{"domain": "canario.exemplo.com", "src": "own", "list": "", "cname": 0,
                                                 "count": 3, "first": now - 5, "last": now - 5}])  # registro antigo, de antes do filtro do executor
        self.assertNotIn("canario.exemplo.com", self.blocked())
        st, r, _ = self.c.call("GET", f"/v1/blocked?dev={self.dev}")
        self.assertNotIn("canario.exemplo.com", {i["domain"] for i in r["items"]})
        st, r, _ = self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/requests", {"kind": "unblock", "domains": ["canario.exemplo.com"]})
        self.assertEqual(st, 400)
        self.assertIn("canário", r["error"])

    def test_09c_parent_domain_can_be_requested_but_never_a_suffix(self):
        now = int(time.time())
        self.env.store.merge_blocked(self.dev, [{"domain": "advertise.cloudlinks.cn", "src": "own", "list": "", "cname": 0, "count": 1, "first": now, "last": now},
                                                {"domain": "x.shop.com.br", "src": "own", "list": "", "cname": 0, "count": 1, "first": now, "last": now}])

        def ask(*doms):
            return self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/requests", {"kind": "unblock", "domains": list(doms)})

        self.assertEqual(ask("cloudlinks.cn")[0], 200)          # o pai do que foi bloqueado
        self.assertEqual(ask("shop.com.br")[0], 200)
        self.assertEqual(ask("outro.cn")[0], 400)               # não é pai de nada bloqueado
        self.assertEqual(ask("com.br")[0], 400)                 # sufixo público
        self.assertEqual(ask("loudlinks.cn")[0], 400)           # sufixo de texto não é pai
        self.env.client().signed(self.devkey, "POST", f"/v1/devices/{self.dev}/report", {
            "kind": "device", "snapshot": {"canary": "teste.cloudlinks.cn"}, "trust": {}, "ctrs": {}})
        self.assertEqual(ask("cloudlinks.cn")[0], 400)          # um pai que cobre o canário também não

    def test_10_blocked_cap_and_retention(self):
        items = [{"domain": f"d{i}.exemplo.com", "src": "list", "list": "", "cname": 0, "count": 1, "first": int(NOW) - 5,
                  "last": int(NOW) - 5} for i in range(150)]
        import time as _t
        now = int(_t.time())
        for k in range(8):
            for it in items:
                it["domain"] = f"k{k}-" + it["domain"].split("-")[-1]
                it["first"] = it["last"] = now - k
            self.env.store.merge_blocked(self.dev, [dict(i) for i in items])
        n = self.env.store.one("SELECT COUNT(*) c FROM blocked WHERE dev=?", (self.dev,))["c"]
        self.assertLessEqual(n, 1000)
        self.env.store.x("UPDATE blocked SET last=? WHERE dev=?", (now - 90000, self.dev))
        self.assertEqual(self.blocked(), {})  # tudo com mais de 24 h some da consulta
        self.env.store.purge()
        self.assertEqual(self.env.store.one("SELECT COUNT(*) c FROM blocked")["c"], 0)


if __name__ == "__main__":
    unittest.main()
