import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, pair  # noqa: E402
from guardian.protocol import tailnet  # noqa: E402
from test_executor import pairing_string  # noqa: E402

NOW = float(int(time.time()))


class TailnetIps(unittest.TestCase):
    def test_only_tailnet_addresses_canonical_and_unique(self):
        raw = ["100.64.0.7", " 100.64.0.7 ", "192.168.1.5", "100.128.0.1", "fd7a:115c:a1e0::7", "FD7A:115C:A1E0:0:0:0:0:8", "fe80::1", "x", 5, None]
        self.assertEqual(tailnet.valid_ips(raw), ["100.64.0.7", "fd7a:115c:a1e0::7", "fd7a:115c:a1e0::8"])
        self.assertEqual(tailnet.valid_ips("100.64.0.7"), [])
        self.assertEqual(len(tailnet.valid_ips([f"100.64.0.{i}" for i in range(1, 30)])), tailnet.MAX_IPS)

    def test_ip_claimed_by_two_devices_is_ambiguous(self):
        m = tailnet.ip_map({"a": ["100.64.0.1", "100.64.0.2"], "b": ["100.64.0.2", "100.64.0.3"]})
        self.assertEqual(m, {"100.64.0.1": "a", "100.64.0.3": "b"})


class AutoClients(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        cls.fake = FakePihole()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.k1, cls.d1 = cls.env.pair_device(cls.c)
        cls.k2, cls.d2 = cls.env.pair_device(cls.c)
        cls.cfg = ExecConfig(cls.tmp.name, cls.fake.url, "senha-app", "canario.example")  # sem CLIENTS à mão
        st, p, _ = cls.c.call("POST", "/v1/pairings", {"kind": "executor"})
        pair(cls.cfg, pairing_string(cls.env, cls.c, p["token"]))
        cls.ex = Executor(cls.cfg, now=lambda: NOW)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()
        cls.fake.close()
        cls.tmp.cleanup()

    def report(self, key, dev, ips):
        st, r, _ = self.env.client().signed(key, "POST", f"/v1/devices/{dev}/report", {"kind": "device", "tsIps": ips})
        self.assertEqual(st, 200, r)

    def q(self, t, domain, ip):
        return {"time": t, "domain": domain, "status": "REGEX", "client": {"ip": ip}}

    def blocked(self, key, dev):
        st, r, _ = self.env.client().signed(key, "GET", f"/v1/devices/{dev}/blocked")
        self.assertEqual(st, 200, r)
        return {i["domain"] for i in r["items"]}

    def test_01_no_report_no_clients(self):
        self.assertEqual(self.ex.known_clients(), {})

    def test_02_device_declares_its_ip_and_blocks_flow(self):
        self.report(self.k1, self.d1, ["100.64.0.7", "fd7a:115c:a1e0::7", "8.8.8.8"])
        self.assertEqual(self.ex.known_clients(), {"100.64.0.7": self.d1, "fd7a:115c:a1e0::7": self.d1})
        self.fake.queries += [self.q(NOW - 30, "auto.exemplo.com", "100.64.0.7"), self.q(NOW - 29, "outro.com", "100.64.0.99")]
        self.assertEqual(self.ex.collect_blocks(), 2)  # o do aparelho pareado e o do cliente da rede
        self.assertEqual(self.blocked(self.k1, self.d1), {"auto.exemplo.com"})  # o aparelho não vê o do vizinho

    def test_02b_unpaired_network_client_shows_up_for_the_guardian_only(self):
        self.fake.queries += [{"time": NOW - 20, "domain": "tv.exemplo.com", "status": "REGEX", "client": {"ip": "192.168.2.51", "name": "tv-sala"}},
                              {"time": NOW - 19, "domain": "tv.exemplo.com", "status": "GRAVITY", "client": {"ip": "192.168.2.51", "name": "tv-sala"}, "list_id": -7},
                              {"time": NOW - 18, "domain": "eco.exemplo.com", "status": "REGEX", "client": {"ip": "127.0.0.1"}},
                              {"time": NOW - 17, "domain": "ok.exemplo.com", "status": "FORWARDED", "client": {"ip": "192.168.2.52"}}]
        self.ex.collect_blocks()
        st, r, _ = self.c.call("GET", "/v1/blocked")
        self.assertEqual(st, 200, r)
        self.assertEqual([(n["id"], n["name"], n["ip"]) for n in r["net"] if n["ip"] == "192.168.2.51"], [("net-192-168-2-51", "tv-sala", "192.168.2.51")])
        self.assertNotIn("127.0.0.1", [n["ip"] for n in r["net"]])   # o próprio Pi-hole não conta
        self.assertNotIn("192.168.2.52", [n["ip"] for n in r["net"]])  # sem bloqueio, não aparece
        mine = [i for i in r["items"] if i["dev"] == "net-192-168-2-51"]
        self.assertEqual({i["domain"] for i in mine}, {"tv.exemplo.com"})
        self.assertEqual(self.c.call("GET", "/v1/blocked?dev=net-192-168-2-51")[1]["items"][0]["domain"], "tv.exemplo.com")
        self.assertEqual(self.c.call("GET", "/v1/blocked?dev=net-zz")[0], 400)
        # nenhum aparelho pareado enxerga o cliente da rede
        self.assertNotIn("tv.exemplo.com", self.blocked(self.k1, self.d1))
        st, _, _ = self.env.client().signed(self.k1, "POST", f"/v1/devices/{self.d1}/unblock", {"domains": ["tv.exemplo.com"]})
        self.assertNotEqual(st, 200)

    def test_02c_own_machine_addresses_are_not_network_clients(self):
        from unittest import mock
        self.fake.queries.append({"time": NOW - 10, "domain": "eu-mesmo.exemplo.com", "status": "REGEX", "client": {"ip": "100.99.99.1", "name": "pi.hole"}})
        with mock.patch("guardian.executor.runner.local_ips", return_value={"100.99.99.1"}):
            self.ex.collect_blocks()
        self.assertNotIn("100.99.99.1", [n["ip"] for n in self.c.call("GET", "/v1/blocked")[1]["net"]])

    def test_03_conflicting_claim_is_dropped_for_both(self):
        self.report(self.k2, self.d2, ["100.64.0.7", "100.64.0.8"])
        self.assertEqual(self.ex.known_clients(), {"fd7a:115c:a1e0::7": self.d1, "100.64.0.8": self.d2})

    def test_04_only_executor_reads_clients(self):
        st, _, _ = self.env.client().signed(self.k1, "GET", f"/v1/devices/{self.d1}/clients")
        self.assertEqual(st, 403)
        self.assertEqual(self.env.client().call("GET", f"/v1/devices/{self.d1}/clients")[0], 401)

    def test_05_manual_clients_win_and_gateway_down_keeps_last_map(self):
        self.ex.cfg.clients = {"100.64.0.8": self.d1}
        self.assertEqual(self.ex.known_clients()["100.64.0.8"], self.d1)
        self.ex.cfg.clients = None
        self.ex.gw.base = "http://127.0.0.1:9"  # gateway fora do ar
        self.assertEqual(self.ex.known_clients()["100.64.0.8"], self.d2)


if __name__ == "__main__":
    unittest.main()
