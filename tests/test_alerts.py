import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.gateway import webpush  # noqa: E402
from guardian.gateway.alerts import SILENT_S, Alerts  # noqa: E402
from guardian.protocol import b64  # noqa: E402
from test_webpush import FakePushService  # noqa: E402


class AlertRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def setUp(self):
        self.c, self.a, self.gid = self.env.register_guardian("Ana")
        self.key, self.dev = self.env.pair_device(self.c, name="Tab S8")
        self.now = [self.env.store.device(self.dev)["created"] + 1.0]
        self.alerts = Alerts(self.env.store, now=lambda: self.now[0])

    def report(self, **r):
        base = {"kind": "device", "filterActive": True, "pendingApps": [], "pending": [], "ctrs": {}}
        st, _, _ = self.env.client().signed(self.key, "POST", f"/v1/devices/{self.dev}/report", {**base, **r})
        self.assertEqual(st, 200)

    def mine(self, notes):
        return [n for n in notes if self.dev in n["tag"] or n["tag"].startswith(("req:", "cosign:"))]

    def test_first_pass_only_memorizes(self):
        self.report(pendingApps=[{"pkg": "com.x", "label": "X", "risks": []}])
        self.assertEqual(self.mine(self.alerts.evaluate()), [])
        self.assertEqual(self.mine(self.alerts.evaluate()), [])

    def test_new_pending_app_notifies_once(self):
        self.report()
        self.alerts.evaluate()
        self.report(pendingApps=[{"pkg": "com.jogo", "label": "Jogo", "risks": ["nome sugere VPN/torrent/anônimo"]}])
        notes = self.mine(self.alerts.evaluate())
        self.assertEqual([n["title"] for n in notes], ["App novo pendente"])
        self.assertIn("Jogo", notes[0]["body"])
        self.assertIn("Tab S8", notes[0]["body"])
        self.assertIn("VPN", notes[0]["body"])
        self.assertEqual(self.mine(self.alerts.evaluate()), [])
        self.report(pendingApps=[{"pkg": "com.jogo", "label": "Jogo", "risks": []}, {"pkg": "com.b", "label": "B", "risks": []}])
        notes = self.mine(self.alerts.evaluate())
        self.assertEqual(len(notes), 1)
        self.assertIn("B", notes[0]["body"])

    def test_filter_flip_both_ways(self):
        self.report(filterActive=True)
        self.alerts.evaluate()
        self.report(filterActive=False, filterReason="sem VPN de pé")
        down = self.mine(self.alerts.evaluate())
        self.assertEqual([n["title"] for n in down], ["Filtro caiu"])
        self.assertIn("sem VPN de pé", down[0]["body"])
        self.report(filterActive=True)
        self.assertEqual([n["title"] for n in self.mine(self.alerts.evaluate())], ["Filtro voltou"])

    def test_silent_and_back(self):
        self.report()
        self.alerts.evaluate()
        seen = self.env.store.device(self.dev)["last_seen"]
        self.now[0] = seen + SILENT_S + 10
        self.assertEqual([n["title"] for n in self.mine(self.alerts.evaluate())], ["Aparelho sem sinal"])
        self.assertEqual(self.mine(self.alerts.evaluate()), [])  # não repete
        self.now[0] = seen + 20
        self.report()
        self.assertEqual([n["title"] for n in self.mine(self.alerts.evaluate())], ["Aparelho voltou"])

    def test_new_loosening_request(self):
        self.report()
        self.alerts.evaluate()
        self.report(pending=[{"kind": "RELEASE", "state": "waiting", "remainingMs": 1000, "summary": "remover o Device Owner"}])
        notes = self.mine(self.alerts.evaluate())
        self.assertEqual([n["title"] for n in notes], ["Pedido de afrouxar"])
        self.assertIn("Device Owner", notes[0]["body"])

    def test_user_request_and_cosign_exclude_author(self):
        self.alerts.evaluate()
        st, _, _ = self.env.client().signed(self.key, "POST", f"/v1/devices/{self.dev}/requests", {"kind": "domain", "text": "exemplo.com"})
        self.assertEqual(st, 200)
        c2, a2, g2 = self.env.register_guardian("Bia")
        (st, r, _), _ = self.env.sign_post(self.c, self.a, self.gid, self.dev, "remove_guardian", {"id": g2})
        self.assertEqual(r["status"], "awaiting")
        notes = self.alerts.evaluate()
        req = [n for n in notes if n["tag"].startswith("req:")]
        cos = [n for n in notes if n["tag"].startswith("cosign:")]
        self.assertEqual(len(req), 1)
        self.assertIn("exemplo.com", req[0]["body"])
        self.assertEqual(len(cos), 1)
        self.assertEqual(cos[0]["exclude"], self.gid)  # quem pediu não precisa ser avisado
        self.assertIn("remove_guardian", cos[0]["body"])

    def test_executor_pihole_transitions(self):
        ekey, edev = self.env.pair_device(self.c, kind="executor", name="Pi")
        post = lambda **r: self.env.client().signed(ekey, "POST", f"/v1/devices/{edev}/report", {"kind": "executor", **r})
        post(pihole_ok=True)
        self.alerts.evaluate()
        post(pihole_ok=False, pihole_error="Pi-hole inacessível: timeout")
        notes = [n for n in self.alerts.evaluate() if edev in n["tag"]]
        self.assertEqual([n["title"] for n in notes], ["Pi-hole inacessível"])
        post(pihole_ok=True)
        self.assertEqual([n["title"] for n in self.alerts.evaluate() if edev in n["tag"]], ["Pi-hole voltou"])


class PushThroughTheGateway(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.svc = FakePushService()
        self.c, self.a, self.gid = self.env.register_guardian("Ana")
        self.ua = ec.generate_private_key(ec.SECP256R1())
        self.auth = os.urandom(16)
        self.sub = {"endpoint": self.svc.url, "keys": {"p256dh": b64.enc(webpush.public_bytes(self.ua)), "auth": b64.enc(self.auth)}}

    def tearDown(self):
        self.svc.close()
        self.env.close()

    def payloads(self):
        return [json.loads(webpush.decrypt(self.ua, self.auth, body)) for _, body in self.svc.got]

    def test_vapid_key_is_stable_and_requires_login(self):
        self.assertEqual(self.env.client().call("GET", "/v1/push/key")[0], 401)
        k1 = self.c.call("GET", "/v1/push/key")[1]["key"]
        self.assertEqual(len(b64.dec(k1)), 65)
        self.assertEqual(self.c.call("GET", "/v1/push/key")[1]["key"], k1)
        self.env.srv.gw.vapid = self.env.srv.gw._load_vapid()  # recarregada do banco: a mesma chave
        self.assertEqual(b64.enc(webpush.public_bytes(self.env.srv.gw.vapid)), k1)

    def test_subscribe_test_and_unsubscribe(self):
        self.assertEqual(self.c.call("POST", "/v1/push/subscribe", self.sub)[0], 200)
        st, r, _ = self.c.call("POST", "/v1/push/test", {})
        self.assertEqual((st, r["sent"]), (200, 1))
        self.assertEqual(self.payloads()[0]["title"], "NotToday Guardian")
        self.assertEqual(self.c.call("POST", "/v1/push/unsubscribe", {"endpoint": self.svc.url})[0], 200)
        self.assertEqual(self.c.call("POST", "/v1/push/test", {})[1]["sent"], 0)

    def test_subscribe_validation(self):
        bad = [
            {**self.sub, "keys": {"p256dh": "AAAA", "auth": self.sub["keys"]["auth"]}},
            {**self.sub, "keys": {"p256dh": self.sub["keys"]["p256dh"], "auth": "AAAA"}},
            {**self.sub, "keys": {}}, {"endpoint": self.svc.url}, {"keys": self.sub["keys"]}, {**self.sub, "endpoint": 5},
        ]
        for b in bad:
            self.assertEqual(self.c.call("POST", "/v1/push/subscribe", b)[0], 400, b)
        self.env.srv.gw.cfg.allow_any_push_endpoint = False  # em produção só serviços de push conhecidos
        self.assertEqual(self.c.call("POST", "/v1/push/subscribe", self.sub)[0], 400)
        self.assertEqual(self.c.call("POST", "/v1/push/subscribe", {**self.sub, "endpoint": "https://fcm.googleapis.com/fcm/send/x"})[0], 200)

    def test_gone_subscription_is_removed(self):
        self.c.call("POST", "/v1/push/subscribe", self.sub)
        self.svc.status = 410
        self.assertEqual(self.c.call("POST", "/v1/push/test", {})[1]["sent"], 0)
        self.assertEqual(self.env.store.push_subs(), [])

    def test_keeps_only_the_latest_five_subscriptions_per_guardian(self):
        for i in range(7):
            self.c.call("POST", "/v1/push/subscribe", {**self.sub, "endpoint": self.svc.url + f"?i={i}"})
        self.assertEqual(len(self.env.store.push_subs(guardian=self.gid)), 5)

    def test_alert_reaches_the_subscribed_guardian(self):
        self.c.call("POST", "/v1/push/subscribe", self.sub)
        key, dev = self.env.pair_device(self.c, name="Celular")
        gw = self.env.srv.gw
        self.assertEqual(gw.alerts_tick(), 0)  # 1ª rodada só memoriza
        self.env.client().signed(key, "POST", f"/v1/devices/{dev}/requests", {"kind": "domain", "text": "liberar.exemplo.com"})
        self.assertEqual(gw.alerts_tick(), 1)
        p = self.payloads()[0]
        self.assertEqual(p["title"], "Pedido do usuário")
        self.assertIn("liberar.exemplo.com", p["body"])
        self.assertEqual(gw.alerts_tick(), 0)  # sem repetir


if __name__ == "__main__":
    unittest.main()
