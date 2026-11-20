"""Vigia interno do site: o site que para de atender (sem vagas, laço parado) se reinicia sozinho e deixa um relatório em /data."""
import os
import socketserver
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from gwharness import Env  # noqa: E402
from guardian.gateway import server  # noqa: E402


class SelfCheck(unittest.TestCase):
    def setUp(self):
        self.env = Env(max_connections=8)

    def tearDown(self):
        self.env.close()

    def test_healthy_server_passes_and_full_server_fails(self):
        self.assertTrue(server.selfcheck_once(self.env.port))
        self.env.srv._active = self.env.cfg.max_connections   # todas as vagas presas: o servidor fecha a conexão na hora (o Tailscale vê 502)
        self.assertFalse(server.selfcheck_once(self.env.port, timeout=2))
        self.env.srv._active = 0
        self.assertTrue(server.selfcheck_once(self.env.port))

    def test_three_failures_write_a_report_and_exit(self):
        exits, slept = [], []
        self.env.srv._active = 5
        server.selfcheck_loop(self.env.srv, 30, check=lambda port: False, exit_fn=exits.append, sleep=slept.append)
        self.assertEqual(exits, [3])
        d = os.path.dirname(self.env.cfg.db_path)
        (rep,) = [x for x in os.listdir(d) if x.startswith("trava-")]
        text = open(os.path.join(d, rep)).read()
        self.assertIn("vagas ocupadas: 5 de 8", text)
        self.assertIn("Thread", text)                       # onde cada thread estava parada
        self.assertEqual(slept, [60, 30, 30])               # espera o servidor subir, depois 1 teste a cada 30 s

    def test_a_single_failure_does_not_restart(self):
        exits, results = [], iter([False, True, False, False, True])
        stop = type("S", (), {"n": 0, "is_set": lambda self: (setattr(self, "n", self.n + 1) or self.n > 5)})()
        server.selfcheck_loop(self.env.srv, 30, check=lambda port: next(results), exit_fn=exits.append, sleep=lambda s: None, stop=stop)
        self.assertEqual(exits, [])

    def test_slot_is_released_when_the_thread_cannot_start(self):
        orig = socketserver.ThreadingMixIn.process_request

        def boom(self, request, client_address):
            raise RuntimeError("can't start new thread")
        socketserver.ThreadingMixIn.process_request = boom
        try:
            with self.assertRaises(RuntimeError):
                self.env.srv.process_request(None, ("127.0.0.1", 1))
        finally:
            socketserver.ThreadingMixIn.process_request = orig
        self.assertEqual(self.env.srv._active, 0)

    def test_old_reports_are_pruned(self):
        d = os.path.dirname(self.env.cfg.db_path)
        for i in range(8):
            server.write_trava_report(self.env.srv, 3, now=1_800_000_000 + i)
        self.assertEqual(len([x for x in os.listdir(d) if x.startswith("trava-")]), server.TRAVA_KEEP)


if __name__ == "__main__":
    unittest.main()
