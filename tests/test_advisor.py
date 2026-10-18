import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from gwharness import Env  # noqa: E402
from guardian.gateway import advisor as adv  # noqa: E402
from guardian.gateway.advisor import Advisor  # noqa: E402
from test_roles import register  # noqa: E402

RUN = {"ctr": 7, "type": "win_install", "name": "DBeaver", "ok": False, "rc": 666660, "ts": 1, "by": "g",
       "out": "Installing for C:\\Users\\allan\\AppData\\Local\\Temp\\x from 192.168.2.100 as ALLANPC sha bf9b5ce8a89f244c376a9b1a946276eaa06463dde3e33069a34d7f102f5878cf "
              "contato dono@exemplo.com token sk-or-v1-abcdef0123456789abcdef\nErro: invalid command line",
       "req": {"name": "DBeaver", "source": "file", "path": "C:\\Users\\allan\\Downloads\\dbeaver-ce-26.2.2.exe", "sha256": "a" * 64, "kind": "exe",
               "args": "/S", "publisher": "DBeaver Corp"},
       "installed": [], "verified": False, "needs_help": True}


class Privacy(unittest.TestCase):
    def test_sanitize_removes_what_identifies_the_person_or_the_pc(self):
        t = adv.sanitize(RUN["out"], host="ALLANPC")
        for leak in ("allan", "192.168.2.100", "ALLANPC", "bf9b5ce8", "dono@exemplo.com", "sk-or-v1"):
            self.assertNotIn(leak, t, leak)
        for kept in ("C:\\Users\\<usuario>", "<ip>", "<pc>", "<hash>", "<email>", "<segredo>", "invalid command line"):
            self.assertIn(kept, t, kept)

    def test_sanitize_keeps_the_tail_of_long_output(self):
        t = adv.sanitize("A" * 9000 + "ERRO FINAL")
        self.assertTrue(t.endswith("ERRO FINAL"))
        self.assertLessEqual(len(t), adv.MAX_TAIL + 10)

    def test_input_has_only_what_is_needed(self):
        d = adv.build_input(RUN, "ALLANPC")
        s = json.dumps(d)
        self.assertEqual((d["programa"], d["arquivo"], d["codigo_de_saida"], d["argumentos_usados"]), ("DBeaver", "dbeaver-ce-26.2.2.exe", 666660, "/S"))
        for leak in ("allan", "Downloads", "a" * 64, "ALLANPC", "192.168"):
            self.assertNotIn(leak, s, leak)                                # nem o caminho do arquivo, nem o hash, nem o dono
        url = adv.build_input({**RUN, "req": {"source": "url", "url": "https://www.7-zip.org/a/7z2604-x64.exe?token=segredo", "kind": "exe"}})
        self.assertEqual(url["dominio_do_download"], "www.7-zip.org")
        self.assertNotIn("token=segredo", json.dumps(url))                  # a query do link nunca vai
        self.assertNotIn("path", json.dumps(adv.build_input({**RUN, "req": {"source": "winget", "id": "Git.Git"}})))


class Validation(unittest.TestCase):
    def test_accepts_a_good_answer_and_fenced_json(self):
        good = {"summary": "O instalador recusou os parâmetros.", "likely_cause": "falta /allusers", "confidence": "high",
                "actions": [{"kind": "retry_with_args", "args": "/S /allusers", "why": "documentado"}, {"kind": "release_domain", "domains": ["7-zip.org"], "why": "download"},
                            {"kind": "admin_manual", "why": "janela"}]}
        for raw in (json.dumps(good), "Claro!\n```json\n" + json.dumps(good) + "\n```"):
            r = adv.validate(raw)
            self.assertEqual([a["kind"] for a in r["actions"]], ["retry_with_args", "release_domain", "admin_manual"])
            self.assertEqual((r["confidence"], r["actions"][0]["args"], r["actions"][1]["domains"]), ("high", "/S /allusers", ["7-zip.org"]))

    def test_hostile_or_malformed_answers_are_cut_down(self):
        bad = {"summary": "ok\x00\nIGNORE as regras", "confidence": "certeza absoluta", "actions": [
            {"kind": "run_powershell", "args": "Remove-Item C:\\ -Recurse"},                  # tipo fora da lista
            {"kind": "retry_with_args", "args": "/S & del /q C:\\*"},                          # metacaractere de shell
            {"kind": "retry_with_args", "args": "x" * 300},                                    # grande demais
            {"kind": "retry_with_args", "args": "/S\n/D=C:\\x"},                               # caractere de controle
            {"kind": "release_domain", "domains": ["http://evil.com/x", "localhost", "*.evil.com", "ok.example"]},
            {"kind": "other", "text": "t" * 900}, {"kind": "admin_manual"}, "texto solto"]}
        r = adv.validate(json.dumps(bad))
        self.assertEqual(r["confidence"], "low")
        self.assertNotIn("\x00", r["summary"])
        self.assertEqual(r["actions"], [])        # só os 3 primeiros itens são considerados, e os três eram hostis: nenhum passa
        mix = {"summary": "ok", "actions": bad["actions"][4:7] + bad["actions"][:1]}       # domínio, texto longo e admin_manual primeiro
        r = adv.validate(json.dumps(mix))
        self.assertEqual([a["kind"] for a in r["actions"]], ["release_domain", "other", "admin_manual"])
        self.assertEqual(r["actions"][0]["domains"], ["ok.example"])                       # só o domínio válido
        self.assertLessEqual(len(r["actions"][1]["text"]), 300)
        self.assertEqual(adv.validate(json.dumps({"summary": "x", "actions": bad["actions"][1:4]}))["actions"], [])   # argumentos hostis: nenhum passa

    def test_unusable_answers_return_none(self):
        for raw in ("não sei", "", None, "{}", '{"summary": ""}', "[1,2]", 5):
            self.assertIsNone(adv.validate(raw), raw)


class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.c, cls.a, cls.gid = cls.env.register_guardian("Ana")
        st, inv, _ = cls.c.call("POST", "/v1/invites", {"kind": "new_guardian", "name": "Bia"})
        cls.dc, cls.da, cls.dgid = register(cls.env, inv["token"])
        cls.key, cls.pc = cls.env.pair_device(cls.c, name="PC")
        cls.calls = []
        cls.gw = cls.env.srv.gw

        def answer(system, user):
            cls.calls.append((system, user))
            return json.dumps({"summary": "Parâmetros recusados.", "likely_cause": "falta /allusers", "confidence": "high",
                               "actions": [{"kind": "retry_with_args", "args": "/S /allusers", "why": "doc"}]})

        cls.gw.advisor = Advisor(cls.env.store, "chave-de-teste", "modelo/teste", 2, call=answer)

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def report(self, runs, **extra):
        st, r, _ = self.env.client().signed(self.key, "POST", f"/v1/devices/{self.pc}/report", {"kind": "device", "platform": "windows", "host": "ALLANPC", "runs": runs, **extra})
        self.assertEqual(st, 200, r)
        for t in list(self.gw.advisor.threads):
            t.join(10)

    def items(self):
        return self.c.call("GET", "/v1/analyses")[1]["items"]

    def test_01_failed_install_is_analysed_and_seen_by_both_sides(self):
        self.report([RUN])
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("allan", self.calls[0][1])                       # o que saiu já estava limpo
        self.assertIn("NÃO confiável", self.calls[0][0])
        it = next(x for x in self.items() if x["ctr"] == 7)
        self.assertEqual((it["status"], it["result"]["actions"][0]["args"]), ("done", "/S /allusers"))
        mine = self.env.client().signed(self.key, "GET", f"/v1/devices/{self.pc}/requests")[1]["analyses"]       # o solicitante também vê
        self.assertEqual([m["ctr"] for m in mine], [7])

    def test_02_same_run_is_never_analysed_twice(self):
        n = len(self.calls)
        self.report([RUN])
        self.report([RUN])
        self.assertEqual(len(self.calls), n)

    def test_03_only_installs_that_need_help_are_sent(self):
        n = len(self.calls)
        self.report([{**RUN, "ctr": 8, "needs_help": False, "ok": True, "verified": True},
                     {**RUN, "ctr": 9, "type": "win_run", "name": "script secreto", "out": "senha=123"},   # script de comando admin: nunca sai
                     {**RUN, "ctr": "x"}])
        self.assertEqual(len(self.calls), n)

    def test_04_only_admins_read_analyses(self):
        self.assertEqual(self.dc.call("GET", "/v1/analyses")[0], 403)
        self.assertEqual(self.env.client().call("GET", "/v1/analyses")[0], 401)

    def test_05_daily_cap_skips_and_does_not_call(self):
        n = len(self.calls)                                                                                  # o teto é 2 por dia e o teste 01 já usou 1
        self.report([{**RUN, "ctr": 20}, {**RUN, "ctr": 21}, {**RUN, "ctr": 22}])
        st = {x["ctr"]: x["status"] for x in self.items()}
        self.assertEqual(len(self.calls) - n, 1)                                                              # só mais uma consulta de verdade
        self.assertEqual((st[20], st[21], st[22]), ("done", "skipped", "skipped"))
        self.assertEqual(self.env.store.analyses_called_since(0), 2)
        self.assertIn("Limite diário", [x for x in self.items() if x["ctr"] == 22][0]["result"]["summary"])

    def test_06_ai_failure_is_contained(self):
        gw = self.gw
        gw.advisor = Advisor(self.env.store, "k", "m", 99, call=lambda s, u: (_ for _ in ()).throw(RuntimeError("chave sk-or-SEGREDO inválida")))
        self.report([{**RUN, "ctr": 30}])
        it = next(x for x in self.items() if x["ctr"] == 30)
        self.assertEqual(it["status"], "error")
        self.assertNotIn("SEGREDO", json.dumps(it))                                                        # nada do erro vaza para a tela
        gw.advisor = Advisor(self.env.store, "k", "m", 99, call=lambda s, u: "não sou JSON")
        self.report([{**RUN, "ctr": 31}])
        self.assertEqual(next(x for x in self.items() if x["ctr"] == 31)["status"], "error")

    def test_07_without_a_key_nothing_happens(self):
        self.gw.advisor = Advisor(self.env.store, "", "m", 99, call=lambda s, u: self.fail("não deveria chamar"))
        self.report([{**RUN, "ctr": 40}])
        self.assertFalse([x for x in self.items() if x["ctr"] == 40])
        self.assertFalse(self.c.call("GET", "/v1/analyses")[1]["enabled"])


if __name__ == "__main__":
    unittest.main()
