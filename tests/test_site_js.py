"""O site é JavaScript puro, sem Node no Pi: um parêntese a mais derrubou o app.js inteiro (a tela ficava em "Carregando…").
Este teste lê os arquivos do site com um analisador de JavaScript (esprima, copiado em tests/vendor, licença BSD-2) e falha se algum não carrega.

O esprima não conhece `?.` nem `??`, então esses operadores são trocados por equivalentes antes de ler (a forma do código não muda)."""
import glob
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "vendor"))

import esprima  # noqa: E402

STATIC = os.path.join(HERE, "..", "src", "guardian", "gateway", "static")


def parse_module(src: str):
    src = src.replace("?.[", "[").replace("?.(", "(").replace("?.", ".").replace("??", "||")
    return esprima.parseModule(src)


class SiteScripts(unittest.TestCase):
    def test_every_script_parses(self):
        files = sorted(glob.glob(os.path.join(STATIC, "*.js")))
        self.assertTrue(files)
        for path in files:
            with open(path, encoding="utf-8") as f:
                try:
                    parse_module(f.read())
                except Exception as e:   # esprima levanta Error com linha e coluna
                    self.fail(f"{os.path.basename(path)} não carrega no navegador: {e}")

    def test_the_checker_catches_the_bug_we_had(self):
        with self.assertRaises(Exception):
            parse_module("const a = f(g(1)));")


if __name__ == "__main__":
    unittest.main()
