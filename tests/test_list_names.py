import unittest

from guardian.executor.pihole import list_label
from guardian.executor.runner import Executor


class _Stub:
    """O mínimo que Executor._list_name usa."""
    def __init__(self):
        self._lists, self._lists_ts = None, 0.0
        self.now = lambda: 1000.0
        self.pihole = type("P", (), {"list_names": staticmethod(lambda: {7: "listas.example", 24: "StevenBlack · hosts"})})()


class ListIdTest(unittest.TestCase):
    def test_negative_ids_from_the_pihole_log_resolve_and_missing_lists_are_named(self):
        f, st = Executor._list_name, _Stub()
        self.assertEqual(f(st, 7), "listas.example")
        self.assertEqual(f(st, -24), "StevenBlack · hosts")      # o Pi-hole grava -24
        self.assertEqual(f(st, -3), "lista removida (#3)")        # a lista foi tirada do Pi-hole
        self.assertEqual(f(st, None), "")
        self.assertEqual(f(st, 0), "")


class ListLabelTest(unittest.TestCase):
    def test_comment_wins(self):
        self.assertEqual(list_label("https://x.example/a.txt", "HaGeZi NSFW"), "HaGeZi NSFW")

    def test_github_raw_becomes_owner_and_project_without_slash(self):
        got = list_label("https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts")
        self.assertEqual(got, "StevenBlack · hosts")
        self.assertNotIn("/", got)  # o app corta no primeiro '/'

    def test_other_urls_use_the_host(self):
        self.assertEqual(list_label("https://listas.example/ads.txt"), "listas.example")
        self.assertEqual(list_label("file:///opt/x/lista.txt"), "file:///opt/x/lista.txt")  # sem host: o próprio endereço


if __name__ == "__main__":
    unittest.main()
