import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from authenticator import FakeAuthenticator, command, envelope  # noqa: E402
from guardian.protocol import b64, cbor, devauth, pinbox, webauthn  # noqa: E402
from guardian.protocol.commands import Consumer, CommandError, Guardian, Trust, verify_envelope  # noqa: E402

RP, ORIGIN = "pi.example.ts.net", "https://pi.example.ts.net"


def trust_with(*pairs):
    return Trust(RP, ORIGIN, {gid: Guardian(gid, {a.cred_id_b64: b64.enc(a.spki)}) for gid, a in pairs})


class WebAuthnTests(unittest.TestCase):
    def test_registration_roundtrip(self):
        a, ch = FakeAuthenticator(RP, ORIGIN), os.urandom(32)
        r = a.register(ch)
        cred, spki, be = webauthn.parse_registration(b64.dec(r["attestationObject"]), b64.dec(r["clientDataJSON"]), ch, RP, ORIGIN)
        self.assertEqual(cred, a.cred_id)
        self.assertEqual(spki, a.spki)

    def test_registration_requires_uv_and_origin(self):
        a, ch = FakeAuthenticator(RP, ORIGIN), os.urandom(32)
        for kw in ({"uv": False}, {"origin": "https://evil.example"}):
            r = a.register(ch, **kw)
            with self.assertRaises(webauthn.WebAuthnError):
                webauthn.parse_registration(b64.dec(r["attestationObject"]), b64.dec(r["clientDataJSON"]), ch, RP, ORIGIN)

    def test_assertion_ok_and_failures(self):
        a, ch = FakeAuthenticator(RP, ORIGIN), os.urandom(32)

        def check(asn, challenge=ch):
            webauthn.verify_assertion(a.spki, b64.dec(asn["authenticatorData"]), b64.dec(asn["clientDataJSON"]),
                                      b64.dec(asn["signature"]), challenge, RP, ORIGIN)

        check(a.assert_(ch))
        for kw in ({"uv": False}, {"origin": "https://evil.example"}, {"rp_id": "evil.example"}):
            with self.assertRaises(webauthn.WebAuthnError):
                check(a.assert_(ch, **kw))
        with self.assertRaises(webauthn.WebAuthnError):
            check(a.assert_(ch), challenge=os.urandom(32))
        other = FakeAuthenticator(RP, ORIGIN)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_assertion(other.spki, *(b64.dec(a.assert_(ch)[k]) for k in ("authenticatorData", "clientDataJSON", "signature")), ch, RP, ORIGIN)

    def test_cbor_rejects_garbage(self):
        for bad in (b"", b"\xff", b"\x1c", b"\x5f"):
            with self.assertRaises(cbor.CborError):
                cbor.decode(bad)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = FakeAuthenticator(RP, ORIGIN), FakeAuthenticator(RP, ORIGIN)
        self.trust = trust_with(("ana", self.a), ("bia", self.b))

    def test_single_signature_command(self):
        p = command("dev1", "ana", 1, "approve_app", {"pkg": "x"})
        v = verify_envelope(self.trust, envelope(p, self.a.sign_command("ana", p)))
        self.assertEqual(v.cmd["type"], "approve_app")

    def test_tampered_payload_rejected(self):
        p = command("dev1", "ana", 1, "approve_app", {"pkg": "x"})
        env = envelope(p, self.a.sign_command("ana", p))
        env["payload"] = b64.enc(command("dev1", "ana", 1, "approve_app", {"pkg": "y"}))
        with self.assertRaises(CommandError):
            verify_envelope(self.trust, env)

    def test_unknown_guardian_and_wrong_credential(self):
        stranger = FakeAuthenticator(RP, ORIGIN)
        p = command("dev1", "ana", 1, "approve_app")
        with self.assertRaises(CommandError):
            verify_envelope(self.trust, envelope(p, stranger.sign_command("ana", p)))
        with self.assertRaises(CommandError):
            verify_envelope(self.trust, envelope(p, stranger.sign_command("zed", p)))

    def test_author_must_sign(self):
        p = command("dev1", "ana", 1, "approve_app")
        with self.assertRaises(CommandError):
            verify_envelope(self.trust, envelope(p, self.b.sign_command("bia", p)))

    def test_remove_guardian_needs_two(self):
        p = command("dev1", "ana", 1, "remove_guardian", {"id": "bia"})
        with self.assertRaises(CommandError):
            verify_envelope(self.trust, envelope(p, self.a.sign_command("ana", p)))
        v = verify_envelope(self.trust, envelope(p, self.a.sign_command("ana", p), self.b.sign_command("bia", p)))
        self.assertEqual(v.signers, {"ana", "bia"})
        # o mesmo guardião duas vezes não conta como dois
        with self.assertRaises(CommandError):
            verify_envelope(self.trust, envelope(p, self.a.sign_command("ana", p), self.a.sign_command("ana", p)))

    def test_consumer_replay_and_destination(self):
        c = Consumer("dev1", self.trust)
        p1 = command("dev1", "ana", 1, "approve_app")
        env1 = envelope(p1, self.a.sign_command("ana", p1))
        c.accept(env1)
        with self.assertRaises(CommandError):
            c.accept(env1)
        p0 = command("dev1", "ana", 0 + 1, "approve_app", {"pkg": "z"})  # ctr 1 de novo
        with self.assertRaises(CommandError):
            c.accept(envelope(p0, self.a.sign_command("ana", p0)))
        pw = command("outro", "ana", 5, "approve_app")
        with self.assertRaises(CommandError):
            c.accept(envelope(pw, self.a.sign_command("ana", pw)))
        p2 = command("dev1", "ana", 2, "approve_app")
        c.accept(envelope(p2, self.a.sign_command("ana", p2)))
        # o contador é por guardião
        pb = command("dev1", "bia", 1, "approve_app")
        c.accept(envelope(pb, self.b.sign_command("bia", pb)))

    def test_trust_changes(self):
        c = Consumer("dev1", self.trust)
        third = FakeAuthenticator(RP, ORIGIN)
        c.apply_trust({"type": "add_guardian", "args": {"id": "cris", "name": "Cris", "cred": third.cred_id_b64,
                                                        "spki": b64.enc(third.spki), "role": "admin", "allow_sync": True}})
        self.assertIn("cris", c.trust.guardians)
        c.apply_trust({"type": "remove_guardian", "args": {"id": "cris"}})
        self.assertNotIn("cris", c.trust.guardians)
        c.apply_trust({"type": "remove_guardian", "args": {"id": "bia"}})
        with self.assertRaises(CommandError):
            c.apply_trust({"type": "remove_guardian", "args": {"id": "ana"}})  # último guardião-mor
        for bad in ({"id": "x", "name": "X", "cred": "c", "spki": "s"}, {"id": "x", "name": "X", "cred": "c", "spki": "s", "role": "root"}):
            with self.assertRaises(CommandError):  # papel ausente ou inválido
                c.apply_trust({"type": "add_guardian", "args": bad})

    def test_roles(self):
        dom = FakeAuthenticator(RP, ORIGIN)
        trust = trust_with(("ana", self.a), ("bia", self.b))
        trust.guardians["dora"] = Guardian("Dora", {dom.cred_id_b64: b64.enc(dom.spki)}, "domains")

        def env(author, auth, type_, args=None, *more):
            p = command("dev1", author, 1, type_, args)
            return envelope(p, auth.sign_command(author, p), *[a.sign_command(g, p) for g, a in more])

        # domínios: liberar e bloquear sim; o resto não
        for t in ("pihole_allow", "pihole_deny", "pihole_remove", "pihole_batch"):
            verify_envelope(trust, env("dora", dom, t, {"domain": "a.com"}))
        verify_envelope(trust, env("dora", dom, "approve_app", {"pkg": "x"}))  # aprovar e revogar app também
        verify_envelope(trust, env("dora", dom, "revoke_app", {"pkg": "x"}))
        for t, a in (("set_config", {"patch": {}}), ("set_pin", {}), ("activate", {}),
                     ("add_guardian", {"id": "z"}), ("remove_guardian", {"id": "bia"}), ("add_credential", {"id": "ana"})):
            with self.assertRaises(CommandError, msg=t):
                verify_envelope(trust, env("dora", dom, t, a))
        verify_envelope(trust, env("dora", dom, "add_credential", {"id": "dora"}))  # passkey nova para si mesma
        # a assinatura de um guardião não conta para o quórum de guardiões-mor
        with self.assertRaises(CommandError):
            verify_envelope(trust, env("ana", self.a, "remove_guardian", {"id": "bia"}, ("dora", dom)))
        verify_envelope(trust, env("ana", self.a, "remove_guardian", {"id": "bia"}, ("bia", self.b)))
        # com um guardião-mor só, ele remove sozinho; nunca o último guardião-mor
        solo = trust_with(("ana", self.a))
        solo.guardians["dora"] = Guardian("Dora", {dom.cred_id_b64: b64.enc(dom.spki)}, "domains")
        verify_envelope(solo, env("ana", self.a, "remove_guardian", {"id": "dora"}))
        c = Consumer("dev1", solo)
        c.apply_trust({"type": "remove_guardian", "args": {"id": "dora"}})
        with self.assertRaises(CommandError):
            c.apply_trust({"type": "remove_guardian", "args": {"id": "ana"}})
        # papel sobrevive à serialização; confiança antiga (sem papel) é de guardião-mor
        j = json.loads(json.dumps(trust.to_json()))
        self.assertEqual(Trust.from_json(j).guardians["dora"].role, "domains")
        del j["guardians"]["ana"]["role"]
        self.assertEqual(Trust.from_json(j).guardians["ana"].role, "admin")

    def test_master_role(self):
        mst, dom = FakeAuthenticator(RP, ORIGIN), FakeAuthenticator(RP, ORIGIN)
        trust = trust_with(("ana", self.a), ("bia", self.b))
        trust.guardians["mel"] = Guardian("Mel", {mst.cred_id_b64: b64.enc(mst.spki)}, "master")
        trust.guardians["dora"] = Guardian("Dora", {dom.cred_id_b64: b64.enc(dom.spki)}, "domains")

        def ok(author, auth, type_, args=None, *more):
            p = command("dev1", author, 1, type_, args)
            return verify_envelope(trust, envelope(p, auth.sign_command(author, p), *[a.sign_command(g, p) for g, a in more]))

        # o mestre inclui e remove guardiões sozinho, inclusive outro mestre
        ok("mel", mst, "add_guardian", {"id": "novo", "name": "Novo", "cred": "c", "spki": "s", "role": "master", "allow_sync": True})
        ok("mel", mst, "remove_guardian", {"id": "bia"})
        ok("mel", mst, "remove_credential", {"id": "dora", "cred": "c"})
        # tem tudo do guardião-mor
        ok("mel", mst, "set_config", {"patch": {}})
        ok("mel", mst, "approve_app", {"pkg": "x"})
        # o guardião-mor faz tudo, menos mexer em guardiões, nem com a assinatura de outro guardião-mor
        ok("ana", self.a, "set_config", {"patch": {}})
        for t, args in (("add_guardian", {"id": "z", "name": "Z", "cred": "c", "spki": "s", "role": "admin", "allow_sync": True}),
                        ("remove_guardian", {"id": "mel"}), ("remove_credential", {"id": "bia", "cred": "c"}),
                        ("add_credential", {"id": "bia", "cred": "c", "spki": "s"}), ("set_role", {"id": "ana", "role": "master"})):
            with self.assertRaises(CommandError, msg=t):
                ok("ana", self.a, t, args)
            with self.assertRaises(CommandError, msg=t + " 2 assinaturas"):
                ok("ana", self.a, t, args, ("bia", self.b))
        ok("ana", self.a, "add_credential", {"id": "ana", "cred": "c2", "spki": "s"})  # a própria passkey, qualquer um
        # o guardião comum continua como antes
        with self.assertRaises(CommandError):
            ok("dora", dom, "remove_guardian", {"id": "bia"})
        # o último mestre não sai nem é rebaixado
        c = Consumer("dev1", trust)
        c.apply_trust({"type": "remove_guardian", "args": {"id": "bia"}})
        with self.assertRaises(CommandError):
            c.apply_trust({"type": "remove_guardian", "args": {"id": "mel"}})
        with self.assertRaises(CommandError):
            c.apply_trust({"type": "set_role", "args": {"id": "mel", "role": "admin"}})
        c.apply_trust({"type": "set_role", "args": {"id": "ana", "role": "master"}})
        self.assertEqual(c.trust.guardians["ana"].role, "master")

    def test_promotion_to_master_uses_the_old_rule(self):
        """Sem mestre, um guardião-mor promove um guardião-mor a mestre com uma assinatura: é o único caminho para o primeiro mestre."""
        trust = trust_with(("ana", self.a), ("bia", self.b))
        p = command("dev1", "ana", 1, "set_role", {"id": "bia", "role": "master"})
        verify_envelope(trust, envelope(p, self.a.sign_command("ana", p)))
        verify_envelope(trust, envelope(p, self.a.sign_command("ana", p), self.b.sign_command("bia", p)))
        for bad in ({"id": "bia", "role": "admin"}, {"id": "bia", "role": "domains"}, {"id": "nao", "role": "master"}):
            q = command("dev1", "ana", 2, "set_role", bad)
            with self.assertRaises(CommandError, msg=str(bad)):
                verify_envelope(trust, envelope(q, self.a.sign_command("ana", q), self.b.sign_command("bia", q)))
        # nos destinos que ainda não aplicaram, o mesmo comando continua valendo depois de o gateway já ter promovido o alvo
        trust.guardians["bia"].role = "master"
        verify_envelope(trust, envelope(p, self.a.sign_command("ana", p), self.b.sign_command("bia", p)))
        # a partir daí, o guardião-mor não promove mais ninguém
        q = command("dev1", "ana", 3, "set_role", {"id": "ana", "role": "master"})
        with self.assertRaises(CommandError):
            verify_envelope(trust, envelope(q, self.a.sign_command("ana", q), self.b.sign_command("bia", q)))

    def test_consumer_json_roundtrip(self):
        c = Consumer("dev1", self.trust, {"ana": 4})
        c2 = Consumer.from_json(json.loads(json.dumps(c.to_json())))
        self.assertEqual(c2.last_ctr, {"ana": 4})
        self.assertEqual(c2.trust.guardians["bia"].creds, self.trust.guardians["bia"].creds)


class DeviceAuthAndPinbox(unittest.TestCase):
    def test_device_signature(self):
        k = devauth.new_private_key()
        h = devauth.headers(k, "GET", "/v1/x?after=1", b"", 1000, "n1")
        msg = devauth.signing_string("GET", "/v1/x?after=1", h["X-Ts"], h["X-Nonce"], b"")
        self.assertTrue(devauth.verify(devauth.spki_of(k), msg, b64.dec(h["X-Sig"])))
        self.assertFalse(devauth.verify(devauth.spki_of(k), msg + b"x", b64.dec(h["X-Sig"])))
        self.assertEqual(h["X-Dev"], devauth.device_id(devauth.spki_of(k)))
        self.assertEqual(len(h["X-Dev"]), 20)

    def test_pinbox_roundtrip_and_aad(self):
        k = devauth.new_private_key()
        box = pinbox.seal(devauth.spki_of(k), b"123456", b"dev:abc")
        self.assertEqual(pinbox.open_box(k, box, b"dev:abc"), b"123456")
        with self.assertRaises(Exception):
            pinbox.open_box(k, box, b"dev:other")
        with self.assertRaises(Exception):
            pinbox.open_box(devauth.new_private_key(), box, b"dev:abc")


if __name__ == "__main__":
    unittest.main()
