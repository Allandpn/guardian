"""Teste ponta a ponta no Chromium com autenticador virtual (CDP). Rode com o Python que tem `playwright`:

    PYTHONPATH=src python tests/e2e_browser.py

Não faz parte do `unittest discover` (precisa de playwright e do Chromium).
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from playwright.sync_api import sync_playwright  # noqa: E402

from guardian.executor.runner import ExecConfig, Executor, pair  # noqa: E402
from fakepihole import FakePihole  # noqa: E402
from gwharness import Env  # noqa: E402
from guardian.gateway.server import create_invite  # noqa: E402
from guardian.protocol import b64, commands as cmds, devauth, pinbox  # noqa: E402


def main():
    env = Env()
    # localhost é "contexto seguro" no Chromium, então WebAuthn funciona sem HTTPS
    origin = env.cfg.origin
    token = create_invite(env.store, "new_guardian", None, "Ana", 3600)
    fake = FakePihole()
    out = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.environ.get("CHROME", "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"),
                                    args=["--no-sandbox"])
        ctx = browser.new_context()
        page = ctx.new_page()
        logs = []
        page.on("console", lambda m: logs.append(m.text))
        page.on("pageerror", lambda e: logs.append("PAGEERROR " + str(e)))
        cdp = ctx.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True, "automaticPresenceSimulation": True}})

        # 1) convite -> registro do passkey
        page.goto(f"{origin}/#invite={token}")
        page.get_by_role("button", name="Cadastrar passkey").click()
        page.get_by_text("Aparelhos").first.wait_for(timeout=10000)
        out["registered"] = True

        # 2) sair e entrar de novo com o passkey
        page.get_by_role("link", name="Sair").click()
        page.get_by_role("button", name="Entrar com passkey").click()
        page.get_by_role("heading", name="Aparelhos").wait_for(timeout=10000)
        out["login"] = True

        # 3) parear um executor e um aparelho pela tela
        page.goto(f"{origin}/#/guardians")
        page.get_by_role("button", name="Parear executor Pi-hole").click()
        pairing_exec = page.locator("textarea").input_value()
        page.get_by_role("button", name="Parear aparelho").click()
        page.wait_for_function("(old) => document.querySelector('textarea').value !== old", arg=pairing_exec)
        pairing_dev = page.locator("textarea").input_value()

        tmp = tempfile.TemporaryDirectory()
        cfg = ExecConfig(tmp.name, fake.url, "senha-app", "canario.example")
        out["executor_fp"] = pair(cfg, pairing_exec)
        ex = Executor(cfg)

        # aparelho simulado (o NotToday de verdade é Kotlin): registra e reporta com um app pendente
        key = devauth.new_private_key()
        spki = devauth.spki_of(key)
        dev = devauth.device_id(spki)
        from guardian.executor.runner import GatewayClient, parse_pairing
        pp = parse_pairing(pairing_dev)
        gw = GatewayClient(pp["url"], key)
        gw.call("POST", "/v1/devices/register", {"pairing": pp["token"], "pubkey": b64.enc(spki), "name": "Celular", "kind": "device"})
        trust = cmds.Trust(pp["rp"], pp["url"], {g: cmds.Guardian(v["name"], dict(v["creds"])) for g, v in pp["guardians"].items()})
        consumer = cmds.Consumer(dev, trust)
        gw.call("POST", f"/v1/devices/{dev}/report", {
            "kind": "device", "filterActive": True, "owner": True, "tailscale": True, "pinSet": False, "version": "test",
            "pendingApps": [{"pkg": "com.exemplo.jogo", "label": "Jogo", "risks": ["nome sugere VPN/torrent/anônimo"]}],
            "pending": [], "snapshot": {"unlock_delay_min": "1440", "new_apps_deny": "true"}, "trust": {}, "ctrs": {}})
        ex.report()

        # 4) aprovar o app pelo site (assinatura com passkey)
        page.goto(f"{origin}/#/device/{dev}")
        page.get_by_text("Jogo").first.wait_for(timeout=10000)
        page.get_by_role("button", name="Aprovar").click()
        page.get_by_text("Comando enviado").wait_for(timeout=10000)
        got = gw.call("GET", f"/v1/devices/{dev}/commands?after=0&wait=0")["commands"]
        v = consumer.accept(got[0]["envelope"])
        out["approve_verified"] = (v.cmd["type"], v.cmd["args"]["pkg"])
        if os.environ.get("CHROME_VECTOR_OUT"):  # envelope assinado por um passkey real do Chromium, para os testes do Kotlin
            vec = {"dev": dev, "type": v.cmd["type"], "trust": cmds.Trust(pp["rp"], pp["url"], {
                g: cmds.Guardian(x["name"], dict(x["creds"])) for g, x in pp["guardians"].items()}).to_json(),
                "envelope": got[0]["envelope"]}
            json.dump(vec, open(os.environ["CHROME_VECTOR_OUT"], "w"))

        # 5) PIN cifrado no navegador, aberto no "aparelho"
        page.reload()
        page.get_by_placeholder("PIN (6+ dígitos)").fill("246810")
        page.get_by_role("button", name="Definir PIN local").click()
        page.get_by_text("Comando enviado").wait_for(timeout=10000)
        got = gw.call("GET", f"/v1/devices/{dev}/commands?after={got[-1]['seq']}&wait=0")["commands"]
        v = consumer.accept(got[0]["envelope"])
        pin = pinbox.open_box(key, v.cmd["args"]["box"], f"guardian/set_pin/{dev}".encode())
        out["pin_roundtrip"] = pin == b"246810"

        # 6) liberar domínio temporário pelo site -> executor aplica no Pi-hole falso
        page.goto(f"{origin}/#/domains")
        page.get_by_placeholder("exemplo.com").fill("Liberado.Exemplo.com")
        page.locator("select").first.select_option(label="1 hora")
        page.get_by_role("button", name="Liberar", exact=True).click()
        page.get_by_text("Comando enviado").wait_for(timeout=10000)
        ex.step(wait_s=0)
        out["allowed"] = "liberado.exemplo.com" in fake.lists["allow"]
        out["temp_recorded"] = len(ex.state.data["temp"]) == 1
        page.reload()
        page.get_by_text("liberado.exemplo.com").first.wait_for(timeout=10000)
        out["listed_in_ui"] = True

        # 7) o canário não é liberado, mesmo com comando válido
        page.get_by_placeholder("exemplo.com").fill("canario.example")
        page.get_by_role("button", name="Liberar", exact=True).click()
        page.get_by_text("Comando enviado").wait_for(timeout=10000)
        ex.step(wait_s=0)
        out["canary_refused"] = "canario.example" not in fake.lists["allow"]

        # 8) página de auditoria renderiza
        page.goto(f"{origin}/#/audit")
        page.get_by_text("pihole_allow ok").first.wait_for(timeout=10000)
        out["audit_ui"] = True
        out["console_errors"] = [l for l in logs if "error" in l.lower() or "PAGEERROR" in l]
        browser.close()
    fake.close()
    env.close()
    print(json.dumps(out, indent=1, ensure_ascii=False))
    ok = all(v is True or isinstance(v, (str, list, tuple)) for v in out.values()) and not out["console_errors"]
    return 0 if ok and out["allowed"] and out["canary_refused"] and out["pin_roundtrip"] else 1


if __name__ == "__main__":
    sys.exit(main())
