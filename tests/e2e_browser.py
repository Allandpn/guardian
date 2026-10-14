"""Teste ponta a ponta no Chromium com autenticador virtual (CDP). Rode com o Python que tem `playwright`:

    PYTHONPATH=src python tests/e2e_browser.py              # opcional: SHOTS=/pasta salva capturas de tela
    CHROME_VECTOR_OUT=/tmp/chrome.json PYTHONPATH=src python tests/e2e_browser.py   # grava um envelope assinado por passkey real

Não faz parte do `unittest discover` (precisa de playwright e do Chromium).
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from playwright.sync_api import sync_playwright  # noqa: E402

from fakepihole import FakePihole  # noqa: E402
from guardian.executor.runner import ExecConfig, Executor, GatewayClient, pair, parse_pairing  # noqa: E402
from guardian.gateway.server import create_invite  # noqa: E402
from guardian.protocol import b64, commands as cmds, devauth, pinbox  # noqa: E402
from gwharness import Env  # noqa: E402

PHONE = {"width": 390, "height": 844}
DESKTOP = {"width": 1280, "height": 820}


def main():
    env = Env()
    origin = env.cfg.origin  # localhost é "contexto seguro" no Chromium: WebAuthn funciona sem HTTPS
    token = create_invite(env.store, "new_guardian", None, "Ana", 3600)
    fake = FakePihole()
    shots = os.environ.get("SHOTS")
    out = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.environ.get("CHROME", "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"), args=["--no-sandbox"])
        ctx = browser.new_context(viewport=DESKTOP)
        page = ctx.new_page()
        logs = []
        page.on("console", lambda m: logs.append(m.text))
        page.on("pageerror", lambda e: logs.append("PAGEERROR " + str(e)))
        cdp = ctx.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True, "automaticPresenceSimulation": True}})

        def shot(name, viewport=None):
            if not shots:
                return
            os.makedirs(shots, exist_ok=True)
            if viewport:
                page.set_viewport_size(viewport)
                page.wait_for_timeout(250)
            page.screenshot(path=os.path.join(shots, name + ".png"), full_page=True)

        def back():
            """Volta ao computador e espera a página redesenhar (cruzar 900 px refaz a tela)."""
            page.set_viewport_size(DESKTOP)
            page.wait_for_timeout(900)

        def fetch(gw_, dev_, after, tries=40):
            """Pergunta ao gateway até chegar comando novo (o site assina e envia depois que a folha fecha)."""
            for _ in range(tries):
                got_ = gw_.call("GET", f"/v1/devices/{dev_}/commands?after={after}&wait=0")["commands"]
                if got_:
                    return got_
                page.wait_for_timeout(250)
            raise AssertionError("nenhum comando chegou ao gateway")

        def run_executor(cond, tries=40):
            """Roda o executor até a condição valer (o site assina e envia depois que a folha fecha)."""
            for _ in range(tries):
                ex.step(wait_s=0)
                if cond():
                    return True
                page.wait_for_timeout(250)
            return False

        def sign():
            """Folha de confirmação -> assinar com o passkey."""
            try:
                page.get_by_role("dialog").get_by_role("button", name="Assinar", exact=False).click(timeout=8000)
            except Exception:
                shot("FALHA-sem-folha")
                print("TEXTO DA PÁGINA:", page.inner_text("body")[:600])
                raise
            page.get_by_role("dialog").wait_for(state="detached", timeout=10000)

        # 1) convite -> passkey -> logado
        page.goto(f"{origin}/#invite={token}")
        shot("00-convite", PHONE)
        back()
        page.get_by_role("button", name="Cadastrar passkey").click()
        page.get_by_role("heading", name="Início").wait_for(timeout=10000)
        out["registered"] = True

        # 2) sair e entrar de novo
        page.get_by_role("button", name="Sair").click()
        shot("01-entrar", PHONE)
        back()
        page.get_by_role("button", name="Entrar com passkey").click()
        page.get_by_role("heading", name="Início").wait_for(timeout=10000)
        page.get_by_text("Nenhum aparelho pareado").wait_for()
        out["login"] = True

        # 3) parear o executor pelo assistente
        tmp = tempfile.TemporaryDirectory()
        cfg = ExecConfig(tmp.name, fake.url, "senha-app", "canario.example")
        page.goto(f"{origin}/#/pair")
        page.get_by_role("link", name="Executor do Pi-hole").click()
        page.get_by_role("button", name="Gerar código").click()
        page.locator("textarea").wait_for()
        out["executor_fp"] = pair(cfg, page.locator("textarea").input_value())
        ex = Executor(cfg)
        ex.report()
        page.get_by_text("Conferir por voz").first.wait_for(timeout=10000)
        page.get_by_role("button", name="Confere, continuar").click()
        page.get_by_text("Executor pareado").wait_for()
        page.get_by_role("button", name="Concluir").click()
        out["executor_paired_in_ui"] = True

        # 4) parear um aparelho (o NotToday de verdade é Kotlin: aqui um aparelho simulado)
        page.goto(f"{origin}/#/pair")
        page.get_by_role("button", name="Gerar código").click()
        page.locator("textarea").wait_for()
        pairing_dev = page.locator("textarea").input_value()
        shot("02-parear-passo2", PHONE)
        back()
        key = devauth.new_private_key()
        spki = devauth.spki_of(key)
        dev = devauth.device_id(spki)
        pp = parse_pairing(pairing_dev)
        gw = GatewayClient(pp["url"], key)
        gw.call("POST", "/v1/devices/register", {"pairing": pp["token"], "pubkey": b64.enc(spki), "name": "Tab S8", "kind": "device"})
        trust = cmds.Trust(pp["rp"], pp["url"], {g: cmds.Guardian(x["name"], dict(x["creds"])) for g, x in pp["guardians"].items()})
        consumer = cmds.Consumer(dev, trust)
        labels = {"dns_filter": "Filtro ativo", "new_apps_deny": "Suspender apps novos até a aprovação", "unlock_delay_min": "Atraso de desbloqueio (minutos)",
                  "canary": "Domínio-canário", "chrome_youtube": "Chrome: YouTube restrito", "r_no_safe_boot": "Bloquear modo seguro"}
        groups = {"dns_filter": "Filtro", "canary": "Filtro", "new_apps_deny": "Apps novos", "unlock_delay_min": "Segurança", "chrome_youtube": "Chrome",
                  "r_no_safe_boot": "Restrições do sistema"}
        gw.call("POST", f"/v1/devices/{dev}/report", {
            "kind": "device", "filterActive": True, "owner": False, "tailscale": True, "pinSet": False, "version": "test", "activated": False,
            "pendingApps": [{"pkg": "com.exemplo.jogo", "label": "Jogo Novo", "risks": ["nome sugere VPN/torrent/anônimo"]},
                            {"pkg": "com.exemplo.minivpn", "label": "Mini VPN", "risks": ["cria VPN"]}],
            "approvedApps": [{"pkg": "com.android.chrome", "label": "Chrome"}, {"pkg": "com.whatsapp", "label": "WhatsApp"}],
            "pending": [], "windows": {"maintenanceMs": 0, "devMs": 0, "devUsed": 0},
            "snapshot": {"dns_filter": "true", "new_apps_deny": "true", "unlock_delay_min": "1440", "canary": "canario.example", "chrome_youtube": "1", "r_no_safe_boot": "true"},
            "labels": labels, "groups": groups, "hints": {"canary": "Trocar o canário espera o atraso."}, "trust": {}, "ctrs": {}})
        page.get_by_text("Conferir por voz").first.wait_for(timeout=10000)
        shot("03-parear-passo3", PHONE)
        back()
        out["fingerprint_shown"] = devauth.fingerprint(spki) in page.locator(".fpb").inner_text() or devauth.device_id(spki)[:4] in page.locator(".fpb").inner_text()
        page.get_by_role("button", name="Confere, continuar").click()
        page.get_by_placeholder("PIN local").fill("246810")
        page.get_by_role("button", name="Definir PIN e atraso").click()
        page.get_by_role("dialog").wait_for()
        shot("04-confirmar-pin", PHONE)
        back()
        sign()
        got = fetch(gw, dev, 0)
        v = consumer.accept(got[0]["envelope"])
        out["pin_roundtrip"] = pinbox.open_box(key, v.cmd["args"]["box"], f"guardian/set_pin/{dev}".encode()) == b"246810"
        page.get_by_role("button", name="Ativar aparelho").click()
        sign()
        got = fetch(gw, dev, got[-1]['seq'])
        out["activate_verified"] = consumer.accept(got[0]["envelope"]).cmd["type"] == "activate"
        page.get_by_text("Aparelho pareado e ativado").wait_for()
        page.get_by_role("button", name="Concluir").click()
        last = got[-1]["seq"]

        # 5) início, aprovar app pelo site
        page.get_by_role("heading", name="Início").wait_for()
        shot("05-inicio-celular", PHONE)
        shot("06-inicio-computador", DESKTOP)
        page.goto(f"{origin}/#/device/{dev}/apps")
        page.get_by_text("Mini VPN").first.wait_for(timeout=10000)
        shot("07-apps", PHONE)
        back()
        page.get_by_role("button", name="Aprovar").first.click()
        shot("08-confirmar-app", PHONE)
        back()
        sign()
        got = fetch(gw, dev, last)
        v = consumer.accept(got[0]["envelope"])
        out["approve_verified"] = (v.cmd["type"], v.cmd["args"]["pkg"])
        last = got[-1]["seq"]
        if os.environ.get("CHROME_VECTOR_OUT"):  # envelope assinado por um passkey real do Chromium, para os testes do Kotlin
            json.dump({"dev": dev, "type": v.cmd["type"], "trust": cmds.Trust(pp["rp"], pp["url"], {
                g: cmds.Guardian(x["name"], dict(x["creds"])) for g, x in pp["guardians"].items()}).to_json(), "envelope": got[0]["envelope"]},
                open(os.environ["CHROME_VECTOR_OUT"], "w"))

        # 6) regras: várias mudanças, um toque
        page.goto(f"{origin}/#/device/{dev}/regras")
        page.get_by_role("switch", name="Suspender apps novos até a aprovação").wait_for(timeout=10000)
        page.get_by_role("switch", name="Suspender apps novos até a aprovação").click()
        page.get_by_text("1 alteração").wait_for()
        shot("09-regras", PHONE)
        back()
        page.get_by_role("button", name="Revisar e assinar").click()
        page.get_by_role("dialog").get_by_text("espera 24 h").first.wait_for()
        shot("10-confirmar-regras", PHONE)
        back()
        sign()
        got = fetch(gw, dev, last)
        v = consumer.accept(got[0]["envelope"])
        out["set_config_verified"] = v.cmd["type"] == "set_config" and v.cmd["args"]["patch"] == {"new_apps_deny": "false"}
        last = got[-1]["seq"]

        # 7) domínio temporário pelo site -> executor -> Pi-hole falso
        page.goto(f"{origin}/#/domains/liberados")
        page.get_by_placeholder("exemplo.com").fill("Liberado.Exemplo.com")
        page.get_by_role("button", name="Liberar", exact=True).click()
        page.get_by_role("dialog").get_by_text("1 hora").first.wait_for()
        sign()
        run_executor(lambda: "liberado.exemplo.com" in fake.lists["allow"])
        out["allowed"] = "liberado.exemplo.com" in fake.lists["allow"]
        out["temp_recorded"] = len(ex.state.data["temp"]) == 1
        ex.report()
        page.reload()
        page.get_by_text("liberado.exemplo.com").first.wait_for(timeout=10000)
        shot("11-dominios", PHONE)
        back()
        out["listed_in_ui"] = True

        # 8) o canário não é liberado, mesmo com comando válido
        page.get_by_placeholder("exemplo.com").fill("canario.example")
        page.get_by_role("button", name="Liberar", exact=True).click()
        before = sum(ex.consumer.last_ctr.values())
        sign()
        run_executor(lambda: sum(ex.consumer.last_ctr.values()) > before)  # o executor recebeu e recusou o comando
        ex.report()
        out["canary_refused"] = "canario.example" not in fake.lists["allow"]

        # 9) pessoas e histórico
        page.goto(f"{origin}/#/people")
        page.get_by_role("heading", name="Pessoas").wait_for()
        page.get_by_text("Só 1 passkey").wait_for()
        shot("12-pessoas", PHONE)
        back()
        page.goto(f"{origin}/#/history")
        page.get_by_text("liberar domínio").first.wait_for(timeout=10000)
        out["history_ui"] = True
        shot("13-historico", PHONE)
        back()
        out["console_errors"] = [x for x in logs if "error" in x.lower() or "PAGEERROR" in x]
        browser.close()
    fake.close()
    env.close()
    print(json.dumps(out, indent=1, ensure_ascii=False))
    need = ("registered", "login", "pin_roundtrip", "activate_verified", "set_config_verified", "allowed", "canary_refused", "history_ui")
    return 0 if all(out.get(k) is True for k in need) and not out["console_errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
