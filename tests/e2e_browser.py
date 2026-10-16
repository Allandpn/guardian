"""Teste ponta a ponta no Chromium com autenticador virtual (CDP). Rode com o Python que tem `playwright`:

    PYTHONPATH=src python tests/e2e_browser.py              # opcional: SHOTS=/pasta salva capturas de tela
    CHROME_VECTOR_OUT=/tmp/chrome.json PYTHONPATH=src python tests/e2e_browser.py   # grava um envelope assinado por passkey real

Não faz parte do `unittest discover` (precisa de playwright e do Chromium).
"""
import datetime
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

        audit_js = """() => {
          const W = innerWidth, out = [];
          if (document.documentElement.scrollWidth > W + 1) out.push('rolagem horizontal: ' + document.documentElement.scrollWidth + 'px');
          const desc = (e) => (e.tagName.toLowerCase() + (e.className && typeof e.className === 'string' ? '.' + e.className.split(' ').join('.') : '') + ' "' + (e.innerText || e.value || e.getAttribute('aria-label') || '').trim().slice(0, 40) + '"');
          for (const e of document.querySelectorAll('#main *, #nav *, .sheet *')) {
            const r = e.getBoundingClientRect();
            if (!r.width || !r.height || getComputedStyle(e).visibility === 'hidden') continue;
            let clip = false;
            for (let p = e.parentElement; p; p = p.parentElement) { const o = getComputedStyle(p); if (/(auto|scroll|hidden)/.test(o.overflowX)) { clip = true; break; } }
            if (r.right > W + 1 && !clip) out.push('vaza ' + Math.round(r.right - W) + 'px: ' + desc(e));
            const tap = e.matches('button, a[href], [role=button], input:not([type=hidden]), select, textarea');
            if (tap && (r.height < 40 || r.width < 40)) out.push('alvo pequeno ' + Math.round(r.width) + 'x' + Math.round(r.height) + ': ' + desc(e));
            if (e.matches('input, select, textarea') && parseFloat(getComputedStyle(e).fontSize) < 16) out.push('zoom no iPhone (fonte ' + getComputedStyle(e).fontSize + '): ' + desc(e));
          }
          return [...new Set(out)];
        }"""

        def audit(name):
            for w in (320, 360):
                page.set_viewport_size({"width": w, "height": 740})
                page.wait_for_timeout(300)
                issues = page.evaluate(audit_js)
                if issues:
                    out.setdefault("mobile_issues", {})[f"{name}@{w}"] = issues
                    print(f"AUDIT {name}@{w}: " + json.dumps(issues, ensure_ascii=False), file=sys.stderr, flush=True)

        def shot(name, viewport=None):
            if os.environ.get("AUDIT") and viewport == PHONE:
                audit(name)
            if not shots:
                return
            os.makedirs(shots, exist_ok=True)
            if viewport:
                page.set_viewport_size(viewport)
                page.wait_for_timeout(250)
            page.screenshot(path=os.path.join(shots, name + ".png"), full_page=True)
            if os.environ.get("WIDE") and viewport == PHONE:  # também em tablet e computador, para conferir o layout largo
                for tag, vp in (("t", {"width": 820, "height": 1100}), ("d", {"width": 1366, "height": 800})):
                    page.set_viewport_size(vp)
                    page.wait_for_timeout(900)
                    page.screenshot(path=os.path.join(shots, f"{name}-{tag}.png"), full_page=True)
                page.set_viewport_size(PHONE)
                page.wait_for_timeout(500)

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
        page.go_back()  # voltar do Android/navegador fecha a folha e fica na mesma tela
        page.get_by_role("dialog").wait_for(state="detached", timeout=10000)
        out["back_closes_sheet"] = page.url.endswith(f"#/device/{dev}/apps")
        page.get_by_role("button", name="Aprovar").first.click()
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

        # 6b) fluxo de liberação: bloqueio no Pi-hole -> executor -> pedido do aparelho -> guardião decide
        import time as _t
        now_ = _t.time()
        ex.cfg.clients = {"100.64.0.7": dev}
        fake.queries += [{"time": now_ - 30, "domain": "cdn.video.exemplo.com", "status": "REGEX", "client": {"ip": "100.64.0.7"}},
                         {"time": now_ - 20, "domain": "api.video.exemplo.com", "status": "DENYLIST", "client": {"ip": "100.64.0.7"}},
                         {"time": now_ - 10, "domain": "ads.rastreador.net", "status": "GRAVITY", "list_id": 7, "client": {"ip": "100.64.0.7"}}]
        ex.collect_blocks()
        page.goto(f"{origin}/#/domains/bloqueios")
        page.get_by_text("cdn.video.exemplo.com").first.wait_for(timeout=10000)
        out["blocks_hidden_ads"] = page.get_by_text("ads.rastreador.net").count() == 0
        page.get_by_role("button", name="Listas", exact=True).click()
        page.get_by_text("ads.rastreador.net").first.wait_for(timeout=10000)
        page.get_by_role("button", name="Regras próprias", exact=True).click()
        shot("14-bloqueios", PHONE)
        back()
        gw.call("POST", f"/v1/devices/{dev}/requests", {"kind": "unblock", "domains": ["cdn.video.exemplo.com", "api.video.exemplo.com"]})
        page.goto(f"{origin}/#/pedidos")
        page.get_by_text("api.video.exemplo.com").first.wait_for(timeout=10000)
        page.get_by_role("group", name="Escolha para api.video.exemplo.com").get_by_role("button", name="1 h").click()
        page.get_by_role("group", name="Escolha para cdn.video.exemplo.com").get_by_role("button", name="Sempre").wait_for()
        shot("15-pedidos", PHONE)
        back()
        page.get_by_role("button", name="Confirmar com passkey").click()
        page.get_by_role("dialog").get_by_text("api.video.exemplo.com").first.wait_for()
        sign()
        run_executor(lambda: "cdn.video.exemplo.com" in fake.lists["allow"] and "api.video.exemplo.com" in fake.lists["allow"])
        out["unblock_applied"] = "cdn.video.exemplo.com" in fake.lists["allow"] and "api.video.exemplo.com" in fake.lists["allow"]
        out["unblock_ttl"] = sorted(t["domain"] for t in ex.state.data["temp"]) == ["api.video.exemplo.com"]
        for _ in range(40):
            rq = gw.call("GET", f"/v1/devices/{dev}/requests")["requests"]
            if rq and rq[0]["status"] == "done":
                break
            page.wait_for_timeout(250)
        out["unblock_state_back_to_device"] = {i["domain"]: i["state"] for i in rq[0]["items"]} == {"cdn.video.exemplo.com": "allowed", "api.video.exemplo.com": "allowed"}
        ex.report()
        page.goto(f"{origin}/#/domains/liberados")
        page.get_by_role("button", name="Bloquear de novo").first.wait_for(timeout=10000)
        shot("16-liberados", PHONE)
        back()
        page.get_by_role("button", name="Bloquear de novo").first.click()
        sign()
        run_executor(lambda: "cdn.video.exemplo.com" not in fake.lists["allow"] or "api.video.exemplo.com" not in fake.lists["allow"])
        out["block_again"] = len([d for d in ("cdn.video.exemplo.com", "api.video.exemplo.com") if d in fake.lists["allow"]]) == 1

        # 7) domínio temporário pelo site -> executor -> Pi-hole falso
        page.goto(f"{origin}/#/domains/liberados")
        page.get_by_text("Avançado").click()
        page.get_by_role("group", name="Duração").get_by_role("button", name="1 hora").click()
        page.get_by_role("group", name="Duração").get_by_role("button", name="1 hora", pressed=True).wait_for()  # a tela redesenha
        page.get_by_placeholder("exemplo.com").fill("Liberado.Exemplo.com")
        page.get_by_role("button", name="Liberar", exact=True).click()
        try:
            page.get_by_role("dialog").get_by_text("1 hora").first.wait_for(timeout=8000)
        except Exception:
            print("DEBUG", page.inner_text("body")[:1500], file=sys.stderr)
            raise
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
        page.goto(f"{origin}/#/domains/liberados")
        page.get_by_text("Avançado").click()
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
        page.get_by_text("Cadastre uma chave de reserva").wait_for()
        shot("12-pessoas", PHONE)
        back()

        # 10) guardião só de domínios, num segundo navegador
        page.get_by_placeholder("nome do guardião").fill("Bia")
        page.get_by_role("button", name="Gerar link de convite").click()
        link = page.locator("textarea").first.input_value()
        ctx2 = browser.new_context(viewport=PHONE)
        page2 = ctx2.new_page()
        page2.on("pageerror", lambda e: logs.append("PAGEERROR2 " + str(e)))
        cdp2 = ctx2.new_cdp_session(page2)
        cdp2.send("WebAuthn.enable")
        cdp2.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True, "automaticPresenceSimulation": True}})
        page2.goto(link)
        page2.get_by_role("button", name="Cadastrar passkey").click()
        page2.get_by_role("heading", name="Domínios").wait_for(timeout=10000)
        navtext = page2.locator("#nav").inner_text()
        out["domain_guardian_nav"] = "Conta" in navtext and "Pessoas" not in navtext and "Início" not in navtext
        page.reload()
        page.get_by_text("Bia").first.wait_for(timeout=10000)
        exrow = page.locator(".li", has_text="executor")
        exrow.get_by_role("button", name="Propagar").click()
        sign()
        run_executor(lambda: any(g.name == "Bia" for g in ex.consumer.trust.guardians.values()))
        ana = next((g for g in ex.consumer.trust.guardians.values() if g.name == "Bia"), None)
        out["executor_knows_domain_role"] = bool(ana) and ana.role == "domains"
        ex.report()
        page.reload()
        devrow = page.locator(".li", has_text="Tab S8")
        devrow.wait_for(timeout=10000)
        out["device_does_not_need_domain_guardian"] = "Bia" not in devrow.inner_text()
        shot("17-pessoas-papeis", PHONE)
        back()
        fake.queries.append({"time": _t.time() - 5, "domain": "escola.exemplo.com", "status": "REGEX", "client": {"ip": "100.64.0.7"}})
        ex.collect_blocks()
        gw.call("POST", f"/v1/devices/{dev}/requests", {"kind": "unblock", "domains": ["escola.exemplo.com"]})
        page2.goto(f"{origin}/#/domains/bloqueios")  # guardião de domínios: mínimo, só os pedidos (sem abas e sem Histórico)
        page2.get_by_text("escola.exemplo.com").first.wait_for(timeout=10000)
        out["domain_guardian_minimal"] = (page2.get_by_role("link", name="Bloqueios").count() == 0 and page2.get_by_role("link", name="Liberados").count() == 0
                                          and "Histórico" not in page2.locator("#nav").inner_text())
        if shots:
            page2.set_viewport_size(PHONE)
            page2.wait_for_timeout(300)
            page2.screenshot(path=os.path.join(shots, "21-guardiao-pedidos.png"), full_page=True)
        page2.get_by_role("group", name="Escolha para escola.exemplo.com").get_by_role("button", name="Sempre").click()
        page2.get_by_role("button", name="Confirmar com passkey").click()
        page2.get_by_role("dialog").get_by_role("button", name="Assinar", exact=False).click(timeout=8000)
        page2.get_by_role("dialog").wait_for(state="detached", timeout=10000)
        run_executor(lambda: "escola.exemplo.com" in fake.lists["allow"])
        out["domain_guardian_allowed"] = "escola.exemplo.com" in fake.lists["allow"]
        # "Liberar todos": vários pedidos abertos, um comando e um passkey só
        for n, dom in enumerate(("lote1.exemplo.com", "lote2.exemplo.com", "lote3.exemplo.com")):
            fake.queries.append({"time": _t.time() - 4 + n * 0.1, "domain": dom, "status": "REGEX", "client": {"ip": "100.64.0.7"}})
        ex.collect_blocks()
        gw.call("POST", f"/v1/devices/{dev}/requests", {"kind": "unblock", "domains": ["lote1.exemplo.com", "lote2.exemplo.com"]})
        gw.call("POST", f"/v1/devices/{dev}/requests", {"kind": "unblock", "domains": ["lote3.exemplo.com"]})
        page2.goto(f"{origin}/#/domains/pedidos")
        page2.reload()
        page2.get_by_role("button", name="Liberar todos (3) com um passkey").wait_for(timeout=10000)
        page2.get_by_role("group", name="Escolha para lote2.exemplo.com").get_by_role("button", name="1 h").click()
        if shots:
            page2.set_viewport_size(PHONE)
            page2.wait_for_timeout(300)
            page2.screenshot(path=os.path.join(shots, "22-liberar-todos.png"), full_page=True)
        page2.get_by_role("button", name="Liberar todos (3) com um passkey").click()
        page2.get_by_role("dialog").get_by_role("button", name="Assinar", exact=False).click(timeout=8000)
        page2.get_by_role("dialog").wait_for(state="detached", timeout=10000)
        run_executor(lambda: {"lote1.exemplo.com", "lote2.exemplo.com", "lote3.exemplo.com"} <= set(fake.lists["allow"]))
        page2.get_by_text("Nenhum pedido de liberação").wait_for(timeout=10000)
        out["release_all_one_passkey"] = ({"lote1.exemplo.com", "lote2.exemplo.com", "lote3.exemplo.com"} <= set(fake.lists["allow"])
                                          and any(t["domain"] == "lote2.exemplo.com" for t in ex.state.data["temp"])
                                          and not any(t["domain"] == "lote1.exemplo.com" for t in ex.state.data["temp"]))
        page2.goto(f"{origin}/#/device/{dev}")
        page2.get_by_text("não liberou a visualização").wait_for(timeout=10000)
        page.goto(f"{origin}/#/people")
        page.get_by_role("group", name="O que Bia pode ver").get_by_role("button", name="Estado dos aparelhos").click()
        page.get_by_role("group", name="O que Bia pode ver").get_by_role("button", name="Estado dos aparelhos", pressed=True).wait_for(timeout=10000)
        page2.goto(f"{origin}/#/device/{dev}")
        page2.reload()
        page2.get_by_text("Filtro CONFIRMADO").wait_for(timeout=10000)
        out["visibility_toggle"] = True
        page2.goto(f"{origin}/#/people")
        page2.get_by_role("heading", name="Conta").wait_for(timeout=10000)
        if shots:
            page2.screenshot(path=os.path.join(shots, "18-conta.png"), full_page=True)
        ctx2.close()
        page.goto(f"{origin}/#/history")
        page.get_by_text("liberar domínio").first.wait_for(timeout=10000)
        out["history_ui"] = True
        shot("13-historico", PHONE)
        back()
        # 11) guardião-mor do trabalho: só neste aparelho + horário (a passkey sincronizada é recusada)
        page.goto(f"{origin}/#/people")
        page.get_by_placeholder("nome do guardião").fill("Trabalho")
        page.get_by_role("button", name="Guardião-mor", exact=True).click()
        page.get_by_role("button", name="Só neste aparelho", pressed=True).wait_for()  # padrão do guardião-mor
        page.get_by_role("button", name="Só em um horário").click()
        for d in ("sáb", "dom"):
            page.get_by_role("button", name=d, exact=True).click()
        page.get_by_label("Início", exact=True).fill("00:00")
        page.get_by_label("Fim", exact=True).fill("23:59")
        page.get_by_role("button", name="Gerar link de convite").click()
        link2 = page.locator("textarea").first.input_value()
        ctx3 = browser.new_context(viewport=PHONE)
        page3 = ctx3.new_page()
        cdp3 = ctx3.new_cdp_session(page3)
        cdp3.send("WebAuthn.enable")
        opts = {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
                "isUserVerified": True, "automaticPresenceSimulation": True}
        synced = cdp3.send("WebAuthn.addVirtualAuthenticator", {"options": {**opts, "defaultBackupEligibility": True, "defaultBackupState": True}})
        page3.goto(link2)
        page3.get_by_role("button", name="Cadastrar passkey").click()
        page3.get_by_text("seria sincronizada").wait_for(timeout=10000)
        out["synced_passkey_refused"] = True
        cdp3.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": synced["authenticatorId"]})
        cdp3.send("WebAuthn.addVirtualAuthenticator", {"options": {**opts, "defaultBackupEligibility": False}})
        page3.get_by_role("button", name="Cadastrar passkey").click()
        page3.get_by_role("heading", name="Início").wait_for(timeout=10000)
        out["device_bound_passkey_accepted"] = True
        page.reload()
        page.get_by_text("só neste aparelho").first.wait_for(timeout=10000)
        page.get_by_text("seg–dom, 0h às 23h59").wait_for(timeout=10000)
        shot("19-pessoas-politica", PHONE)
        back()
        env.store.x("UPDATE guardians SET window=? WHERE name='Trabalho'", (json.dumps({"days": [(datetime.datetime.now(datetime.timezone.utc).weekday() + 3) % 7], "from": 0, "to": 1440, "utc_offset_min": 0}),))
        page3.reload()
        page3.get_by_role("heading", name="Fora do horário").wait_for(timeout=10000)
        out["out_of_window_screen"] = True
        if shots:
            page3.screenshot(path=os.path.join(shots, "20-fora-do-horario.png"), full_page=True)
        ctx3.close()
        out["console_errors"] = [x for x in logs if "error" in x.lower() or "PAGEERROR" in x]
        browser.close()
    fake.close()
    env.close()
    print(json.dumps(out, indent=1, ensure_ascii=False))
    need = ("registered", "login", "pin_roundtrip", "activate_verified", "set_config_verified", "allowed", "blocks_hidden_ads", "unblock_applied", "unblock_ttl", "unblock_state_back_to_device", "block_again", "canary_refused", "history_ui", "domain_guardian_nav", "domain_guardian_minimal", "release_all_one_passkey", "executor_knows_domain_role", "device_does_not_need_domain_guardian", "domain_guardian_allowed", "visibility_toggle", "back_closes_sheet", "synced_passkey_refused", "device_bound_passkey_accepted", "out_of_window_screen")
    return 0 if all(out.get(k) is True for k in need) and not out["console_errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
