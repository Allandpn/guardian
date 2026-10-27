# Contrato para o NotToday: instalar e atualizar apps (inclusive o próprio NotToday)

O gateway e o site do Guardian já fazem a parte deles (docs/DEPLOY.md, "Apps Android"). Falta o lado do aparelho.

## Comando novo: `install_app`

Mesmo envelope dos outros comandos (assinado por passkey, `dev` = este aparelho, contador por guardião). Tipo `install_app`, argumentos:

    {"pkg": "com.exemplo.app", "sha256": "<64 hex minúsculos>", "size": 1234567, "version_name": "1.2.0", "version_code": 12}

`version_name` e `version_code` são opcionais e só informativos. Regras que o aparelho deve conferir **como para todo comando**:
assinatura válida, autor com papel **mestre** (só ele assina `install_app`), janela de horário do autor, contador, `dev`. Em Python: `protocol/commands.py`
(`T_INSTALL_APP`, `check_install_args`, `MASTER_TYPES`). Argumentos fora do formato acima: recusar.

## Baixar

`GET /v1/devices/{dev}/apk/{sha256}` com os cabeçalhos assinados de sempre (`X-Dev`, `X-Ts`, `X-Nonce`, `X-Sig`; corpo vazio).
- 200: o APK, `Content-Type: application/vnd.android.package-archive`, com `Content-Length`. Calcule o SHA-256 enquanto grava num arquivo.
- 403: nenhum comando assinado autoriza este hash neste aparelho. 404: o APK ainda não chegou ao gateway (o Pi o envia em até ~1 min): tente de novo depois.

## Conferir antes de instalar (qualquer falha: apagar o arquivo, não instalar, reportar)

1. SHA-256 do arquivo == `args.sha256` e tamanho == `args.size`.
2. `PackageManager.getPackageArchiveInfo(arquivo, GET_SIGNING_CERTIFICATES)`: `packageName == args.pkg`.
3. App já instalado: o certificado de assinatura do arquivo tem de ser o do app instalado (o Android já exige para atualizar) e `versionCode` maior que o instalado
   (sem downgrade). App novo: guardar o SHA-256 do certificado na primeira instalação e exigir o mesmo nas próximas.

## Instalar em silêncio (Device Owner)

`PackageInstaller` com `SessionParams.MODE_FULL_INSTALL`, `setAppPackageName(args.pkg)`, `setRequireUserAction(USER_ACTION_NOT_REQUIRED)` (API 31+), gravar o arquivo na sessão,
`session.commit(IntentSender)`. Um Device Owner não precisa de toque do usuário. Isso **não** depende de "fontes desconhecidas" nem de depuração USB.

## Atualizar o próprio NotToday

Mesmo comando, com `pkg == com.allan.nottoday`. A substituição mata o processo; o Device Owner continua porque o pacote e o certificado são os mesmos.
Reinicie o que for preciso em `ACTION_MY_PACKAGE_REPLACED` (VPN/filtro, relatório) e reporte o resultado na primeira inicialização depois da troca.
Nunca instalar um NotToday com certificado diferente.

## Resultado

Reporte no relatório assinado, em `executed`: `{"type": "install_app", "ok": true|false, "msg": "instalado com.exemplo.app 1.2.0" | "hash não confere" | ...}`.
Depois de instalar um app novo, ele cai em `pendingApps` como qualquer app novo: o guardião ainda precisa aprová-lo em Apps para ele rodar.

## Testes sugeridos

- Comando de guardião que não é mestre, ou fora da janela: recusado.
- Arquivo com hash errado, pacote diferente, certificado diferente, versionCode menor: não instala.
- Atualização do próprio app mantém o Device Owner e volta a reportar.
