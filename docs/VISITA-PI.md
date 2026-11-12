# Visita ao Pi sem teclado, monitor nem senha

Para instalar o deployer novo (ele não se atualiza por deploy) sem reabrir o acesso de ninguém. O Pi arranca do SSD; a partição de boot dele
(a pequena, FAT) abre no Windows, e o `cmdline.txt` pode chamar um script uma vez, como root, no arranque. É o mesmo mecanismo que o Raspberry Pi
Imager usa para configurar um Pi sem tela. O script (`tools/visita-pi/guardian-visita.sh`) só faz o que está nele e se apaga; ninguém ganha senha nem sudo.

## Antes (pelo Guardian)
1. Etiqueta `release/15` no commit `dbb040b1b01ab8c6011da824e47e0f631bee5248` (é o que o script confere).
2. Na janela, o mestre coloca a `release/15` no ar em **Deploys** (vem com o aviso vermelho: esperado).
3. Baixe para o PC, pelo botão **Download raw file** do GitHub (não copie e cole o texto, nem salve pelo Bloco de Notas: o fim de linha do Windows quebra o script):
   `https://github.com/Allandpn/guardian/blob/main/tools/visita-pi/guardian-visita.sh`

## No Pi
1. Tire o Pi da tomada (o Pi-hole e os serviços caem por alguns minutos).
2. Desligue o SSD do Pi e ligue no PC (pelo mesmo adaptador USB). O Windows mostra uma unidade pequena (`bootfs`).
   **Se o Windows oferecer formatar a outra partição do disco, clique em Cancelar. Nunca formate.**
3. Copie o `guardian-visita.sh` para a raiz da `bootfs`.
4. Abra o `cmdline.txt` da `bootfs` no Bloco de Notas. É uma linha só. No FIM dela, sem quebrar a linha, acrescente um espaço e:
   ```
   systemd.run=/boot/firmware/guardian-visita.sh systemd.run_success_action=reboot systemd.unit=kernel-command-line.target
   ```
   Se o sistema do Pi for anterior a outubro de 2023 (o arquivo `issue.txt` da `bootfs` mostra a data), troque `/boot/firmware/` por `/boot/`.
5. Salve, ejete o SSD com segurança, ligue-o de volta no Pi e ligue o Pi na tomada.

O Pi arranca, prepara (fase 1), reinicia sozinho e, no arranque normal, faz a visita (fase 2): confere que a versão no ar é a `release/15`, guarda uma cópia do
registro (`projects.json.antes-da-visita`), troca a entrada `guardian` pela do `deploy/deploy-projects.example.json` (mantém endereço, token e checagens do Pi),
roda `deploy/install-deployer.sh`, reinicia o deployer e o executor e confere que o deployer novo respondeu. O `cmdline.txt` volta ao normal logo na fase 1.

## Depois (pelo site, uns 10 minutos)
- **Deploys > Últimos deploys** mostra uma linha `visita deployer`: **no ar** (deu certo) ou **recusado**, com o motivo.
- **PC > Executar agora > Raspberry Pi**: o botão libera. Teste com `uptime`.

## Se algo der errado
- Se a versão no ar não for a esperada, o script **não muda nada** e só registra o motivo.
- Se o `install-deployer.sh` falhar, o registro volta ao que era.
- O relato completo fica em `guardian-visita.log`, na `bootfs`. Para lê-lo é preciso desligar o Pi e ligar o SSD no PC de novo.
- Se o Pi não voltar (site fora do ar por mais de 15 min), desligue, ligue o SSD no PC e confira se o `cmdline.txt` ainda tem o `systemd.run=...`; se tiver, apague
  esse trecho (deixe o resto da linha como estava) e ligue de novo. Leia o `guardian-visita.log` e mande o texto para quem cuida do código.
