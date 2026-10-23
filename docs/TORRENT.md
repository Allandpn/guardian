# Bloqueio do protocolo BitTorrent

Os aparelhos protegidos usam o Pi como **exit node** do Tailscale. O tráfego deles (Tailscale ↔ internet) passa pelo
Suricata em modo IPS (fila NFQUEUE 0), que derruba só os pacotes com assinatura de BitTorrent. O resto passa.

| Peça | Arquivo |
|---|---|
| Regras (handshake TCP e uTP, tracker HTTP e UDP, DHT) | `deploy/suricata/torrent.rules` |
| Suricata em Docker, só com essas regras | `deploy/suricata/docker-compose.yml` |
| Encaminha `tailscale0 ↔ eth0` para a fila (`--queue-bypass`: se o Suricata cair, o tráfego passa) | `deploy/torrent-firewall.sh` |
| Sobe tudo a cada boot | `deploy/guardian-torrent-firewall.service` |

## Ligar (o que falta fora do Pi)

1. No Pi: `sudo tailscale set --advertise-exit-node`.
2. No painel do Tailscale: aprovar o Pi como exit node e, na ACL, deixar `tag:protegido` usar `autogroup:internet`
   (hoje eles só alcançam o DNS do Pi e o gateway; sem isso o exit node não funciona para eles).
3. Em cada aparelho protegido: escolher o Pi como exit node (e, no Android, ativar "permitir acesso à rede local" se precisar da LAN).
4. Instalação no boot: `sudo cp deploy/guardian-torrent-firewall.service /etc/systemd/system/ && sudo systemctl enable --now guardian-torrent-firewall`.

## Limites

- **Só vale para tráfego que passa pelo Pi.** Fora do exit node (outra rede sem ele, outro aparelho) nada é bloqueado.
- **Torrent com criptografia de protocolo (MSE/PE)** não tem assinatura legível e passa. Só um classificador por comportamento pega, e erra mais.
- **Todo o tráfego dos aparelhos sai pela internet de casa** enquanto o exit node estiver ligado.

## Testar

As regras foram validadas offline com capturas sintéticas: 6 casos de torrent alertam e 6 de tráfego normal
(HTTP, TLS, DNS, QUIC, STUN, UDP parecido com uTP) não. Ao vivo: `docker logs guardian-suricata` e `docker exec guardian-suricata tail -f /var/log/suricata/fast.log`.
