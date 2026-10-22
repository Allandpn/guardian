# Atualiza o Guardian Agent do computador a partir do repositório público (branch main).
# Para colar em "Executar agora" na tela PC do site (um guardião-mor ou o mestre assina com a passkey).
# Roda como SYSTEM. A reinstalação para o próprio agente, então vai numa tarefa agendada separada.
$ErrorActionPreference = 'Stop'
$w = 'C:\ProgramData\GuardianAgent\update'
Remove-Item $w -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $w -Force | Out-Null
Invoke-WebRequest 'https://github.com/Allandpn/guardian/archive/refs/heads/main.zip' -OutFile "$w\g.zip" -UseBasicParsing
Expand-Archive "$w\g.zip" -DestinationPath $w -Force
$inst = "$w\guardian-main\src\guardian\agent\windows\install.ps1"
if (-not (Test-Path $inst)) { throw "install.ps1 não encontrado em $inst" }
$tray = ''
if (Get-ScheduledTask -TaskName GuardianAgentTray -ErrorAction SilentlyContinue) { $tray = '-Tray' }
$run = "$w\run.ps1"
Set-Content -Path $run -Encoding UTF8 -Value @(
  "Start-Sleep -Seconds 5",
  "& '$inst' $tray *> '$w\update.log'",
  "schtasks /Delete /TN GuardianAgentUpdate /F"
)
schtasks /Create /TN GuardianAgentUpdate /SC ONCE /ST 23:59 /RU SYSTEM /RL HIGHEST /F /TR "powershell -NoProfile -ExecutionPolicy Bypass -File $run"
schtasks /Run /TN GuardianAgentUpdate
Write-Output "Atualização agendada. Log em $w\update.log. O agente reinicia em instantes."
