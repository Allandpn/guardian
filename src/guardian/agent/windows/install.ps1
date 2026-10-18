<#
.SYNOPSIS
  Instala o Guardian Agent neste computador. Rode como ADMINISTRADOR, uma vez, com a pessoa de confiança presente.

.DESCRIPTION
  - copia o agente para "C:\Program Files\GuardianAgent" (leitura para todos, escrita só para administradores);
  - cria o estado em "C:\ProgramData\GuardianAgent" (SYSTEM e administradores apenas: a conta comum não alcança a chave nem o estado);
  - pareia com o Guardian usando a string de pareamento gerada no site (Dispositivos > Parear aparelho);
  - cria a tarefa "GuardianAgent" (SYSTEM, sobe na inicialização, reinicia sozinha se cair);
  - cria o atalho "Guardian" na área de trabalho de todos e, com -Tray, o ícone na bandeja.

  Depois de instalar, siga docs/AGENTE.md: o agente só protege de verdade se a sua conta do dia a dia for uma conta COMUM.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install.ps1 -Pairing "<string do site>" -Tray
#>
param(
  [Parameter(Mandatory = $true)][string]$Pairing,
  [string]$Name = $env:COMPUTERNAME,
  [string]$Python = "",
  [int]$Port = 47657,
  [switch]$Tray
)
$ErrorActionPreference = "Stop"

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Rode este script como administrador." }

$App = Join-Path $env:ProgramFiles "GuardianAgent"
$State = Join-Path $env:ProgramData "GuardianAgent"
$Src = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path          # a pasta "src" do repositório (contém "guardian")
if (-not (Test-Path (Join-Path $Src "guardian\agent\agent.py"))) { throw "Não achei guardian\agent\agent.py em $Src. Rode o script de dentro do repositório." }

if (-not $Python) {
  $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
  if (-not $cmd) { $cmd = Get-Command py.exe -ErrorAction SilentlyContinue }
  if (-not $cmd) { throw "Python 3.11 ou mais novo não encontrado. Instale-o (para todos os usuários) ou passe -Python <caminho>." }
  $Python = $cmd.Source
}

Write-Host "1/6 Copiando o agente para $App"
New-Item -ItemType Directory -Force -Path $App, $State | Out-Null
$Dest = Join-Path $App "src"
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item -Recurse -Force (Join-Path $Src "guardian") $Dest
Get-ChildItem -Recurse -Directory -Filter "__pycache__" $Dest | Remove-Item -Recurse -Force

Write-Host "2/6 Criando o ambiente do Python"
$Venv = Join-Path $App "venv"
if (-not (Test-Path $Venv)) { & $Python -m venv $Venv; if ($LASTEXITCODE) { throw "Falhou criar o venv." } }
$Py = Join-Path $Venv "Scripts\python.exe"
$Pyw = Join-Path $Venv "Scripts\pythonw.exe"
& $Py -m pip install --quiet --disable-pip-version-check "cryptography>=42"
if ($LASTEXITCODE) { throw "Falhou instalar a biblioteca cryptography." }
if ($Tray) { & $Py -m pip install --quiet --disable-pip-version-check pystray pillow; if ($LASTEXITCODE) { throw "Falhou instalar pystray e pillow." } }

Write-Host "3/6 Trancando as pastas"
& icacls $App /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
& icacls $State /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

Write-Host "4/6 Pareando com o Guardian"
$env:AGENT_STATE = $State
$env:PYTHONPATH = $Dest
$fp = & $Py -m guardian.agent pair --pairing $Pairing --name $Name
if ($LASTEXITCODE) { throw "Pareamento recusado. Gere uma string nova no site (vale por pouco tempo) e tente de novo." }
Write-Host $fp
Write-Host "   Confira este fingerprint por voz com o guardião antes de continuar." -ForegroundColor Yellow

Write-Host "5/6 Criando a tarefa do agente (SYSTEM)"
$Run = Join-Path $App "run-agent.cmd"
@"
@echo off
set AGENT_STATE=$State
set AGENT_UI_PORT=$Port
set PYTHONPATH=$Dest
"$Pyw" -m guardian.agent run
"@ | Set-Content -Encoding ASCII $Run
$action = New-ScheduledTaskAction -Execute $Run
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
  -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "GuardianAgent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "GuardianAgent"

Write-Host "6/6 Atalhos"
"[InternetShortcut]`r`nURL=http://localhost:$Port/`r`nIconIndex=0" | Set-Content -Encoding ASCII (Join-Path $env:PUBLIC "Desktop\Guardian.url")
if ($Tray) {
  $trayRun = Join-Path $App "run-tray.cmd"
  @"
@echo off
set AGENT_UI_PORT=$Port
set PYTHONPATH=$Dest
"$Pyw" -m guardian.agent tray
"@ | Set-Content -Encoding ASCII $trayRun
  $tAction = New-ScheduledTaskAction -Execute $trayRun
  $tTrigger = New-ScheduledTaskTrigger -AtLogOn
  $tPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
  Register-ScheduledTask -TaskName "GuardianAgentTray" -Action $tAction -Trigger $tTrigger -Principal $tPrincipal -Force | Out-Null
}

Start-Sleep -Seconds 5
try { $ok = (Invoke-WebRequest -UseBasicParsing "http://localhost:$Port/api/state").StatusCode -eq 200 } catch { $ok = $false }
if ($ok) { Write-Host "Pronto: o agente está no ar em http://localhost:$Port/" -ForegroundColor Green }
else { Write-Host "O agente ainda não respondeu. Veja a tarefa 'GuardianAgent' no Agendador de Tarefas." -ForegroundColor Yellow }
Write-Host "Próximo passo (importante): leia docs/AGENTE.md, seção 'Conta comum'."
