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
  [string]$Pairing = "",    # obrigatório só na primeira instalação; depois a chave e o pareamento ficam em ProgramData
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

# O agente roda como SYSTEM: o Python dele TEM de ficar numa pasta que só administrador escreve (Program Files ou Windows).
# Um Python dentro do perfil de usuário (C:\Users\...) deixaria uma conta comum trocar o python.exe e executar código como SYSTEM.
$safeRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot) | Where-Object { $_ }
function Test-Python([string]$exe) {
  if (-not $exe -or -not (Test-Path $exe)) { return $false }
  $full = (Resolve-Path $exe).Path
  if ($full -like "*\WindowsApps\*") { return $false }                       # o atalho da Microsoft Store não é um Python
  if (-not ($safeRoots | Where-Object { $full.StartsWith($_ + "\", [StringComparison]::OrdinalIgnoreCase) })) { return $false }
  $ok = & $full -c "import sys; print(sys.version_info >= (3, 11))" 2>$null
  return ($LASTEXITCODE -eq 0 -and "$ok".Trim() -eq "True")
}
if ($Python) {
  if (-not (Test-Python $Python)) { throw "O Python '$Python' não serve: precisa ser 3.11+ e estar em Program Files (uma pasta que só administrador escreve)." }
} else {
  $cands = @()
  $cands += Get-ChildItem -Path (Join-Path $env:ProgramFiles "Python3*\python.exe") -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | ForEach-Object { $_.FullName }
  $py = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($py) { $p = & $py.Source -3 -c "import sys; print(sys.executable)" 2>$null; if ($LASTEXITCODE -eq 0) { $cands += "$p".Trim() } }
  $pc = Get-Command python.exe -ErrorAction SilentlyContinue
  if ($pc) { $cands += $pc.Source }
  $Python = $cands | Where-Object { Test-Python $_ } | Select-Object -First 1
  if (-not $Python) {
    throw ("Não achei um Python 3.11+ instalado para todos os usuários (em Program Files). Instale um, ainda como administrador, e rode de novo:`n" +
           "  winget install --id Python.Python.3.12 --scope machine`n" +
           "(Pythons dentro de C:\Users\... e o atalho da Microsoft Store não servem: seriam um caminho para uma conta comum virar SYSTEM.)")
  }
}
Write-Host "Python: $Python"

Write-Host "0/6 Parando o agente, se já estiver rodando (reinstalar por cima)"
foreach ($t in "GuardianAgent", "GuardianAgentTray") { if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue } }
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*guardian.agent*" -and $_.Name -match "^pythonw?\.exe$" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
# Instalador ou script que o agente tinha iniciado e ficou preso (roda de uma cópia em ...\GuardianAgent\work): encerra também.
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -like (Join-Path $State "work\*") } |
  ForEach-Object { Write-Host "   encerrando instalador preso: $($_.Name) (pid $($_.ProcessId))"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 3   # o cmd mantém o run-agent.cmd aberto enquanto o agente roda

Write-Host "1/6 Copiando o agente para $App"
# Uma instalação anterior que falhou pode ter deixado arquivos com a lista de acesso quebrada (sem ninguém, nem administradores).
# Reassume a posse (como grupo Administradores, pelo SID) e volta à herança do Program Files: SYSTEM e administradores com controle total, usuários só leitura.
function Reset-Tree([string]$p) {
  if (-not (Test-Path $p)) { return }
  $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"       # o stderr dos programas nativos não pode derrubar o script
  & icacls $p /setowner "*S-1-5-32-544" /T /C 2>&1 | Out-Null             # dono = grupo Administradores, pelo SID (sem perguntas, em qualquer idioma)
  & icacls $p /reset /T /C 2>&1 | Out-Null
  $ErrorActionPreference = $old
}
Reset-Tree $App
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
# Identificadores universais (SID), não nomes: no Windows em português o grupo não se chama "Administrators" nem "Users".
$SYS = "*S-1-5-18"; $ADM = "*S-1-5-32-544"; $USR = "*S-1-5-32-545"
& icacls $App /reset /T /C | Out-Null       # herda do Program Files: só administradores escrevem (ver acima)
if ($LASTEXITCODE) { throw "Falhou ajustar $App." }
$SidType = [Security.Principal.SecurityIdentifier]
# GetAccessRules já devolve SIDs (sem traduzir nomes, que falha com contas que o Windows em português não resolve).
$writable = (Get-Acl $App).GetAccessRules($true, $true, $SidType) | Where-Object { $_.IdentityReference.Value -eq "S-1-5-32-545" -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -and $_.AccessControlType -eq "Allow" }
if ($writable) { throw "A pasta $App é gravável por usuários comuns. Não vou continuar." }
# Pasta de estado: protege SÓ a raiz e depois manda cada item de dentro herdar dela. NÃO use /T com /inheritance:r:
# o /T deixa os arquivos de dentro com a lista de acesso VAZIA (nem o SYSTEM abre a chave do agente).
$old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
& icacls $State /setowner $ADM /T /C 2>&1 | Out-Null
& icacls $State /inheritance:r 2>&1 | Out-Null
& icacls $State /grant:r "${SYS}:(OI)(CI)F" "${ADM}:(OI)(CI)F" 2>&1 | Out-Null
$grantExit = $LASTEXITCODE
Get-ChildItem -LiteralPath $State -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { & icacls $_.FullName /reset 2>&1 | Out-Null }
$ErrorActionPreference = $old
if ($grantExit) { throw "Falhou trancar $State." }
# Todo arquivo de dentro precisa estar acessível ao SYSTEM (o agente roda como SYSTEM).
$noSystem = Get-ChildItem -LiteralPath $State -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
  -not ((Get-Acl -LiteralPath $_.FullName).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq "S-1-5-18" }) }
if ($noSystem) { throw "Arquivos em $State sem acesso para o SYSTEM: $($noSystem.Name -join ', ')" }
# A pasta de estado guarda a chave do agente: nada de usuário comum, "Todos" ou "Usuários autenticados" nela.
$bad = (Get-Acl $State).GetAccessRules($true, $true, $SidType) | Where-Object { $_.IdentityReference.Value -in @("S-1-5-32-545", "S-1-1-0", "S-1-5-11") }
if ($bad) { throw "A pasta $State ainda é acessível a usuários comuns. Não vou continuar." }

Write-Host "4/6 Pareando com o Guardian"
$env:AGENT_STATE = $State
$env:PYTHONPATH = $Dest
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
if ((Test-Path (Join-Path $State "agent.pem")) -and (Test-Path (Join-Path $State "state.json"))) {
  Write-Host "   Já pareado: mantendo a chave e o pareamento existentes (para parear de novo, rode uninstall.ps1 e apague $State)."
} else {
  if (-not $Pairing) { throw "Passe -Pairing com a string gerada no site (Dispositivos > Parear aparelho)." }
  $fp = & $Py -m guardian.agent pair --pairing $Pairing --name $Name
  if ($LASTEXITCODE) { throw "Pareamento recusado. Gere uma string nova no site (vale por pouco tempo) e tente de novo." }
  Write-Host $fp
  Write-Host "   Confira este fingerprint por voz com o guardião antes de continuar." -ForegroundColor Yellow
}

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
Remove-Item -Force (Join-Path $env:PUBLIC "Desktop\Guardian.url") -ErrorAction SilentlyContinue   # nome antigo do atalho
"[InternetShortcut]`r`nURL=http://localhost:$Port/`r`nIconIndex=0" | Set-Content -Encoding ASCII (Join-Path $env:PUBLIC "Desktop\NotToday PC.url")
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
  $tPrincipal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited   # grupo Users, pelo SID (o nome muda com o idioma)
  Register-ScheduledTask -TaskName "GuardianAgentTray" -Action $tAction -Trigger $tTrigger -Principal $tPrincipal -Force | Out-Null
}

$ok = $false
foreach ($i in 1..15) {                       # até ~30 s: a primeira partida da tarefa pode demorar
  Start-Sleep -Seconds 2
  try { $ok = (Invoke-WebRequest -UseBasicParsing "http://localhost:$Port/api/state" -TimeoutSec 3).StatusCode -eq 200 } catch { $ok = $false }
  if ($ok) { break }
}
if ($ok) { Write-Host "Pronto: o agente está no ar em http://localhost:$Port/" -ForegroundColor Green }
else {
  Write-Host "O agente não respondeu em 30 s. Rodando uma vez em primeiro plano por 8 s para mostrar o erro:" -ForegroundColor Yellow
  $log = Join-Path $env:TEMP "guardian-agent-diag.txt"
  $proc = Start-Process -FilePath $Py -ArgumentList "-m", "guardian.agent", "run" -PassThru -WindowStyle Hidden -RedirectStandardError $log -RedirectStandardOutput "$log.out"
  Start-Sleep -Seconds 8
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force; Write-Host "  (ele ficou de pé em primeiro plano: o problema é a tarefa agendada, não o agente)" }
  Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 15 | ForEach-Object { Write-Host "  $_" }
  Remove-Item $log, "$log.out" -Force -ErrorAction SilentlyContinue
}
Write-Host "Próximo passo (importante): leia docs/AGENTE.md, seção 'Conta comum'."
