<#
.SYNOPSIS
  Remove o Guardian Agent. Rode como ADMINISTRADOR. Remover o agente tira a proteção: por isso exige administrador,
  e quem usa o computador numa conta comum não consegue.
#>
$ErrorActionPreference = "Stop"
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Rode este script como administrador." }
foreach ($t in "GuardianAgent", "GuardianAgentTray") {
  if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $t -Confirm:$false }
}
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" | Where-Object { $_.CommandLine -like "*guardian.agent*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Item -Force (Join-Path $env:PUBLIC "Desktop\Guardian.url") -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $env:PUBLIC "Desktop\NotToday PC.url") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $env:ProgramFiles "GuardianAgent") -ErrorAction SilentlyContinue
Write-Host "Agente removido. O estado em $env:ProgramData\GuardianAgent foi mantido (chave e confiança); apague-o também para desfazer o pareamento."
Write-Host "No site do Guardian, em Dispositivos, esqueça este computador."
