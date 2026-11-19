# Installs the SentinelX agent as a startup scheduled task running as SYSTEM (needed to read the Security log).
# Run in an ELEVATED PowerShell:   .\install-windows.ps1 -ConfigPath .\agent.json
param([Parameter(Mandatory = $true)][string]$ConfigPath)
$ErrorActionPreference = "Stop"
$admin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run PowerShell as Administrator." }
$dir = "C:\ProgramData\SentinelXAgent"
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item "$PSScriptRoot\sentinelx_agent.py" "$dir\sentinelx_agent.py" -Force
Copy-Item $ConfigPath "$dir\agent.json" -Force
icacls $dir /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null   # the API key must not be readable by other users
$py = (Get-Command python -ErrorAction Stop).Source
$action = New-ScheduledTaskAction -Execute $py -Argument "`"$dir\sentinelx_agent.py`" --config `"$dir\agent.json`"" -WorkingDirectory $dir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "SentinelXAgent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "SentinelXAgent"
Write-Host "Installed. Check the Endpoints page in SentinelX: it shows 'online' only after the first heartbeat arrives."
Write-Host "Uninstall: python $dir\sentinelx_agent.py --config $dir\agent.json --deregister ; Unregister-ScheduledTask SentinelXAgent -Confirm:`$false"
