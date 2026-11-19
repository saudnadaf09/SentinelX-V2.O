# Creates .env from .env.example with generated secrets (UTF-8 without BOM).
$ErrorActionPreference = "Stop"
function New-Hex([int]$bytes) {
  $b = New-Object byte[] $bytes
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  return ($b | ForEach-Object { $_.ToString("x2") }) -join ""
}
$root = Split-Path -Parent $PSScriptRoot
$adminPw = New-Hex 12
$lines = Get-Content -Path (Join-Path $root ".env.example") | ForEach-Object {
  if ($_ -like "SECRET_KEY=*") { "SECRET_KEY=$(New-Hex 32)" }
  elseif ($_ -like "POSTGRES_PASSWORD=*") { "POSTGRES_PASSWORD=$(New-Hex 16)" }
  elseif ($_ -like "BOOTSTRAP_ADMIN_PASSWORD=*") { "BOOTSTRAP_ADMIN_PASSWORD=$adminPw" }
  else { $_ }
}
[System.IO.File]::WriteAllLines((Join-Path $root ".env"), $lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Admin login: admin@sentinelx.local / $adminPw   (also stored in .env)"
