#requires -Version 7.2
param([string]$Root='.local')
$ErrorActionPreference='Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$profile=Join-Path ([IO.Path]::GetFullPath($Root,$PWD.Path)) 'client.json'
$launch=@{FilePath='.\Client.WinForms\bin\Release\net9.0-windows\Client.WinForms.exe';WorkingDirectory=$PWD.Path}
if (Test-Path -LiteralPath $profile) { $launch.ArgumentList=@('--profile', ('"'+$profile+'"')) }
Start-Process @launch
