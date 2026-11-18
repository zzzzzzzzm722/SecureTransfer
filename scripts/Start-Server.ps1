$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$secrets = Get-Content '.local\demo.secret' -Raw | ConvertFrom-Json
try { $env:SFT_PFX_PASSWORD = $secrets.PfxPassword; dotnet Server\bin\Release\net9.0\Server.dll serve .local\server.json }
finally { Remove-Item Env:SFT_PFX_PASSWORD -ErrorAction SilentlyContinue }
