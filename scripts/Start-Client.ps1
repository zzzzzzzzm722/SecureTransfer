$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
Start-Process -FilePath '.\Client.WinForms\bin\Release\net9.0-windows\Client.WinForms.exe' -WorkingDirectory $PWD
