#requires -Version 7.2
param([string]$Root='.local',[switch]$UseDemoSecret)
$ErrorActionPreference='Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$rootPath=[IO.Path]::GetFullPath($Root,$PWD.Path)
$previous=$env:SFT_PFX_PASSWORD
$secure=$null; $pointer=[IntPtr]::Zero
try {
    if ($UseDemoSecret) {
        $env:SFT_PFX_PASSWORD=(Get-Content -LiteralPath (Join-Path $rootPath 'demo.secret') -Raw | ConvertFrom-Json).PfxPassword
    } elseif (-not $env:SFT_PFX_PASSWORD) {
        $secure=Read-Host '服务端 PFX 口令' -AsSecureString
        $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $env:SFT_PFX_PASSWORD=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    # Only this root's server.json is active. The repository config is an initialization template.
    & dotnet Server\bin\Release\net9.0\Server.dll serve (Join-Path $rootPath 'server.json')
    if ($LASTEXITCODE -ne 0) { throw '服务端启动或运行失败' }
} finally {
    $env:SFT_PFX_PASSWORD=$previous
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($secure) { $secure.Dispose() }
}
