#requires -Version 7.2
param([string]$Root='.local',[int]$Port=7443)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$server = Join-Path $PWD 'Server\bin\Release\net9.0\Server.dll'
if (-not (Test-Path -LiteralPath $server)) { throw '请先执行 dotnet build -c Release' }
$rootPath = [IO.Path]::GetFullPath($Root, $PWD.Path)
if ((Test-Path -LiteralPath $rootPath) -and @(Get-ChildItem -LiteralPath $rootPath -Force).Count) { throw '部署目录非空，拒绝覆盖。已有部署使用 Start-Server.ps1；新实验指定空目录 -Root。' }
if ($Port -lt 1 -or $Port -gt 65535) { throw '端口范围为 1–65535' }
New-Item -ItemType Directory -Force $rootPath | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $rootPath /inheritance:r /grant:r "${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '部署私有目录 ACL 配置失败' }
foreach ($dir in @('data','upload','downloads','logs','client-state')) { New-Item -ItemType Directory (Join-Path $rootPath $dir) | Out-Null }
function New-Secret { [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) }
$secrets = @{ PfxPassword=(New-Secret); AlicePassword=(New-Secret); BobPassword=(New-Secret) }
$secrets | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $rootPath 'demo.secret') -Encoding utf8
$previousPfx=$env:SFT_PFX_PASSWORD; $previousUser=$env:SFT_USER_PASSWORD
try {
    $env:SFT_PFX_PASSWORD=$secrets.PfxPassword
    & dotnet $server certs (Join-Path $rootPath 'certs')
    if ($LASTEXITCODE -ne 0) { throw '证书生成失败' }
    foreach ($account in @('alice','bob')) {
        $env:SFT_USER_PASSWORD=$secrets[($account.Substring(0,1).ToUpper()+$account.Substring(1)+'Password')]
        & dotnet $server add-user (Join-Path $rootPath 'accounts.db') $account (Join-Path $rootPath "certs\$account.cer")
        if ($LASTEXITCODE -ne 0) { throw '账号初始化失败' }
    }
    $config=Get-Content server.json -Raw | ConvertFrom-Json
    $config.MutualTls=$true; $config.Port=$Port
    $config.Root=Join-Path $rootPath 'data'; $config.Database=Join-Path $rootPath 'accounts.db'
    $config.Certificate=Join-Path $rootPath 'certs\server.pfx'; $config.Ca=Join-Path $rootPath 'certs\ca.cer'; $config.LogDirectory=Join-Path $rootPath 'logs'
    $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $rootPath 'server.json') -Encoding utf8
    [IO.File]::WriteAllBytes((Join-Path $rootPath 'upload\demo.bin'), [Security.Cryptography.RandomNumberGenerator]::GetBytes(200123))
    [IO.File]::WriteAllBytes((Join-Path $rootPath 'upload\empty.bin'), [byte[]]@())
    @{Host='localhost';Port=$Port;Ca=$config.Ca;User='alice';Certificate=(Join-Path $rootPath 'certs\alice.pfx');UploadFiles=(Join-Path $rootPath 'upload\demo.bin');DownloadDirectory=(Join-Path $rootPath 'downloads');StateRoot=(Join-Path $rootPath 'client-state')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $rootPath 'client.json') -Encoding utf8
    Write-Host "双向认证部署完成：$rootPath。口令在 demo.secret；使用 Start-Server.ps1 -Root 和 Start-Client.ps1 -Root 启动。"
} finally { $env:SFT_PFX_PASSWORD=$previousPfx; $env:SFT_USER_PASSWORD=$previousUser }
