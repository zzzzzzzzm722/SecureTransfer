param([switch]$MutualTls)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$server = Join-Path $PWD 'Server\bin\Release\net9.0\Server.dll'
if (-not (Test-Path -LiteralPath $server)) { throw '请先执行 dotnet build -c Release' }
if (Test-Path -LiteralPath '.local\demo.secret') { throw '本地实验已部署；为保护原数据，本脚本拒绝覆盖。请使用现有口令启动。' }
New-Item -ItemType Directory -Force '.local', '.local\data', '.local\upload', '.local\downloads' | Out-Null
function New-Secret { [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) }
$secrets = @{ PfxPassword = (New-Secret); AlicePassword = (New-Secret); BobPassword = (New-Secret) }
$secrets | ConvertTo-Json | Set-Content -LiteralPath '.local\demo.secret' -Encoding utf8
# Restrict freshly created private lab material to this user and SYSTEM.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe '.local' /inheritance:r /grant:r "${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '实验私有目录 ACL 配置失败' }
try {
    $env:SFT_PFX_PASSWORD = $secrets.PfxPassword
    & dotnet $server certs '.local/certs'
    if ($LASTEXITCODE -ne 0) { throw '证书生成失败' }
    foreach ($account in @('alice', 'bob')) {
        $env:SFT_USER_PASSWORD = $secrets[($account.Substring(0,1).ToUpper()+$account.Substring(1)+'Password')]
        & dotnet $server add-user '.local/accounts.db' $account ".local/certs/$account.cer"
        if ($LASTEXITCODE -ne 0) { throw '账号初始化失败' }
    }
    $config = Get-Content server.json -Raw | ConvertFrom-Json
    $config.MutualTls = [bool]$MutualTls
    $config | ConvertTo-Json | Set-Content '.local\server.json' -Encoding utf8
    [IO.File]::WriteAllBytes((Join-Path $PWD '.local\upload\demo.bin'), [Security.Cryptography.RandomNumberGenerator]::GetBytes(200123))
    [IO.File]::WriteAllBytes((Join-Path $PWD '.local\upload\empty.bin'), [byte[]]@())
    Write-Host '部署完成。随机口令仅保存在 .local/demo.secret，不会进入提交包。'
    Write-Host '运行 scripts/Start-Server.ps1 和 scripts/Start-Client.ps1。GUI 填入本地 secret 中对应账号口令。'
} finally { Remove-Item Env:SFT_PFX_PASSWORD,Env:SFT_USER_PASSWORD -ErrorAction SilentlyContinue }
