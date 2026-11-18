param([Parameter(Mandatory)][string]$ServiceAccount,[string]$LabRoot=(Join-Path (Split-Path $PSScriptRoot -Parent) '.local'),[switch]$Apply)
$ErrorActionPreference='Stop'
$resolved=(Resolve-Path -LiteralPath $LabRoot).Path
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().Name
if (-not (Test-Path -LiteralPath (Join-Path $resolved 'data'))) { throw '请先部署实验目录' }
if ($Apply) {
    # Account must already exist; no account creation or password changes here.
    $null=([Security.Principal.NTAccount]$ServiceAccount).Translate([Security.Principal.SecurityIdentifier])
    & icacls.exe $resolved /inheritance:r /grant:r "${owner}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' "${ServiceAccount}:(RX)"
    if ($LASTEXITCODE -ne 0) { throw '根目录 ACL 失败' }
    & icacls.exe (Join-Path $resolved 'data') /grant:r "${ServiceAccount}:(OI)(CI)M"
    & icacls.exe (Join-Path $resolved 'certs') /grant:r "${ServiceAccount}:(RX)"
    foreach ($name in @('server.pfx','ca.cer')) { & icacls.exe (Join-Path $resolved "certs\$name") /grant:r "${ServiceAccount}:(R)" }
    & icacls.exe (Join-Path $resolved 'accounts.db') /grant:r "${ServiceAccount}:(R)"
    & icacls.exe (Join-Path $resolved 'server.json') /grant:r "${ServiceAccount}:(R)"
    if ($LASTEXITCODE -ne 0) { throw '文件 ACL 失败' }
}
& icacls.exe $resolved
& icacls.exe (Join-Path $resolved 'data')
& icacls.exe (Join-Path $resolved 'certs\server.pfx')
& icacls.exe (Join-Path $resolved 'accounts.db')
Write-Host '服务账号只应获得程序目录读取/执行权、data 修改权、数据库及服务证书读取权；不要授予管理员组成员资格。'
