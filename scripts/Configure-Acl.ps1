#requires -Version 7.2
param([Parameter(Mandatory)][string]$ServiceAccount,[string]$LabRoot=(Join-Path (Split-Path $PSScriptRoot -Parent) '.local'),[switch]$Apply)
$ErrorActionPreference='Stop'
$resolved=(Resolve-Path -LiteralPath $LabRoot).Path
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$sid=([Security.Principal.NTAccount]$ServiceAccount).Translate([Security.Principal.SecurityIdentifier]).Value
if ($sid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or $sid -in @('S-1-5-18','S-1-5-32-544')) { throw '服务身份必须是独立的低权限账号' }
function Invoke-Acl([string[]]$Arguments) {
    & icacls.exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "ACL 命令失败（退出码 $LASTEXITCODE）：$($Arguments[0])" }
}
foreach ($name in @('data','logs','certs','certs\server.pfx','certs\ca.cer','accounts.db','server.json')) {
    $path=Join-Path $resolved $name
    if (-not (Test-Path -LiteralPath $path)) { throw "缺少部署项：$path" }
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "拒绝重解析点：$path" }
}
if ($Apply) {
    # Remove only this service SID's previous grants; preserve other explicit user ACL entries.
    Invoke-Acl @($resolved,'/remove:g',"*$sid",'/T')
    Invoke-Acl @($resolved,'/inheritance:r','/grant:r',"${owner}:(OI)(CI)F",'*S-1-5-18:(OI)(CI)F',"*${sid}:(RX)")
    foreach ($private in @('demo.secret','certs\alice.pfx','certs\bob.pfx')) {
        $privatePath=Join-Path $resolved $private
        if (Test-Path -LiteralPath $privatePath) { Invoke-Acl @($privatePath,'/deny',"*${sid}:(R)") }
    }
    foreach ($name in @('data','logs')) { Invoke-Acl @((Join-Path $resolved $name),'/grant:r',"*${sid}:(OI)(CI)M") }
    Invoke-Acl @((Join-Path $resolved 'certs'),'/grant:r',"*${sid}:(RX)")
    foreach ($name in @('certs\server.pfx','certs\ca.cer','accounts.db','server.json')) { Invoke-Acl @((Join-Path $resolved $name),'/grant:r',"*${sid}:(R)") }
}
foreach ($name in @('','data','logs','certs\server.pfx','certs\alice.pfx','accounts.db','demo.secret')) { Invoke-Acl @((Join-Path $resolved $name)) }
Write-Host '程序目录另授读取/执行权；仅 data、logs 授修改权。客户端私钥和 demo.secret 不授服务账号权限。检查组成员及显式 ACL 后，用该账号启动验收；脚本输出不代表低权限运行已验证。'

