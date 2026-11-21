#requires -Version 7.2
param([string]$OutputDirectory='output/submission')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$output=[IO.Path]::GetFullPath($OutputDirectory,$root)
$tag=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$package=Join-Path $output "LATEST_源码_待补齐_$tag"
New-Item -ItemType Directory -Path $package | Out-Null
$files=@()
foreach($directory in @('Protocol','Server','Client.WinForms','Tests')) {
    $files+=Get-ChildItem -LiteralPath (Join-Path $root $directory) -File -Recurse | Where-Object {
        $_.FullName -notmatch '[\\/](bin|obj)[\\/]' -and $_.Extension -in @('.cs','.csproj')
    }
}
foreach($name in @('Configure-Acl','Setup-Lab','Start-Client','Start-Server','Verify','Verify-Package','Package-Source')) {
    $files+=Get-Item -LiteralPath (Join-Path $root "scripts/$name.ps1")
}
foreach($name in @('SecureTransfer.sln','Directory.Build.props','global.json','server.json','.gitignore','.editorconfig','.gitattributes','docs/快速开始.md','docs/低权限部署.md')) {
    $files+=Get-Item -LiteralPath (Join-Path $root $name)
}
foreach($file in $files) {
    $relative=[IO.Path]::GetRelativePath($root,$file.FullName)
    $target=Join-Path $package $relative
    New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $target
}
$entries=@(Get-ChildItem -LiteralPath $package -File -Recurse | Sort-Object FullName | ForEach-Object {
    @{Path=[IO.Path]::GetRelativePath($package,$_.FullName).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
ConvertTo-Json -InputObject $entries -Depth 4 | Set-Content -LiteralPath (Join-Path $package 'contents-sha256.json') -Encoding utf8
$zip=$package+'.zip'
Compress-Archive -LiteralPath $package -DestinationPath $zip
Write-Output $zip
