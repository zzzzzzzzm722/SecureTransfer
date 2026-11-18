$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
New-Item -ItemType Directory -Force evidence | Out-Null
dotnet --info | Tee-Object evidence\environment.txt
dotnet --list-sdks | Tee-Object evidence\sdks.txt
dotnet restore SecureTransfer.sln | Tee-Object evidence\restore.txt
if ($LASTEXITCODE -ne 0) { throw 'restore 失败' }
dotnet build SecureTransfer.sln -c Release --no-restore | Tee-Object evidence\build.txt
if ($LASTEXITCODE -ne 0) { throw 'build 失败' }
dotnet test SecureTransfer.sln -c Release --no-build --logger 'trx;LogFileName=acceptance.trx' --results-directory evidence\TestResults | Tee-Object evidence\test.txt
if ($LASTEXITCODE -ne 0) { throw 'test 失败' }
$run = Get-ChildItem '.local' -Directory -Filter 'tests-*' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item -LiteralPath (Join-Path $run.FullName 'server.log') -Destination evidence\server-tests.log
$paths = @((Join-Path $run.FullName 'source\binary.dat'),(Join-Path $run.FullName 'downloads\alice\binary.dat'),(Join-Path $run.FullName 'downloads\bob\binary.dat'))
$hashes = Get-FileHash -Algorithm SHA256 -LiteralPath $paths
$hashes | Format-List | Out-String | Set-Content evidence\independent-sha256.txt
if (($hashes.Hash | Select-Object -Unique).Count -ne 1) { throw '独立摘要校验失败' }
Write-Host '全部自动化验收和独立 SHA-256 校验通过。'
