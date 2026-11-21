#requires -Version 7.2
param([string]$ResultsDirectory='')
$ErrorActionPreference='Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not $ResultsDirectory) { $ResultsDirectory=Join-Path $PWD ('.validation\verify-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)) }
$results=[IO.Path]::GetFullPath($ResultsDirectory,$PWD.Path)
if (Test-Path -LiteralPath $results) { throw '结果目录已存在，拒绝覆盖验收证据' }
New-Item -ItemType Directory $results | Out-Null
$started=Get-Date
dotnet --info | Tee-Object (Join-Path $results 'environment.txt')
dotnet restore SecureTransfer.sln | Tee-Object (Join-Path $results 'restore.txt')
if ($LASTEXITCODE -ne 0) { throw 'restore 失败' }
dotnet build SecureTransfer.sln -c Release --no-restore | Tee-Object (Join-Path $results 'build.txt')
if ($LASTEXITCODE -ne 0) { throw 'build 失败' }
dotnet test Tests\Tests.csproj -c Release --no-build --logger 'trx;LogFileName=acceptance.trx' --results-directory $results | Tee-Object (Join-Path $results 'test.txt')
if ($LASTEXITCODE -ne 0) { throw 'test 失败' }
[xml]$trx=Get-Content -LiteralPath (Join-Path $results 'acceptance.trx')
$counters=$trx.SelectSingleNode('//*[local-name()="Counters"]')
if ([int]$counters.failed -ne 0 -or [int]$counters.passed -ne [int]$counters.total) { throw '存在失败或未执行测试' }
$run=Get-ChildItem '.local' -Directory -Filter 'tests-*' | Where-Object LastWriteTime -ge $started | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $run) { throw '未找到本次原有集成测试数据' }
$paths=@((Join-Path $run.FullName 'source\binary.dat'),(Join-Path $run.FullName 'downloads\alice\binary.dat'),(Join-Path $run.FullName 'downloads\bob\binary.dat'))
$hashes=Get-FileHash -Algorithm SHA256 -LiteralPath $paths
$hashes | Format-List | Out-String | Set-Content (Join-Path $results 'independent-sha256.txt')
if (@($hashes.Hash | Select-Object -Unique).Count -ne 1) { throw '独立摘要校验失败' }
Copy-Item -LiteralPath (Join-Path $run.FullName 'server.log') -Destination (Join-Path $results 'legacy-server.log')
Write-Host "全部 $($counters.total) 项测试与独立摘要校验通过：$results"
