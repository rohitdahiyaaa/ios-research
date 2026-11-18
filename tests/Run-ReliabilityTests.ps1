$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$modulePath=Join-Path $root 'src\IosResearchPipeline\IosResearchPipeline.psd1'
$stateModulePath=Join-Path $root 'src\IosResearchPipeline\IosResearchState.psm1'
Import-Module $modulePath -Force
Import-Module $stateModulePath -Force
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('ios-pipeline-reliability-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$passed=0
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:passed++}

try {
    Assert-True ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'Reliability regressions must run on Windows PowerShell 5.1.'

    # Compact a metadata-only copy derived from the forensic run. The fixture itself remains untouched.
    $fixturePath=Join-Path $PSScriptRoot 'fixtures\existing-run-metadata-copy.json'
    $fixtureHashBefore=(Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash
    $fixture=Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
    $copyPath=Join-Path $testRoot 'existing-run-copy.json'
    $fixture | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $copyPath -Encoding UTF8
    $copy=Get-Content -LiteralPath $copyPath -Raw | ConvertFrom-Json
    $report=@($copy.Stages | Where-Object Name -eq 'report')[0]
    $report.Status='completed';$report.ExitCode=0;$report.OutputPaths=@('report-summary.json','research-report.md','run-manifest.json')
    $report | Add-Member -NotePropertyName StartedAt -NotePropertyValue '2026-11-15T09:25:05Z'
    $report | Add-Member -NotePropertyName CompletedAt -NotePropertyValue '2026-11-15T09:26:02Z'
    $copy.Status='completed';$copy.CompletedAt='2026-11-15T09:27:39Z'
    Save-IosRunState -State $copy -Path $copyPath
    $normalized=Get-IosRunState -Path $copyPath -RunId $copy.RunId
    Assert-True ($normalized.SchemaVersion -eq 4 -and $normalized.Status -eq 'completed') 'A copied legacy run record is persisted in compact schema without changing its RunId.'
    $normalizedReport=@($normalized.Stages | Where-Object Name -eq 'report')[0]
    Assert-True ($normalizedReport.Status -eq 'completed' -and $normalizedReport.ExitCode -eq 0 -and $normalizedReport.OutputPaths.Count -eq 3) 'The copied report stage retains its final exit code and output references.'
    Assert-True ((Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash -eq $fixtureHashBefore) 'The forensic metadata fixture remains unchanged.'

    # A multi-megabyte analysis result stays in its dedicated artifact; run state keeps only a summary and pointer.
    $largeArtifact=Join-Path $testRoot 'binary-diff-stage-result.json'
    $largePayload='SYNTHETIC_LARGE_RESULT_SENTINEL_'+('x'*2MB)
    $largeResult=[pscustomobject]@{
        Status='completed';IdenticalBinaries=@();ChangedBinaries=@([pscustomobject]@{Name='synthetic.dylib'});AddedBinaries=@();RemovedBinaries=@()
        FunctionComparison=[pscustomobject]@{Status='completed';MatchedFunctionCount=64000;ChangedFunctionCount=1;ChangedFunctions=@([pscustomobject]@{Name='syntheticFunction';Body=$largePayload});AddedFunctions=@();RemovedFunctions=@();Pairs=@();BinDiffUsed=$true}
    }
    $largeJson=ConvertTo-Json -InputObject $largeResult -Depth 8
    [IO.File]::WriteAllText($largeArtifact,$largeJson,(New-Object System.Text.UTF8Encoding($false)))
    $artifactHash=(Get-FileHash -LiteralPath $largeArtifact -Algorithm SHA256).Hash
    $largeStatePath=Join-Path $testRoot 'large-run.json'
    $largeState=[pscustomobject]@{
        SchemaVersion=3;RunId='large-fixture';CreatedAt='2026-01-01T00:00:00Z';CompletedAt='2026-01-01T00:00:10Z';Status='completed';Mode='research';ReportPath=$null
        InputHashes=@();OutputPaths=@($largeArtifact);Stages=@([pscustomobject]@{Name='binary-diff';Status='completed';StartedAt='2026-01-01T00:00:01Z';CompletedAt='2026-01-01T00:00:09Z';ExitCode=0;Error=$null;Details=$null;ValidationResult=$null;InputHashes=@();OutputPaths=@($largeArtifact);ResultPath=$largeArtifact;ResultSummary=(Get-IosStageResultSummary -StageName binary-diff -Result $largeResult);Result=$largeResult})
    }
    Save-IosRunState -State $largeState -Path $largeStatePath
    $compactBytes=(Get-Item -LiteralPath $largeStatePath).Length
    $compactText=Get-Content -LiteralPath $largeStatePath -Raw
    $loaded=Get-IosRunState -Path $largeStatePath -RunId 'large-fixture'
    Assert-True ($compactBytes -lt 50000 -and $compactText -notmatch 'SYNTHETIC_LARGE_RESULT_SENTINEL') 'Large BinDiff payloads are not embedded in run.json.'
    Assert-True ($loaded.Stages[0].ResultSummary.ChangedCount -eq 1 -and $loaded.Stages[0].ResultPath -eq $largeArtifact) 'Compact state preserves result counts and a resolvable detailed-artifact path.'
    Assert-True ((Get-FileHash -LiteralPath $largeArtifact -Algorithm SHA256).Hash -eq $artifactHash) 'Compacting state leaves the dedicated detailed result artifact unchanged.'

    # Report-stage completion and resume are validated on synthetic mock stages only.
    $dataRoot=Join-Path $testRoot 'resume-workspace';New-Item -ItemType Directory -Path $dataRoot | Out-Null
    $configPath=Join-Path $testRoot 'resume-config.json'
    $config=[ordered]@{
        schemaVersion=1;workspace='resume-workspace';deviceIdentifier='iPhone15,2';baselineFirmwareVersion='17.0';baselineBuild='21A329';targetFirmwareVersion='17.1';targetBuild='21B74';sourceType='IPSW'
        inputFirmwarePaths=@();outputWorkspace='resume-workspace';toolPaths=[ordered]@{ipsw='missing';sevenZip='missing';ghidra='missing';binDiff='missing';java='missing';python='missing';wsl='missing'}
        stages=@('validate','report');resourceLimits=[ordered]@{maxRunMinutes=10;minimumFreeBytes=1024;maxCpuThreads=1;maxGhidraBinaries=1;maxDylibExtractions=1;toolTimeoutSeconds=30}
        approvalPolicy=[ordered]@{authorizedResearch=$false;approvedHosts=@();downloadsEnabled=$false};authorizedResearch=$false;approvedHosts=@()
        analysisInputPaths=@();sharedCacheRoots=@();sharedCacheArchitectures=@();binExportPairs=@();components=@();adapters=[ordered]@{python=[ordered]@{enabled=$false;command='python'};wsl=[ordered]@{enabled=$false;command='wsl.exe'}}
    }
    $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $partial=Invoke-IosResearchPipeline -ConfigPath $configPath -Product 'iPhone15,2' -Build '21B74' -Mock -Stage @('validate')
    Assert-True ($partial.Status -eq 'partial') 'A partial mock run remains resumable.'
    $completed=Invoke-IosResearchPipeline -ConfigPath $configPath -Product 'iPhone15,2' -Build '21B74' -ResumeRunId $partial.RunId -Mock -Stage @('report')
    $runDir=Join-Path (Join-Path $dataRoot 'runs') $partial.RunId
    $state=Get-Content -LiteralPath (Join-Path $runDir 'run.json') -Raw | ConvertFrom-Json
    $manifestPath=$state.ReportManifestPath
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $reportStage=@($state.Stages | Where-Object Name -eq 'report')[0]
    $manifestReport=@($manifest.Stages | Where-Object Name -eq 'report')[0]
    $events=Get-Content -LiteralPath (Join-Path $runDir 'pipeline.log') | ForEach-Object {$_|ConvertFrom-Json}
    $stageEvent=@($events | Where-Object {$_.Event -eq 'stage_finished' -and $_.Stage -eq 'report'} | Select-Object -Last 1)[0]
    $runEvent=@($events | Where-Object Event -eq 'run_finished' | Select-Object -Last 1)[0]
    Assert-True ($completed.Status -eq 'completed' -and $state.Status -eq 'completed' -and $manifest.Status -eq 'completed' -and $manifest.ExecutionStatus -eq 'completed') 'Resume finalizes status consistently across return value, run.json, and run-manifest.json.'
    Assert-True ($reportStage.Status -eq 'mocked' -and $reportStage.ExitCode -eq 0 -and $reportStage.OutputPaths -contains $manifestPath) 'The report stage persists its exit code and manifest output path.'
    Assert-True ($manifestReport.Status -eq 'mocked' -and $manifestReport.ExitCode -eq 0 -and $manifestReport.OutputPaths -contains $manifestPath) 'The final manifest snapshot contains the completed report-stage record.'
    Assert-True ($stageEvent.OutputPaths -contains $manifestPath -and $runEvent.Status -eq 'completed') 'Pipeline logs record report completion paths and the final completed run.'
    Assert-True ([DateTime]::Parse($manifest.GeneratedAt).ToUniversalTime() -gt [DateTime]::Parse($stageEvent.Timestamp).ToUniversalTime()) 'The final manifest is generated after the report completion event.'
    Assert-True ((Get-Item -LiteralPath (Join-Path $runDir 'run.json')).Length -lt 50000) 'Resumed run state remains compact.'
    Assert-True ([bool]($manifest.ArtifactReferences | Where-Object {$_.Path -eq $manifestPath -and -not $_.SHA256 -and -not $_.SizeBytes})) 'The manifest documents its self-reference without embedding result data.'

    Write-Output "PASS: $passed reliability assertions (PowerShell $($PSVersionTable.PSVersion))"
} catch {
    Write-Error "FAIL: $($_.Exception.Message)"
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module IosResearchPipeline -ErrorAction SilentlyContinue
    Remove-Module IosResearchState -ErrorAction SilentlyContinue
}
if($passed -lt 10){exit 1}
