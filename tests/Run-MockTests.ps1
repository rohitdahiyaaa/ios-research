$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\IosResearchPipeline\IosResearchPipeline.psd1'
Import-Module $modulePath -Force
$extractModulePath=Join-Path (Split-Path -Parent $modulePath) 'IosFirmwareExtraction.psm1'
Import-Module $extractModulePath -Force
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ios-pipeline-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$script:passed = 0
$script:failed = 0
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message }; $script:passed++ }
function Assert-Throws([scriptblock]$Action,[string]$Message) { $threw=$false; try { & $Action } catch { $threw=$true }; if (-not $threw) { throw "Expected error: $Message" }; $script:passed++ }
function Assert-ThrowsLike([scriptblock]$Action,[string]$Expected,[string]$Message) { $actual=$null; try { & $Action } catch { $actual=$_.Exception.Message }; if ($actual -notlike $Expected) { throw "$Message (actual: $actual)" }; $script:passed++ }
function New-TestConfig([string]$Path,[string[]]$Stages=@('validate','inventory','analyze-metadata','report'),[string[]]$Inputs=@(),[bool]$Authorized=$false) {
    $cfg = [ordered]@{
        schemaVersion=1; workspace='data'; deviceIdentifier='iPhone15,2'; baselineFirmwareVersion='17.0'; baselineBuild='21A329'
        targetFirmwareVersion='17.1'; targetBuild='21B74'; sourceType='IPSW'; inputFirmwarePaths=$Inputs; outputWorkspace='data'
        toolPaths=[ordered]@{ ipsw='__missing_ipsw__'; sevenZip='__missing_7z__'; ghidra='__missing_ghidra__'; binDiff='__missing_bindiff__'; java='__missing_java__'; python='__missing_python__'; wsl='__missing_wsl__' }
        stages=$Stages; resourceLimits=[ordered]@{ maxRunMinutes=10; minimumFreeBytes=1024; maxCpuThreads=2; maxGhidraBinaries=2; maxDylibExtractions=8; toolTimeoutSeconds=20 }
        approvalPolicy=[ordered]@{ authorizedResearch=$Authorized; approvedHosts=@(); downloadsEnabled=$false }; authorizedResearch=$Authorized; approvedHosts=@()
        analysisInputPaths=@(); sharedCacheRoots=@(); sharedCacheArchitectures=@(); binExportPairs=@(); components=@('JavaScriptCore','WebKit','ImageIO','CoreGraphics','CoreMedia','VideoToolbox','IOKit','Kernel')
        adapters=[ordered]@{ python=[ordered]@{ enabled=$false; command='python' }; wsl=[ordered]@{ enabled=$false; command='wsl.exe' } }
    }
    $cfg | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
    return $cfg
}
function New-SyntheticIpsw([string]$Path,[string]$Version='17.1',[string]$Build='21B74') {
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try{$entry=$zip.CreateEntry('BuildManifest.plist');$stream=$entry.Open();$writer=New-Object IO.StreamWriter($stream);$xml="<?xml version=`"1.0`"?><plist version=`"1.0`"><dict><key>ProductVersion</key><string>$Version</string><key>ProductBuildVersion</key><string>$Build</string><key>SupportedProductTypes</key><array><string>iPhone15,2</string></array></dict></plist>";$writer.Write($xml);$writer.Dispose();$stream.Dispose()}finally{$zip.Dispose()}
}
function New-SyntheticMachO([string]$Path,[byte]$Marker=1,[byte]$UuidSeed=1) {
    $fs=[IO.File]::Create($Path);$writer=New-Object IO.BinaryWriter($fs)
    try{$writer.Write([byte[]](0xcf,0xfa,0xed,0xfe));$writer.Write([uint32]0x0100000c);$writer.Write([uint32]0);$writer.Write([uint32]6);$writer.Write([uint32]1);$writer.Write([uint32]24);$writer.Write([uint32]0);$writer.Write([uint32]0);$writer.Write([uint32]0x1b);$writer.Write([uint32]24);$uuid=[byte[]](1..16|ForEach-Object {[byte]($_+$UuidSeed-1)});$writer.Write($uuid);$writer.Write($Marker)}finally{$writer.Dispose();$fs.Dispose()}
}
function New-SyntheticMachOWithLoads([string]$Path) {
    $fs=[IO.File]::Create($Path);$writer=New-Object IO.BinaryWriter($fs)
    try{
        $writer.Write([byte[]](0xcf,0xfa,0xed,0xfe));$writer.Write([uint32]0x0100000c);$writer.Write([uint32]0);$writer.Write([uint32]6);$writer.Write([uint32]3);$writer.Write([uint32]104);$writer.Write([uint32]0);$writer.Write([uint32]0)
        $name=[Text.Encoding]::UTF8.GetBytes('/usr/lib/libSystem.B.dylib');$writer.Write([uint32]0x0c);$writer.Write([uint32]56);$writer.Write([uint32]24);$writer.Write([uint32]0);$writer.Write([uint32]0);$writer.Write([uint32]0);$writer.Write($name);$writer.Write([byte]0);$writer.Write((New-Object byte[] (56-24-$name.Length-1)))
        $writer.Write([uint32]0x1b);$writer.Write([uint32]24);$writer.Write([byte[]](1..16))
        $writer.Write([uint32]0x2);$writer.Write([uint32]24);$writer.Write([uint32]136);$writer.Write([uint32]1);$writer.Write([uint32]152);$writer.Write([uint32]13)
        $writer.Write([uint32]1);$writer.Write([byte]0x0f);$writer.Write([byte]1);$writer.Write([uint16]0);$writer.Write([uint64]0x1000);$writer.Write([byte]0);$writer.Write([Text.Encoding]::UTF8.GetBytes('_parseImage'));$writer.Write([byte]0)
    }finally{$writer.Dispose();$fs.Dispose()}
}
try {
    $cfgPath=Join-Path $testRoot 'pipeline.json'
    $cfg=New-TestConfig $cfgPath
    $v=Test-IosResearchConfig -ConfigPath $cfgPath
    Assert-True $v.Valid 'Valid config should pass.'
    $badPath=Join-Path $testRoot 'bad.json'
    $bad=New-TestConfig $badPath @('not-a-stage')
    Assert-Throws { Test-IosResearchConfig -ConfigPath $badPath } 'unsupported stages must fail'
    $escapePath=Join-Path $testRoot 'escape.json'
    $escape=New-TestConfig $escapePath
    $escape.outputWorkspace='..\outside'
    $escape | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $escapePath -Encoding UTF8
    Assert-Throws { Invoke-IosResearchPipeline -ConfigPath $escapePath -Product 'iPhone15,2' -Build '21B74' -Mock } 'output workspace traversal must be rejected'
    $p=Get-IosResearchPlan -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74'
    Assert-True (-not $p.NetworkAccess -and -not $p.FirmwareExtraction -and -not $p.VersionBuildVerified) 'Plan safety and verification status must be explicit.'
    $whatIf=Invoke-IosResearchPipeline -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74' -Mock -WhatIf
    Assert-True ($whatIf.Status -eq 'whatif') 'WhatIf returns a preview.'
    Assert-True (-not (Test-Path (Join-Path $testRoot 'data'))) 'WhatIf must not create run artifacts.'
    $entryPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-IOSResearch.ps1'
    $entryPreview=& $entryPath -ConfigPath $cfgPath -Device 'iPhone15,2' -BaselineBuild '21A329' -TargetBuild '21B74' -Mock -WhatIf
    Assert-True ($entryPreview.Plan.Status -eq 'whatif' -and -not (Test-Path (Join-Path $testRoot 'data'))) 'Entry point WhatIf must remain artifact-free.'
    $entryResult=& $entryPath -ConfigPath $cfgPath -Device 'iPhone15,2' -BaselineVersion '17.0' -BaselineBuild '21A329' -TargetVersion '17.1' -TargetBuild '21B74' -Stage @('validate') -Mock | Out-String
    Assert-True ($entryResult -match 'partial') 'Entry point should execute the selected mock stage and emit a report record.'
    $r=Invoke-IosResearchPipeline -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74' -Mock
    Assert-True ($r.Status -eq 'completed' -and $r.Stages.Count -eq 4) 'Mock run should complete configured stages.'
    $runDir=Join-Path (Join-Path (Join-Path $testRoot 'data') 'runs') $r.RunId
    Assert-True (Test-Path (Join-Path $runDir 'run.json')) 'State should persist.'
    Assert-True (Test-Path (Join-Path $runDir 'pipeline.log')) 'Structured log should be generated.'
    Assert-True (Test-Path $r.ReportPath) 'Report should be generated.'
    foreach($mockReport in @('firmware-inventory.json','macho-inventory.json','shared-cache-inventory.json','binary-diff-summary.json','candidate-ranking.json','research-report.md','run-manifest.json')){Assert-True (Test-Path (Join-Path $runDir $mockReport)) "Mock report is explicit and generated: $mockReport"}
    $mockReportData=Get-Content (Join-Path $runDir 'macho-inventory.json') -Raw|ConvertFrom-Json
    Assert-True ($mockReportData.EvidenceClass -eq 'simulated' -and $mockReportData.ExecutionStatus -eq 'completed') 'Mock reports remain explicitly simulated and record the finalized overall status.'
    Assert-True ((Get-Content (Join-Path $runDir 'run.json') -Raw | ConvertFrom-Json).ConfigurationHash.Length -eq 64) 'State should include config hash.'
    Assert-Throws { Invoke-IosResearchPipeline -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74' } 'non-mock execution must fail closed'

    $approval=[pscustomobject]@{ authorizedResearch=$true; approvedHosts=@('example.com') }
    $hash='a'*64
    Assert-ThrowsLike { Invoke-IosApprovedDownload -Config $approval -Url 'https://example.com/fw' -Sha256 $hash -Destination (Join-Path $testRoot 'never.ipsw') -AllowDownload -AuthorizedResearch } '*adapter is not implemented*' 'approved mock input reaches disabled adapter'
    Assert-Throws { Assert-IosDownloadApproval -Config $approval -Url 'https://example.com/fw' -Sha256 'bad' -AllowDownload -AuthorizedResearch } 'invalid SHA-256 rejected'
    Assert-Throws { Assert-IosDownloadApproval -Config $approval -Url 'https://evil.example/fw' -Sha256 $hash -AllowDownload -AuthorizedResearch } 'unapproved host rejected'
    Assert-Throws { Assert-IosDownloadApproval -Config $approval -Url 'http://example.com/fw' -Sha256 $hash -AllowDownload -AuthorizedResearch } 'non-HTTPS rejected'
    $noAuth=[pscustomobject]@{ authorizedResearch=$false; approvedHosts=@('example.com') }
    Assert-Throws { Assert-IosDownloadApproval -Config $noAuth -Url 'https://example.com/fw' -Sha256 $hash -AllowDownload -AuthorizedResearch } 'config authorization required'
    $notExplicit=[pscustomobject]@{ authorizedResearch=$true; approvedHosts=@('example.com') }
    Assert-Throws { Assert-IosDownloadApproval -Config $notExplicit -Url 'https://example.com/fw' -Sha256 $hash -AllowDownload } 'explicit authorization switch required'
    Assert-Throws { Invoke-IosApprovedExtraction -InputPath 'mock.ipsw' -Destination (Join-Path $testRoot 'out') } 'extraction approval rejection'
    Assert-ThrowsLike { Invoke-IosApprovedDownload -Config $approval -Url 'https://example.com/fw' -Sha256 $hash -Destination (Join-Path $testRoot 'never.ipsw') -AllowDownload -AuthorizedResearch } '*adapter is not implemented*' 'Destination forwarding regression must not reject an unknown Assert parameter'

    $authorizedConfigPath=Join-Path $testRoot 'authorized-config.json'
    $authorizedConfig=New-TestConfig $authorizedConfigPath @('inventory','report') @() $true
    $ipswPath=Join-Path $testRoot 'synthetic.ipsw'
    New-SyntheticIpsw $ipswPath '17.1' '21B74'
    $ipswCopy=Join-Path $testRoot 'synthetic-copy.ipsw';Copy-Item -LiteralPath $ipswPath -Destination $ipswCopy
    $inputHash=(Get-FileHash -LiteralPath $ipswPath -Algorithm SHA256).Hash
    $firmware=Get-IosFirmwareInventory -Config $authorizedConfig -InputPaths @($ipswPath,$ipswCopy) -ExpectedHashes @{ $ipswPath=$inputHash } -AllowFirmwareAccess -AuthorizedResearch
    Assert-True ($firmware.Inputs.Count -eq 2 -and $firmware.UniqueInputCount -eq 1 -and $firmware.DuplicateInputCount -eq 1) 'Firmware inventory detects duplicate files by SHA-256.'
    Assert-True ($firmware.Inputs[0].SHA256 -eq $inputHash.ToLowerInvariant() -and $firmware.Inputs[0].FileSizeBytes -gt 0) 'Firmware inventory records file SHA-256 and size.'
    Assert-True ($firmware.Inputs[0].FirmwareVersion -eq '17.1' -and $firmware.Inputs[0].Build -eq '21B74' -and $firmware.Inputs[0].DeviceIdentifiers -contains 'iPhone15,2') 'Firmware inventory reads synthetic BuildManifest metadata.'
    Assert-Throws { Get-IosFirmwareInventory -Config $authorizedConfig -InputPaths @(Join-Path $testRoot 'missing.ipsw') -AllowFirmwareAccess -AuthorizedResearch } 'missing IPSW is rejected.'
    Assert-Throws { Get-IosFirmwareInventory -Config $authorizedConfig -InputPaths @($ipswPath) -ExpectedHashes @{ $ipswPath='not-a-hash' } -AllowFirmwareAccess -AuthorizedResearch } 'invalid expected firmware hash is rejected.'
    Assert-Throws { Get-IosFirmwareInventory -Config $authorizedConfig -InputPaths @($ipswPath) -ExpectedHashes @{ $ipswPath=('f'*64) } -AllowFirmwareAccess -AuthorizedResearch } 'firmware hash mismatch is rejected.'
    $invalidIpsw=Join-Path $testRoot 'invalid.ipsw';Set-Content -LiteralPath $invalidIpsw -Value 'invalid archive' -Encoding ASCII
    Assert-Throws { Get-IosFirmwareInventory -Config $authorizedConfig -InputPaths @($invalidIpsw) -IpswCommand '__missing_ipsw__' -AllowFirmwareAccess -AuthorizedResearch } 'invalid firmware metadata is rejected.'
    Assert-Throws { Get-IosFirmwareInventory -Config $cfg -InputPaths @($ipswPath) -AllowFirmwareAccess -AuthorizedResearch } 'config authorization is required for firmware access.'
    $manifestPath=Join-Path $testRoot 'firmware-inventory.json'
    $null=Get-IosFirmwareInventory -Config $authorizedConfig -InputPaths @($ipswPath) -AllowFirmwareAccess -AuthorizedResearch -ManifestPath $manifestPath
    Assert-Throws { Save-IosFirmwareManifest -Manifest $firmware -Path $manifestPath } 'firmware inventory manifest cannot overwrite an existing artifact.'

    $extractArgs=New-IosIpswExtractArguments -InputPath $ipswPath -OutputDirectory (Join-Path $testRoot 'extract-output') -Components @('dyld') -Device 'iPhone15,2' -Architecture @('arm64e')
    Assert-True ($extractArgs -contains '--dyld' -and $extractArgs -contains '--dyld-arch' -and $extractArgs[-1] -eq $ipswPath) 'ipsw extraction arguments use observed local dyld options.'
    Assert-Throws { Invoke-IosFirmwareExtraction -Config $authorizedConfig -InputPath $ipswPath -OutputDirectory (Join-Path $testRoot 'extract-no-approval') -AllowFirmwareAccess -AuthorizedResearch } 'extraction requires -AllowExtraction.'
    Assert-Throws { Invoke-IosFirmwareExtraction -Config $cfg -InputPath $ipswPath -OutputDirectory (Join-Path $testRoot 'extract-no-auth') -AllowFirmwareAccess -AllowExtraction -AuthorizedResearch } 'extraction requires configured authorization.'

    $cacheRoot=Join-Path $testRoot 'cache-root';New-Item -ItemType Directory -Path $cacheRoot|Out-Null
    $cachePath=Join-Path $cacheRoot 'dyld_shared_cache_arm64e';Set-Content -LiteralPath $cachePath -Value 'cache fixture' -Encoding ASCII
    $caches=Find-IosDyldSharedCaches -Roots @($cacheRoot)
    Assert-True ($caches.Count -eq 1 -and $caches[0].Architecture -eq 'arm64e') 'Shared-cache discovery identifies cache architecture from its name.'
    $dylibs=Get-IosDylibRecords -Json (@{images=@(@{path='/System/Library/Frameworks/WebKit.framework/WebKit';version='617.1'})}|ConvertTo-Json -Depth 4|ConvertFrom-Json)
    Assert-True ($dylibs.Count -eq 1 -and $dylibs[0].Name -eq 'WebKit') 'Shared-cache image inventory parses install names.'
    $dylibArgs=New-IosIpswDylibExtractArguments -CachePath $cachePath -InstallName '/usr/lib/libSystem.B.dylib' -OutputDirectory (Join-Path $testRoot 'dylib-out')
    Assert-True ($dylibArgs[0] -eq 'dyld' -and $dylibArgs[1] -eq 'extract') 'Dyld image adapter uses the observed ipsw command shape.'
    Assert-Throws { New-IosIpswDylibExtractArguments -CachePath $cachePath -InstallName 'relative.dylib' -OutputDirectory (Join-Path $testRoot 'bad-dylib') } 'dyld image extraction requires an absolute install name.'

    $binaryRoot=Join-Path $testRoot 'macho';New-Item -ItemType Directory -Path $binaryRoot|Out-Null
    $baseChanged=Join-Path $binaryRoot 'changed.dylib';$targetChanged=Join-Path $binaryRoot 'changed-target.dylib';$sameOld=Join-Path $binaryRoot 'same-old.dylib';$sameNew=Join-Path $binaryRoot 'same-new.dylib';$removed=Join-Path $binaryRoot 'removed.dylib';$added=Join-Path $binaryRoot 'added.dylib'
    New-SyntheticMachO $baseChanged 1 1;New-SyntheticMachO $targetChanged 2 1;New-SyntheticMachO $sameOld 3 2;New-SyntheticMachO $sameNew 3 2;New-SyntheticMachO $removed 4 3;New-SyntheticMachO $added 5 4
    $baseMacho=Get-IosMachOInventory -Roots @($baseChanged,$sameOld,$removed)
    $targetMacho=Get-IosMachOInventory -Roots @($targetChanged,$sameNew,$added)
    Assert-True ($baseMacho.BinaryCount -eq 3 -and $baseMacho.Binaries[0].Architecture -eq 'arm64' -and $baseMacho.Binaries[0].UUID) 'Mach-O inventory parses architecture and UUID.'
    $loadsPath=Join-Path $binaryRoot 'loads.dylib';New-SyntheticMachOWithLoads $loadsPath;$loads=Get-IosMachOInventory -Roots @($loadsPath)
    Assert-True ($loads.Binaries[0].LinkedLibraries -contains '/usr/lib/libSystem.B.dylib' -and $loads.Binaries[0].Symbols -contains 'parseImage') 'Mach-O inventory extracts linked libraries and exported symbol names.'
    $diff=Compare-IosBinaryInventories -Baseline ([pscustomobject]@{Build='21A329';Binaries=$baseMacho.Binaries}) -Target ([pscustomobject]@{Build='21B74';Binaries=$targetMacho.Binaries})
    Assert-True (@($diff.IdenticalBinaries).Count -eq 1 -and @($diff.ChangedBinaries).Count -eq 1 -and @($diff.AddedBinaries).Count -eq 1 -and @($diff.RemovedBinaries).Count -eq 1) 'Binary comparison records identical, changed, added, and removed binaries.'
    $functionsOld=[pscustomobject]@{functions=@([pscustomobject]@{name='parseImage';entryPoint='0x1000';bodySHA256='a';bodyBytes=20},[pscustomobject]@{name='oldCheck';entryPoint='0x2000';bodySHA256='b';bodyBytes=10})}
    $functionsNew=[pscustomobject]@{functions=@([pscustomobject]@{name='parseImage';entryPoint='0x3000';bodySHA256='c';bodyBytes=64},[pscustomobject]@{name='newCheck';entryPoint='0x4000';bodySHA256='d';bodyBytes=10})}
    $functionDiff=Compare-IosFunctionInventories -Baseline $functionsOld -Target $functionsNew
    Assert-True ($functionDiff.ChangedFunctionCount -eq 1 -and $functionDiff.AddedFunctions.Count -eq 1 -and $functionDiff.RemovedFunctions.Count -eq 1) 'Function inventory comparison identifies changed, added, and removed functions.'
    $diff.FunctionComparison=$functionDiff
    foreach($changedFunction in $diff.FunctionComparison.ChangedFunctions){$changedFunction|Add-Member -NotePropertyName BinaryName -NotePropertyValue 'JavaScriptCore' -Force}
    $candidates=Get-IosSecurityCandidates -BinaryDiff $diff -BaselineVersion '17.0' -BaselineBuild '21A329' -TargetVersion '17.1' -TargetBuild '21B74'
    Assert-True ($candidates.CandidateCount -gt 0 -and $candidates.VulnerabilityFindings -eq 0 -and $candidates.Candidates[0].Confidence -eq 'low') 'Candidate ranking is transparent and does not declare vulnerabilities.'
    $reportDir=Join-Path $testRoot 'reports';New-Item -ItemType Directory -Path $reportDir|Out-Null
    $context=[pscustomobject]@{RunId='test-run';DeviceIdentifier='iPhone15,2';BaselineFirmwareVersion='17.0';BaselineBuild='21A329';TargetFirmwareVersion='17.1';TargetBuild='21B74';InputHashes=@();ToolVersions=@{};Status='completed';Mode='mock';Stages=@()}
    $reports=New-IosResearchReports -RunDirectory $reportDir -Context $context -Artifacts @{'binary-diff-summary'=$diff;'candidate-ranking'=$candidates}
    foreach($requiredReport in @('firmware-inventory.json','macho-inventory.json','shared-cache-inventory.json','binary-diff-summary.json','candidate-ranking.json','research-report.md','run-manifest.json')){Assert-True (Test-Path (Join-Path $reportDir $requiredReport)) "Required report is generated: $requiredReport"}
    $reportEnvelope=Get-Content (Join-Path $reportDir 'binary-diff-summary.json') -Raw|ConvertFrom-Json
    Assert-True ($reportEnvelope.Firmware.BaselineBuild -eq '21A329' -and $reportEnvelope.EvidenceClass -match 'simulated' -and $reportEnvelope.PSObject.Properties['InputHashes']) 'Machine reports carry build provenance, evidence class, and input hash fields.'
    Assert-Throws { Write-IosUniqueArtifact -Directory $reportDir -Name 'firmware-inventory.json' -Value @{} } 'report generation preserves an existing artifact.'
    Assert-ThrowsLike { Assert-IosBinDiffCompleted -Result ([pscustomobject]@{Status='failed';ExitCode=2;OutputDirectory='synthetic-output'}) } '*Function matches were not parsed*' 'Failed BinDiff status cannot be promoted to successful pipeline status.'
    Assert-ThrowsLike { Assert-IosBinDiffCompleted -Result ([pscustomobject]@{Status='completed';FunctionMatchesParsed=$false;FunctionMatches=@();ExitCode=0;OutputDirectory='synthetic-output'}) } '*Function matches were not parsed*' 'A BinDiff process without parsed database output cannot be reported complete.'

    $python=Get-Command python.exe -ErrorAction SilentlyContinue|Select-Object -First 1
    if($python){
        $fixtureDb=Join-Path $testRoot 'BinDiff synthetic fixture.sqlite';$fixtureSql=Join-Path (Split-Path -Parent $PSScriptRoot) 'tests\fixtures\bindiff-synthetic.sql';$parser=Join-Path (Split-Path -Parent $PSScriptRoot) 'adapters\BinDiff\ParseBinDiff.py'
        & $python.Source $parser --create-fixture $fixtureDb $fixtureSql
        $fixtureExit=$LASTEXITCODE
        Assert-True ($fixtureExit -eq 0 -and (Test-Path -LiteralPath $fixtureDb)) 'Synthetic BinDiff SQLite fixture is generated locally without network access.'
        $parsed=Read-IosBinDiffDatabase -Path $fixtureDb -PythonCommand $python.Source
        Assert-True ($parsed.Status -eq 'completed' -and $parsed.FunctionCount -eq 4 -and $parsed.MatchedFunctionCount -eq 2) 'BinDiff parser reads actual synthetic SQLite function records.'
        Assert-True ($parsed.ChangedFunctionCount -eq 1 -and $parsed.AddedFunctionCount -eq 1 -and $parsed.RemovedFunctionCount -eq 1) 'BinDiff parser distinguishes changed, added, and removed functions.'
        Assert-True ($parsed.ChangedFunctions[0].Confidence -eq 0.84 -and $parsed.ChangedFunctions[0].Similarity -eq 0.62 -and $parsed.ConfidenceSource -match 'function.confidence') 'BinDiff confidence and similarity are preserved verbatim from source fields.'
        $parsed.ChangedFunctions[0]|Add-Member -NotePropertyName BinaryName -NotePropertyValue 'synthetic.dylib' -Force
        $parsed.ChangedFunctions[0]|Add-Member -NotePropertyName Name -NotePropertyValue $parsed.ChangedFunctions[0].TargetName -Force
        $parsed.ChangedFunctions[0]|Add-Member -NotePropertyName BaselinePath -NotePropertyValue 'baseline/synthetic.dylib' -Force
        $parsed.ChangedFunctions[0]|Add-Member -NotePropertyName TargetPath -NotePropertyValue 'target/synthetic.dylib' -Force
        $parsedCandidate=Get-IosSecurityCandidates -BinaryDiff ([pscustomobject]@{ChangedBinaries=@();AddedBinaries=@();RemovedBinaries=@();FunctionComparison=[pscustomobject]@{ChangedFunctions=@($parsed.ChangedFunctions);AddedFunctions=@();RemovedFunctions=@()}}) -BaselineBuild 'old' -TargetBuild 'new'
        Assert-True ($parsedCandidate.Candidates.Count -eq 1 -and $parsedCandidate.Candidates[0].FunctionName -eq 'changedParser' -and $parsedCandidate.Candidates[0].ComparisonEvidence.Confidence -eq 0.84) 'Candidate ranking consumes the parsed function name and preserves native BinDiff confidence as evidence.'
        $parsedRun=Assert-IosBinDiffCompleted -Result ([pscustomobject]@{Status='completed';FunctionMatchesParsed=$true;ParsedResult=$parsed;FunctionMatches=@($parsed.Matches);ExitCode=0})
        Assert-True ($parsedRun.FunctionMatchesParsed -and $parsedRun.ParsedResult.FunctionCount -eq 4) 'Completion contract accepts a fully parsed database result.'
    } else { Write-Warning 'Python unavailable; BinDiff SQLite parser fixture assertions skipped.' }

    $selection=Select-IosDylibImages -Caches @([pscustomobject]@{CachePath='cache-arm64e';Architecture='arm64e';Images=@([pscustomobject]@{InstallName='/System/Library/Frameworks/WebKit.framework/WebKit';Name='WebKit'},[pscustomobject]@{InstallName='/usr/lib/libSystem.B.dylib';Name='libSystem.B.dylib'})},[pscustomobject]@{CachePath='cache-arm64';Architecture='arm64';Images=@([pscustomobject]@{InstallName='/System/Library/Frameworks/WebKit.framework/WebKit';Name='WebKit'})}) -Architecture @('arm64e') -Components @('WebKit')
    Assert-True ($selection.Count -eq 1 -and $selection[0].Architecture -eq 'arm64e' -and $selection[0].Component -eq 'WebKit') 'Shared-cache image selection honors architecture and component filters.'
    $cacheRoleConfig=[pscustomobject]@{sharedCacheRoots=@('baseline-cache','target-cache')};$cacheRoots=@(& (Get-Module IosResearchPipeline) { param($c,$base) Get-IosSharedCacheRootEntries -Config $c -BasePath $base } $cacheRoleConfig $testRoot)
    Assert-True ($cacheRoots.Count -eq 2 -and $cacheRoots[0].Role -eq 'baseline' -and $cacheRoots[1].Role -eq 'target') 'Two untagged shared-cache roots map consistently to baseline and target roles.'
    $autoBinary=Join-Path $binaryRoot 'auto-extracted.dylib';New-SyntheticMachO $autoBinary 6 5
    $pipelineModule=Get-Module IosResearchPipeline
    $autoEntries=@(& $pipelineModule { param($record) Get-IosExtractedAnalysisEntries -Record $record } ([pscustomobject]@{Stages=@([pscustomobject]@{Name='shared-cache';Status='completed';Result=[pscustomobject]@{ImageExtractions=@([pscustomobject]@{Role='target';OutputFiles=@([pscustomobject]@{Path=$autoBinary})})}})}))
    Assert-True ($autoEntries.Count -eq 1 -and $autoEntries[0].Role -eq 'target' -and $autoEntries[0].Source -eq 'shared-cache-dylib-extraction') 'Mach-O auto discovery consumes completed role-tagged dylib outputs.'

    $analysisConfigPath=Join-Path $testRoot 'analysis-config.json'
    $analysisConfig=New-TestConfig $analysisConfigPath @('macho','binary-diff','candidates','report') @() $true
    $analysisConfig.components=@()
    $analysisConfig.analysisInputPaths=@([ordered]@{Role='baseline';Path=$baseChanged},[ordered]@{Role='baseline';Path=$sameOld},[ordered]@{Role='baseline';Path=$removed},[ordered]@{Role='target';Path=$targetChanged},[ordered]@{Role='target';Path=$sameNew},[ordered]@{Role='target';Path=$added})
    $analysisConfig|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $analysisConfigPath -Encoding UTF8
    $analysisRun=Invoke-IosResearchPipeline -ConfigPath $analysisConfigPath -Product 'iPhone15,2' -Build '21B74' -BaselineBuild '21A329' -AllowFirmwareAccess -AuthorizedResearch
    $analysisRunDir=Join-Path (Join-Path (Join-Path $testRoot 'data') 'runs') $analysisRun.RunId
    $analysisSummary=(Get-Content (Join-Path $analysisRunDir 'binary-diff-summary.json') -Raw|ConvertFrom-Json).Data
    Assert-True ($analysisSummary.ChangedCount -eq 1 -and $analysisSummary.AddedCount -eq 1 -and $analysisSummary.RemovedCount -eq 1) 'Compact report summary preserves binary classifications while detailed records remain in the stage artifact.'
    Assert-True ($analysisRun.Stages[0].Result.ParsedBinaryCount -eq 6 -and $analysisRun.Stages[1].Result.Status -eq 'completed') 'Mach-O stage exposes parsed outputs consumed by the completed diff stage.'
    Assert-True (Test-Path (Join-Path $analysisRunDir 'firmware-inventory.json')) 'Final report stage emits the canonical report name alongside stage artifacts.'
    Assert-True (Test-Path (Join-Path $analysisRunDir 'research-report.md')) 'Pipeline report stage emits the human-readable report.'
    $analysisRecord=Get-Content (Join-Path $analysisRunDir 'run.json') -Raw|ConvertFrom-Json
    Assert-True ($analysisRecord.ReportPath -and $analysisRecord.OutputPaths -contains $analysisRecord.ReportPath) 'Run state points to its Markdown report and aggregates stage artifacts.'

    Import-Module $extractModulePath -Force
    $sleepExe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $interrupted=Invoke-IosLocalProcess -Executable $sleepExe -Arguments @('-NoProfile','-Command','Start-Sleep -Seconds 3') -TimeoutSeconds 1
    Assert-True $interrupted.TimedOut 'Tool timeout is recorded as an interrupted operation.'

    $partial=Invoke-IosResearchPipeline -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74' -Stage @('validate') -Mock
    Assert-True ($partial.Status -eq 'partial') 'Selected stages can run independently.'
    Assert-ThrowsLike { Invoke-IosResearchPipeline -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74' -Stage @('analyze-metadata') -Mock } "*requires a successful 'inventory' stage*" 'Metadata stage cannot report success without its required inventory.'
    Assert-ThrowsLike { Invoke-IosResearchPipeline -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74' -ResumeRunId $partial.RunId -Stage @('validate') } '*Cannot resume a mock run in research mode*' 'A mock run cannot be resumed as real research.'
    $statePath=Join-Path (Join-Path (Join-Path (Join-Path $testRoot 'data') 'runs') $partial.RunId) 'run.json'
    $state=Get-Content $statePath -Raw | ConvertFrom-Json
    $state.Stages[0].Status='failed'; $state.Stages[0].ExitCode=9
    $state | ConvertTo-Json -Depth 10 | Set-Content $statePath -Encoding UTF8
    $resumed=Invoke-IosResearchPipeline -ConfigPath $cfgPath -Product 'iPhone15,2' -Build '21B74' -ResumeRunId $partial.RunId -Stage @('validate') -Mock
    Assert-True ($resumed.Stages[0].Status -eq 'mocked' -and $resumed.Stages[0].ExitCode -eq 0) 'Resume retries a failed stage and records mock completion.'

    $inputFile=Join-Path $testRoot 'input.ipsw'
    New-SyntheticIpsw $inputFile '17.1' '21B74'
    $inputCfgPath=Join-Path $testRoot 'input-config.json'
    $inputCfg=New-TestConfig $inputCfgPath @('inventory','report') @($inputFile) $true
    $mockInputCfgPath=Join-Path $testRoot 'mock-input-config.json'
    $mockInputCfg=New-TestConfig $mockInputCfgPath @('inventory','report') @($inputFile) $true
    $mockInputRun=Invoke-IosResearchPipeline -ConfigPath $mockInputCfgPath -Product 'iPhone15,2' -Build '21B74' -Mock
    Assert-True (@($mockInputRun.InputHashes).Count -eq 0 -and $mockInputRun.Stages[0].Status -eq 'mocked') 'Mock execution does not open or hash configured firmware inputs.'
    $inputRun=Invoke-IosResearchPipeline -ConfigPath $inputCfgPath -Product 'iPhone15,2' -Build '21B74' -BaselineBuild '21A329' -BaselineVersion '17.0' -TargetVersion '17.1' -AllowFirmwareAccess -AuthorizedResearch
    $zip=[IO.Compression.ZipFile]::Open($inputFile,[IO.Compression.ZipArchiveMode]::Update);try{$entry=$zip.CreateEntry('Payload/marker.bin');$stream=$entry.Open();$writer=New-Object IO.StreamWriter($stream);$writer.Write('synthetic content change');$writer.Dispose();$stream.Dispose()}finally{$zip.Dispose()}
    $changedRun=Invoke-IosResearchPipeline -ConfigPath $inputCfgPath -Product 'iPhone15,2' -Build '21B74' -BaselineBuild '21A329' -BaselineVersion '17.0' -TargetVersion '17.1' -ResumeRunId $inputRun.RunId -Stage @('inventory') -AllowFirmwareAccess -AuthorizedResearch
    Assert-True (@($changedRun.Stages | Where-Object { $_.Name -eq 'report' -and $_.Status -eq 'invalidated' }).Count -eq 1) 'Changed IPSW hash invalidates dependent report stage while inventory is rerun.'
    $inputRunDir=Join-Path (Join-Path (Join-Path $testRoot 'data') 'runs') $inputRun.RunId
    Assert-True (Test-Path (Join-Path $inputRunDir 'research-report.md')) 'Resume preserves prior research report artifacts.'
    Assert-True (@(Get-ChildItem -LiteralPath $inputRunDir -Filter 'inventory-stage-result*.json').Count -ge 2) 'Resume writes a new inventory artifact without overwriting the old one.'

    $preflight=Get-IosEnvironmentPreflight -Config $cfg
    Assert-True ($preflight.PowerShellVersion -match '^5\.1') 'Tests run on Windows PowerShell 5.1.'
    Assert-True (-not $preflight.Tools.python.Available -and -not $preflight.Tools.wsl.Available) 'Missing optional tools are reported without blocking.'
    Assert-Throws { Save-IosRunState -State ([pscustomobject]@{ RunId='other' }) -Path $statePath } 'state protection rejects a different run record'
    Write-Output "PASS: $script:passed mock assertions"
} catch {
    $script:failed++
    Write-Error "FAIL: $($_.Exception.Message)"
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module IosResearchPipeline -ErrorAction SilentlyContinue
}
if ($script:failed -gt 0) { exit 1 }
