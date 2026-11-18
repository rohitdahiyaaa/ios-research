Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosResearchState.psm1') -Force

function Get-IosUniqueArtifactPath {
    param([Parameter(Mandatory=$true)][string]$Directory,[Parameter(Mandatory=$true)][string]$Name)
    $path=Join-Path $Directory $Name
    if(Test-Path -LiteralPath $path){$base=[IO.Path]::GetFileNameWithoutExtension($Name);$ext=[IO.Path]::GetExtension($Name);$path=Join-Path $Directory ($base+'-'+[guid]::NewGuid().ToString('N')+$ext)}
    return $path
}

function Write-IosUniqueArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Directory,[string]$Name,[string]$Path,$Value,[switch]$Markdown)
    if(-not(Test-Path -LiteralPath $Directory -PathType Container)){throw "Report directory does not exist: $Directory"}
    if(-not $Path){if(-not $Name){throw 'Name or Path is required.'};$Path=Get-IosUniqueArtifactPath -Directory $Directory -Name $Name}
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith([IO.Path]::GetFullPath($Directory).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Report path must remain inside the run directory.'}
    if(Test-Path -LiteralPath $full){throw "Refusing to overwrite report artifact: $full"}
    if($Markdown){$content=[string]$Value}else{$content=ConvertTo-Json -InputObject $Value -Depth 20}
    $bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($content)
    $fs=$null;try{$fs=New-Object IO.FileStream($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$fs.Write($bytes,0,$bytes.Length)}finally{if($fs){$fs.Dispose()}}
    return $full
}

function Get-IosResearchReportPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RunDirectory)
    $names=@('firmware-inventory.json','macho-inventory.json','shared-cache-inventory.json','binary-diff-summary.json','candidate-ranking.json','research-report.md','run-manifest.json')
    $plan=[ordered]@{}
    foreach($name in $names){$plan[$name]=Get-IosUniqueArtifactPath -Directory $RunDirectory -Name $name}
    return $plan
}

function Get-IosReportDataSummary {
    param([string]$Key,$Value)
    if($null -eq $Value){
        switch($Key){
            'firmware-inventory' {return [pscustomobject]@{Status='not-run';Validation='not-run';Inputs=@();Reason='Stage was not executed or its input was not available.'}}
            'macho-inventory' {return [pscustomobject]@{Status='not-run';BinaryCount=0;ParsedBinaryCount=0;Reason='Stage was not executed or its input was not available.'}}
            'shared-cache-inventory' {return [pscustomobject]@{Status='not-run';Caches=@();ImageExtractionCount=0;Reason='Stage was not executed or its input was not available.'}}
            'binary-diff-summary' {return [pscustomobject]@{Status='not-run';IdenticalCount=0;ChangedCount=0;AddedCount=0;RemovedCount=0;Reason='Stage was not executed or its input was not available.'}}
            'candidate-ranking' {return [pscustomobject]@{Status='not-run';CandidateCount=0;Candidates=@();Reason='Stage was not executed or its input was not available.'}}
            default {return [pscustomobject]@{Status='not-run';Reason='Stage was not executed or its input was not available.'}}
        }
    }
    $stageName=switch($Key){'firmware-inventory'{'inventory'}'macho-inventory'{'macho'}'shared-cache-inventory'{'shared-cache'}'binary-diff-summary'{'binary-diff'}'candidate-ranking'{'candidates'}default{$Key}}
    if($Value.PSObject.Properties['SchemaVersion'] -and $Value.PSObject.Properties['Stage']){return $Value}
    if(Get-Command Get-IosStageResultSummary -ErrorAction SilentlyContinue){return Get-IosStageResultSummary -StageName $stageName -Result $Value}
    $status='available';if($Value.PSObject.Properties['Status']){$status=$Value.Status}
    return [pscustomobject]@{Status=$status}
}

function Get-IosReportFileReference {
    param([string]$Kind,[string]$Path,[hashtable]$Metadata=@{},[switch]$IncludeHash)
    if(-not $Path -or -not(Test-Path -LiteralPath $Path -PathType Leaf)){return [pscustomobject]@{Kind=$Kind;Path=$Path;SizeBytes=$null;SHA256=$null;Metadata=$Metadata}}
    $full=[IO.Path]::GetFullPath($Path);$item=Get-Item -LiteralPath $full;$hash=$null
    if($IncludeHash){$hash=(Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    [pscustomobject]@{Kind=$Kind;Path=$full;SizeBytes=[long]$item.Length;SHA256=$hash;Metadata=$Metadata}
}

function Get-IosReportStageRecord {
    param($Stage)
    $started=$Stage.StartedAt;$completed=$Stage.CompletedAt;$duration=$null
    if($started -and $completed){try{$duration=([DateTime]::Parse($completed).ToUniversalTime()-[DateTime]::Parse($started).ToUniversalTime()).TotalSeconds}catch{}}
    [pscustomobject]@{
        Name=$Stage.Name;Status=$Stage.Status;StartedAt=$started;CompletedAt=$completed;DurationSeconds=$duration;ExitCode=$Stage.ExitCode
        Error=if($Stage.PSObject.Properties['Error']){$Stage.Error}else{$null};Details=$Stage.Details;ValidationResult=$Stage.ValidationResult
        InputHashes=@($Stage.InputHashes);OutputPaths=@($Stage.OutputPaths);ResultPath=if($Stage.PSObject.Properties['ResultPath']){$Stage.ResultPath}else{$null}
        ResultSummary=if($Stage.PSObject.Properties['ResultSummary']){$Stage.ResultSummary}else{$null}
    }
}

function New-IosResearchReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RunDirectory,
        [Parameter(Mandatory=$true)]$Context,
        [hashtable]$Artifacts=@{},
        [hashtable]$ArtifactReferences=@{},
        $Plan,
        [switch]$DeferManifest
    )
    if(-not $Plan){$Plan=Get-IosResearchReportPlan -RunDirectory $RunDirectory}
    $keys=[ordered]@{'firmware-inventory'='firmware-inventory.json';'macho-inventory'='macho-inventory.json';'shared-cache-inventory'='shared-cache-inventory.json';'binary-diff-summary'='binary-diff-summary.json';'candidate-ranking'='candidate-ranking.json'}
    $summaries=@{};$paths=[ordered]@{}
    foreach($key in $keys.Keys){
        $summary=Get-IosReportDataSummary -Key $key -Value $Artifacts[$key];$summaries[$key]=$summary
        $ref=$ArtifactReferences[$key]
        $envelope=[pscustomobject]@{
            SchemaVersion=2;ReportType=$key;GeneratedAt=[DateTime]::UtcNow.ToString('o')
            ExecutionStatus=$Context.Status;Mode=$Context.Mode
            Firmware=[pscustomobject]@{DeviceIdentifier=$Context.DeviceIdentifier;BaselineVersion=$Context.BaselineFirmwareVersion;BaselineBuild=$Context.BaselineBuild;TargetVersion=$Context.TargetFirmwareVersion;TargetBuild=$Context.TargetBuild}
            InputHashes=@($Context.InputHashes);ToolVersions=$Context.ToolVersions
            EvidenceClass=if($Context.Mode -eq 'mock'){'simulated'}else{'automated observation; manual validation required'}
            ArtifactReference=$ref;Data=$summary
            Limitations=@('Detailed stage data remains in the referenced artifact.','Automated observations and heuristic rankings do not establish a vulnerability.')
        }
        $paths[$key]=$Plan[$keys[$key]]
        Write-IosUniqueArtifact -Directory $RunDirectory -Path $paths[$key] -Value $envelope | Out-Null
    }
    $firmware=$summaries['firmware-inventory'];$macho=$summaries['macho-inventory'];$cache=$summaries['shared-cache-inventory'];$diff=$summaries['binary-diff-summary'];$candidate=$summaries['candidate-ranking']
    $lines=New-Object System.Collections.ArrayList
    foreach($line in @('# iOS Firmware Research Report','',('Run ID: '+$Context.RunId),('Execution status: '+$Context.Status),('Mode: '+$Context.Mode),('Baseline: '+$Context.BaselineFirmwareVersion+' ('+$Context.BaselineBuild+')'),('Target: '+$Context.TargetFirmwareVersion+' ('+$Context.TargetBuild+')'),('Generated UTC: '+[DateTime]::UtcNow.ToString('o')),'','## Execution and provenance','','### Stage statuses')){[void]$lines.Add($line)}
    foreach($stage in @($Context.Stages)){[void]$lines.Add(('- {0}: {1}; exit code {2}' -f $stage.Name,$stage.Status,$stage.ExitCode))}
    [void]$lines.Add('');[void]$lines.Add('### Input SHA-256')
    foreach($inputHash in @($Context.InputHashes)){if($inputHash.Path){[void]$lines.Add(('- `{0}` — `{1}`' -f $inputHash.Path,$inputHash.SHA256))}}
    if(-not @($Context.InputHashes).Count){[void]$lines.Add('- No firmware or analysis inputs were hashed for this execution.')}
    [void]$lines.Add('');[void]$lines.Add('### Tool probes')
    $toolEntries=New-Object System.Collections.ArrayList
    if($Context.ToolVersions -is [System.Collections.IDictionary]){foreach($toolName in $Context.ToolVersions.Keys){[void]$toolEntries.Add([pscustomobject]@{Name=[string]$toolName;Value=$Context.ToolVersions[$toolName]})}}
    else{foreach($toolProperty in $Context.ToolVersions.PSObject.Properties){[void]$toolEntries.Add([pscustomobject]@{Name=$toolProperty.Name;Value=$toolProperty.Value})}}
    foreach($tool in $toolEntries){$versionProperty=$null;$executedProperty=$null;if($tool.Value){$versionProperty=$tool.Value.PSObject.Properties['Version'];$executedProperty=$tool.Value.PSObject.Properties['Executed']};$version=if($versionProperty -and $versionProperty.Value){$versionProperty.Value}else{'unavailable'};$executed=if($executedProperty -and $executedProperty.Value){'executed'}else{'not executed'};[void]$lines.Add(('- {0}: {1} ({2})' -f $tool.Name,$version,$executed))}
    if(-not $toolEntries.Count){[void]$lines.Add('- No tool probe data was supplied.')}
    foreach($line in @('','## Verified facts','','- Firmware input hashes and metadata are verified only when the inventory stage completed.','- Firmware version/build labels are supplied identifiers; this project does not independently verify Apple release pairings.','- No network access is performed by this report generator.','')){[void]$lines.Add($line)}
    if($firmware -and $firmware.PSObject.Properties['Validation'] -and $firmware.Validation -eq 'valid'){foreach($input in @($firmware.Inputs)){[void]$lines.Add(('- `{0}` — SHA-256 `{1}`, {2} bytes, {3} build {4}.' -f $input.FileName,$input.SHA256,$input.FileSizeBytes,$input.FirmwareVersion,$input.Build))}}else{[void]$lines.Add('- Firmware inventory was not completed; no firmware metadata is asserted.')}
    [void]$lines.Add('');[void]$lines.Add('## Automated observations');[void]$lines.Add('')
    if($diff -and $diff.Status -ne 'not-run'){[void]$lines.Add(('- Binary comparison: {0} identical, {1} changed, {2} added, {3} removed.' -f $diff.IdenticalCount,$diff.ChangedCount,$diff.AddedCount,$diff.RemovedCount))}else{[void]$lines.Add('- Binary comparison was not run.')}
    if($macho -and $macho.Status -ne 'not-run'){[void]$lines.Add(('- Mach-O inventory contains {0} parsed binaries.' -f $macho.ParsedBinaryCount))}else{[void]$lines.Add('- Mach-O inventory was not run.')}
    if($cache -and $cache.Status -ne 'not-run'){[void]$lines.Add(('- Shared-cache inventory contains {0} caches.' -f @($cache.Caches).Count))}else{[void]$lines.Add('- Shared-cache inventory was not run.')}
    [void]$lines.Add('');[void]$lines.Add('## Heuristic candidate ranking');[void]$lines.Add('')
    if($candidate -and $candidate.Status -ne 'not-run'){foreach($item in @($candidate.Candidates|Select-Object -First 25)){[void]$lines.Add(('- #{0} score {1}/100 ({2}) — {3} / {4} / {5}: {6}' -f $item.Rank,$item.Score,$item.Confidence,$item.Component,$item.Binary,$item.FunctionName,$item.Reason))}}else{[void]$lines.Add('- No candidate ranking was generated.')}
    [void]$lines.Add('');[void]$lines.Add('## Manual validation required');[void]$lines.Add('');[void]$lines.Add('- Review changed code in context, including callers, data flow, architecture, relocations, and compiler transformations.');[void]$lines.Add('- Validate any security impact manually. Automated changes are not vulnerability findings.');[void]$lines.Add('');[void]$lines.Add('## Limitations');[void]$lines.Add('');[void]$lines.Add('- File hash changes can result from code signatures, relocation, rebasing, or metadata.');[void]$lines.Add('- Function matches based on names and instruction-byte hashes are heuristic and can miss split, merged, or renamed functions.');[void]$lines.Add('- This report does not establish a vulnerability, exploitability, CVE association, or disclosure status.')
    $paths['research-report.md']=$Plan.'research-report.md'
    Write-IosUniqueArtifact -Directory $RunDirectory -Path $paths['research-report.md'] -Value ($lines -join "`r`n") -Markdown | Out-Null
    $reportRefs=@()
    foreach($key in $keys.Keys){$reportRefs+=Get-IosReportFileReference -Kind 'report-summary' -Path $paths[$key] -IncludeHash}
    $reportRefs+=Get-IosReportFileReference -Kind 'research-report' -Path $paths['research-report.md'] -IncludeHash
    $manifestPath=$Plan.'run-manifest.json'
    $paths['run-manifest.json']=$manifestPath
    if(-not $DeferManifest){
        $manifest=New-IosCompactRunManifest -Context $Context -ArtifactReferences (@($ArtifactReferences.Values)+@($reportRefs)) -ReportManifestPath $manifestPath
        Write-IosUniqueArtifact -Directory $RunDirectory -Path $manifestPath -Value $manifest | Out-Null
    }
    [pscustomobject]@{ReportPaths=$paths;ManifestPath=$manifestPath;MarkdownPath=$paths['research-report.md'];Summaries=$summaries;ArtifactReferences=(@($ArtifactReferences.Values)+@($reportRefs))}
}

function New-IosCompactRunManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Context,[object[]]$ArtifactReferences=@(),[string]$ReportManifestPath)
    $stages=@($Context.Stages | ForEach-Object {Get-IosReportStageRecord -Stage $_})
    $seconds=0.0;foreach($stage in $stages){if($null -ne $stage.DurationSeconds){$seconds += [double]$stage.DurationSeconds}}
    $outputRefs=@($ArtifactReferences)
    if($ReportManifestPath){$outputRefs+=,[pscustomobject]@{Kind='run-manifest';Path=[IO.Path]::GetFullPath($ReportManifestPath);SizeBytes=$null;SHA256=$null;Metadata=@{SelfReference=$true;Reason='A manifest cannot contain its own final hash.'}}}
    [pscustomobject]@{
        SchemaVersion=2;RunId=$Context.RunId;Status=$Context.Status;ExecutionStatus=$Context.Status;GeneratedAt=[DateTime]::UtcNow.ToString('o');Mode=$Context.Mode;DeviceIdentifier=$Context.DeviceIdentifier
        BaselineFirmwareVersion=$Context.BaselineFirmwareVersion;BaselineBuild=$Context.BaselineBuild;TargetFirmwareVersion=$Context.TargetFirmwareVersion;TargetBuild=$Context.TargetBuild
        CreatedAt=if($Context.PSObject.Properties['CreatedAt']){$Context.CreatedAt}else{$null};CompletedAt=if($Context.PSObject.Properties['CompletedAt']){$Context.CompletedAt}else{$null};DurationSeconds=$seconds;ElapsedSeconds=if($Context.PSObject.Properties['ElapsedSeconds']){$Context.ElapsedSeconds}else{$null}
        InputHashes=@($Context.InputHashes);ToolVersions=$Context.ToolVersions;NetworkAccess=$false;Stages=$stages
        ArtifactReferences=$outputRefs
        ErrorInformation=@($stages | Where-Object {$_.Error -or $_.Status -in @('failed','interrupted')} | ForEach-Object {[pscustomobject]@{Stage=$_.Name;Status=$_.Status;ExitCode=$_.ExitCode;Error=$_.Error;Details=$_.Details}})
        Limitations=@('Detailed results are preserved in the referenced stage artifacts.','Automated observations require manual validation.','No vulnerability claims are produced.')
    }
}

Export-ModuleMember -Function Write-IosUniqueArtifact,Get-IosResearchReportPlan,New-IosResearchReports,New-IosCompactRunManifest,Get-IosReportFileReference
