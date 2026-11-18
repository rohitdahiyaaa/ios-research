Set-StrictMode -Version 2.0

function Get-IosStateFileHash {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-IosPropertyValue {
    param($Object,[string]$Name,$Default=$null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $Default
}

function Get-IosStageResultSummary {
    [CmdletBinding()]
    param([string]$StageName,$Result)
    if ($null -eq $Result) { return $null }
    $summary = [ordered]@{ SchemaVersion=1; Stage=$StageName; Status=(Get-IosPropertyValue $Result 'Status') }
    switch ($StageName) {
        'validate' {
            foreach ($name in @('DeviceIdentifier','BaselineBuild','TargetBuild','VersionBuildVerified','Validation')) {
                $value=Get-IosPropertyValue $Result $name
                if ($null -ne $value) { $summary[$name]=$value }
            }
        }
        'environment' {
            $summary['CollectedAt']=Get-IosPropertyValue $Result 'CollectedAt'
            $summary['PowerShell']=Get-IosPropertyValue $Result 'PowerShell'
            $summary['Tools']=Get-IosPropertyValue $Result 'Tools'
            $summary['AvailableDiskBytes']=Get-IosPropertyValue $Result 'AvailableDiskBytes'
        }
        'inventory' {
            $summary['Validation']=Get-IosPropertyValue $Result 'Validation'
            $summary['InputCount']=@((Get-IosPropertyValue $Result 'Inputs' @())).Count
            $summary['Inputs']=@((Get-IosPropertyValue $Result 'Inputs' @()) | ForEach-Object {
                [pscustomobject]@{Path=$_.Path;FileName=$_.FileName;SHA256=$_.SHA256;FileSizeBytes=$_.FileSizeBytes;FirmwareVersion=$_.FirmwareVersion;Build=$_.Build;DeviceIdentifiers=@($_.DeviceIdentifiers);MetadataSource=$_.MetadataSource;Role=$_.Role}
            })
            $request=Get-IosPropertyValue $Result 'RequestValidation'
            if ($request) { $summary['RequestValidation']=[pscustomobject]@{Status=$request.Status;Errors=@($request.Errors)} }
        }
        'extract' {
            $items=@(Get-IosPropertyValue $Result 'Extractions' @())
            $summary['ExtractionCount']=$items.Count
            $summary['Extractions']=@($items | ForEach-Object {
                $files=@($_.OutputFiles)
                [pscustomobject]@{Role=$_.Role;InputPath=$_.InputPath;InputSHA256=$_.InputSHA256;Status=$_.Extraction.Status;ExitCode=$_.Extraction.ExitCode;OutputCount=$files.Count;OutputBytes=[long](($files | Measure-Object -Property SizeBytes -Sum).Sum);OutputFiles=$files;Attempts=@($_.Attempts | ForEach-Object {[pscustomobject]@{Status=$_.Status;ExitCode=$_.ExitCode;StartedAt=$_.StartedAt;CompletedAt=$_.CompletedAt;OutputDirectory=$_.OutputDirectory}})}
            })
            $summary['NetworkAccess']=Get-IosPropertyValue $Result 'NetworkAccess' $false
        }
        'shared-cache' {
            $summary['Caches']=@((Get-IosPropertyValue $Result 'Caches' @()) | ForEach-Object {[pscustomobject]@{Role=$_.Role;Architecture=$_.Architecture;ImageCount=$_.ImageCount;Path=$_.Path;CacheSHA256=$_.CacheSHA256}})
            $images=@(Get-IosPropertyValue $Result 'ImageExtractions' @())
            $summary['ImageExtractionCount']=$images.Count
            $summary['ImageExtractionsByRole']=@($images | Group-Object Role | ForEach-Object {[pscustomobject]@{Role=$_.Name;Count=$_.Count;CompletedCount=@($_.Group | Where-Object {$_.Extraction.Status -eq 'completed' -and $_.Extraction.ExitCode -eq 0}).Count}})
            $summary['DylibExtractionEnabled']=Get-IosPropertyValue $Result 'DylibExtractionEnabled'
            $summary['NetworkAccess']=Get-IosPropertyValue $Result 'NetworkAccess' $false
        }
        'macho' {
            $binaries=@(Get-IosPropertyValue $Result 'Binaries' @())
            $summary['BinaryCount']=Get-IosPropertyValue $Result 'BinaryCount' $binaries.Count
            $summary['ParsedBinaryCount']=Get-IosPropertyValue $Result 'ParsedBinaryCount' (@($binaries | Where-Object {$_.Status -eq 'parsed'}).Count)
            $summary['ByRole']=@((Get-IosPropertyValue $Result 'ByRole' @()) | ForEach-Object {[pscustomobject]@{Role=$_.Role;BinaryCount=@($_.Binaries).Count;ParsedBinaryCount=@($_.Binaries | Where-Object {$_.Status -eq 'parsed'}).Count}})
        }
        'binary-diff' {
            foreach ($pair in @(@('IdenticalBinaries','IdenticalCount'),@('ChangedBinaries','ChangedCount'),@('AddedBinaries','AddedCount'),@('RemovedBinaries','RemovedCount'))) {
                $values=@(Get-IosPropertyValue $Result $pair[0] @())
                $summary[$pair[1]]=$values.Count
            }
            $comparison=Get-IosPropertyValue $Result 'FunctionComparison'
            if ($comparison) { $summary['FunctionComparison']=[pscustomobject]@{MatchedFunctionCount=(Get-IosPropertyValue $comparison 'MatchedFunctionCount');ChangedFunctionCount=(Get-IosPropertyValue $comparison 'ChangedFunctionCount');AddedFunctionCount=@(Get-IosPropertyValue $comparison 'AddedFunctions' @()).Count;RemovedFunctionCount=@(Get-IosPropertyValue $comparison 'RemovedFunctions' @()).Count;BinDiffUsed=(Get-IosPropertyValue $comparison 'BinDiffUsed');PairCount=@(Get-IosPropertyValue $comparison 'Pairs' @()).Count;Status=(Get-IosPropertyValue $comparison 'Status')} }
            $runs=@(Get-IosPropertyValue $Result 'BinDiffRuns' @())
            $summary['BinDiffRunCount']=$runs.Count
            $summary['BinDiffCompletedCount']=@($runs | Where-Object {$_.Status -eq 'completed'}).Count
            $summary['BinDiffVersions']=@($runs | Select-Object -ExpandProperty ToolVersion -Unique)
            $summary['Status']=Get-IosPropertyValue $Result 'Status'
        }
        'candidates' {
            $candidates=@(Get-IosPropertyValue $Result 'Candidates' @())
            $summary['CandidateCount']=Get-IosPropertyValue $Result 'CandidateCount' $candidates.Count
            $summary['VulnerabilityFindings']=Get-IosPropertyValue $Result 'VulnerabilityFindings' 0
            $summary['Candidates']=@($candidates | Select-Object -First 25 | ForEach-Object {[pscustomobject]@{Rank=$_.Rank;Score=$_.Score;Confidence=$_.Confidence;Component=$_.Component;Binary=$_.Binary;FunctionName=$_.FunctionName;Reason=$_.Reason}})
        }
        'report' {
            $summary['ReportPaths']=Get-IosPropertyValue $Result 'ReportPaths'
            $summary['ManifestPath']=Get-IosPropertyValue $Result 'ManifestPath'
        }
        default {
            foreach ($name in @('Validation','Claims','Analysis','FirmwareInventoryPath','NetworkAccess','CandidateCount','ParsedBinaryCount','BinaryCount')) {
                $value=Get-IosPropertyValue $Result $name
                if ($null -ne $value) { $summary[$name]=$value }
            }
        }
    }
    return [pscustomobject]$summary
}

function Get-IosCompactStageRecord {
    param($Stage)
    $resultSummary=Get-IosPropertyValue $Stage 'ResultSummary'
    if (-not $resultSummary) { $resultSummary=Get-IosStageResultSummary -StageName ([string]$Stage.Name) -Result (Get-IosPropertyValue $Stage 'Result') }
    $started=Get-IosPropertyValue $Stage 'StartedAt';$completed=Get-IosPropertyValue $Stage 'CompletedAt';$duration=$null
    if ($started -and $completed) { try {$duration=([DateTime]::Parse($completed).ToUniversalTime()-[DateTime]::Parse($started).ToUniversalTime()).TotalSeconds} catch {} }
    [pscustomobject]@{
        Name=$Stage.Name;Status=$Stage.Status;StartedAt=$started;CompletedAt=$completed;DurationSeconds=$duration
        ExitCode=(Get-IosPropertyValue $Stage 'ExitCode');Error=(Get-IosPropertyValue $Stage 'Error')
        Details=(Get-IosPropertyValue $Stage 'Details');ValidationResult=(Get-IosPropertyValue $Stage 'ValidationResult')
        InputHashes=@(Get-IosPropertyValue $Stage 'InputHashes' @());OutputPaths=@(Get-IosPropertyValue $Stage 'OutputPaths' @())
        ResultPath=(Get-IosPropertyValue $Stage 'ResultPath');ResultSummary=$resultSummary;Result=$resultSummary
    }
}

function Get-IosCompactRunState {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$State)
    $copy=[ordered]@{}
    foreach($property in $State.PSObject.Properties){if($property.Name -ne 'Stages'){$copy[$property.Name]=$property.Value}}
    $copy['SchemaVersion']=4
    $copy['Stages']=@($State.Stages | ForEach-Object {Get-IosCompactStageRecord -Stage $_})
    return [pscustomobject]$copy
}

function Get-IosRunSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$State)
    $compact=Get-IosCompactRunState -State $State
    $stageSeconds=0.0
    foreach($stage in @($compact.Stages)){if($null -ne $stage.DurationSeconds){$stageSeconds += [double]$stage.DurationSeconds}}
    $elapsed=$null
    if($compact.CreatedAt -and $compact.CompletedAt){try{$elapsed=([DateTime]::Parse($compact.CompletedAt).ToUniversalTime()-[DateTime]::Parse($compact.CreatedAt).ToUniversalTime()).TotalSeconds}catch{}}
    [pscustomobject]@{
        SchemaVersion=1;RunId=$compact.RunId;Status=$compact.Status;Mode=$compact.Mode;CreatedAt=$compact.CreatedAt;CompletedAt=$compact.CompletedAt
        DurationSeconds=$stageSeconds;ElapsedSeconds=$elapsed;InputHashes=@($compact.InputHashes);Stages=@($compact.Stages)
        OutputPaths=@($compact.OutputPaths);ReportPath=$compact.ReportPath;ErrorInformation=@($compact.Stages | Where-Object {$_.Error -or $_.Status -in @('failed','interrupted')} | ForEach-Object {[pscustomobject]@{Stage=$_.Name;Status=$_.Status;ExitCode=$_.ExitCode;Error=$_.Error;Details=$_.Details}})
    }
}

function Get-IosExistingRunId {
    param([string]$Path)
    $stream=$null;$reader=$null
    try {
        $stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true)
        $buffer=New-Object char[] 8192;$count=$reader.Read($buffer,0,$buffer.Length)
        $prefix=[string]::new($buffer,0,$count)
        $match=[regex]::Match($prefix,'"RunId"\s*:\s*"(?<id>[^"\\]+)"')
        if($match.Success){return $match.Groups['id'].Value}
        throw 'Existing run state has no readable RunId near the document header.'
    } finally {if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()}}
}

function Save-IosRunState {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$State,[Parameter(Mandatory=$true)][string]$Path)
    $parent=Split-Path -Parent $Path
    if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw 'State directory does not exist.'}
    if(Test-Path -LiteralPath $Path -PathType Leaf){
        $existingRunId=Get-IosExistingRunId -Path $Path
        if($existingRunId -ne $State.RunId){throw 'Refusing to replace a different run record.'}
    }
    $compact=Get-IosCompactRunState -State $State
    $json=ConvertTo-Json -InputObject $compact -Depth 15
    $bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $tmp=Join-Path $parent ([IO.Path]::GetFileName($Path)+'.'+[guid]::NewGuid().ToString('N')+'.tmp')
    $fs=$null
    try {
        $fs=New-Object IO.FileStream($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $fs.Write($bytes,0,$bytes.Length);$fs.Dispose();$fs=$null
        Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
    } finally {if($fs){$fs.Dispose()};if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}}
}

function Get-IosRunState {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][string]$RunId)
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw 'Run state does not exist.'}
    $state=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if($state.RunId -ne $RunId){throw 'Run ID does not match the state record.'}
    return $state
}

function Get-IosArtifactFileReference {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path,[string]$Kind='stage-result',[hashtable]$Metadata=@{},[switch]$IncludeHash)
    $full=[IO.Path]::GetFullPath($Path);$item=Get-Item -LiteralPath $full -ErrorAction Stop
    $hash=$null;if($IncludeHash){$hash=Get-IosStateFileHash -Path $full}
    [pscustomobject]@{Kind=$Kind;Path=$full;SizeBytes=[long]$item.Length;SHA256=$hash;Metadata=$Metadata}
}

Export-ModuleMember -Function Get-IosStateFileHash,Get-IosStageResultSummary,Get-IosCompactStageRecord,Get-IosCompactRunState,Get-IosRunSummary,Get-IosArtifactFileReference,Save-IosRunState,Get-IosRunState
