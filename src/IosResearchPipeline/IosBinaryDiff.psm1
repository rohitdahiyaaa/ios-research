Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosResearchState.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosFirmwareExtraction.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosResearchConfig.psm1') -Force

function Get-IosBinaryMatchKey {
    param($Binary)
    $arch=[string]$Binary.Architecture
    if($Binary.UUID){return ('uuid|'+$arch+'|'+([string]$Binary.UUID).ToLowerInvariant())}
    return ('name|'+$arch+'|'+([string]$Binary.Name).ToLowerInvariant())
}

function Compare-IosBinaryInventories {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Baseline,[Parameter(Mandatory=$true)]$Target,$BaselineFunctions,$TargetFunctions)
    $left=@($Baseline.Binaries);$right=@($Target.Binaries);$unused=New-Object System.Collections.ArrayList
    foreach($x in $right){[void]$unused.Add($x)}
    $pairs=New-Object System.Collections.ArrayList;$removed=New-Object System.Collections.ArrayList
    foreach($old in $left){
        $candidates=@($unused|Where-Object { (Get-IosBinaryMatchKey $_) -eq (Get-IosBinaryMatchKey $old) })
        $matchMethod=if($old.UUID){'UUID+architecture'}else{'name+architecture'}
        if(-not $candidates.Count -and $old.UUID){$candidates=@($unused|Where-Object {$_.Architecture -eq $old.Architecture -and $_.Name -eq $old.Name});$matchMethod='name+architecture (UUID changed or unavailable)'}
        if($candidates.Count -gt 1 -and $old.UUID){$candidates=@($candidates|Where-Object {$_.UUID -eq $old.UUID});if(-not $candidates.Count){$candidates=@($unused|Where-Object {$_.Architecture -eq $old.Architecture -and $_.Name -eq $old.Name});$matchMethod='name+architecture (ambiguous UUID)'}}
        if($candidates.Count -eq 0){[void]$removed.Add([pscustomobject]@{Name=$old.Name;Architecture=$old.Architecture;UUID=$old.UUID;Path=$old.Path;SHA256=$old.SHA256});continue}
        $new=$candidates[0];[void]$unused.Remove($new)
        $equal=$old.SHA256 -eq $new.SHA256
        [void]$pairs.Add([pscustomobject]@{Name=$old.Name;Architecture=$old.Architecture;BaselineUUID=$old.UUID;TargetUUID=$new.UUID;BaselinePath=$old.Path;TargetPath=$new.Path;BaselineSHA256=$old.SHA256;TargetSHA256=$new.SHA256;MatchMethod=$matchMethod;IdentityEvidence=if($old.UUID -and $new.UUID -and $old.UUID -eq $new.UUID){'UUID and architecture match'}else{'name and architecture match'};Status=if($equal){'identical'}else{'changed'};Evidence='SHA-256 comparison';Interpretation=if($equal){'File bytes match.'}else{'File bytes differ. Rebase, relocation, signatures, or metadata may account for differences; this does not prove code changed.'}})
    }
    $added=New-Object System.Collections.ArrayList;foreach($new in $unused){[void]$added.Add([pscustomobject]@{Name=$new.Name;Architecture=$new.Architecture;UUID=$new.UUID;Path=$new.Path;SHA256=$new.SHA256})}
    $functionSummary=$null
    if($BaselineFunctions -and $TargetFunctions){$functionSummary=Compare-IosFunctionInventories -Baseline $BaselineFunctions -Target $TargetFunctions}
    [pscustomobject]@{SchemaVersion=1;GeneratedAt=[DateTime]::UtcNow.ToString('o');BaselineBuild=$Baseline.Build;TargetBuild=$Target.Build;IdenticalBinaries=@($pairs|Where-Object {$_.Status -eq 'identical'});ChangedBinaries=@($pairs|Where-Object {$_.Status -eq 'changed'});AddedBinaries=@($added);RemovedBinaries=@($removed);FunctionComparison=$functionSummary;Limitations=@('Changed file hashes are observations, not proof of code changes. Address rebasing, relocation, code signatures, and metadata may affect hashes.');Status='completed'}
}

function Compare-IosFunctionInventories {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Baseline,[Parameter(Mandatory=$true)]$Target)
    $old=@($Baseline.functions);$remaining=New-Object System.Collections.ArrayList;foreach($f in @($Target.functions)){[void]$remaining.Add($f)}
    $matches=New-Object System.Collections.ArrayList;$removed=New-Object System.Collections.ArrayList
    foreach($f in $old){
        $candidates=@($remaining|Where-Object {$_.name -eq $f.name})
        if($candidates.Count -gt 1 -and $f.bodySHA256){$exact=@($candidates|Where-Object {$_.bodySHA256 -eq $f.bodySHA256});if($exact.Count -eq 1){$candidates=$exact}}
        if($candidates.Count -eq 0){[void]$removed.Add([pscustomobject]@{Name=$f.name;BaselineAddress=$f.entryPoint;BaselineBodySHA256=$f.bodySHA256;BinaryName=$null;BaselinePath=$null;TargetPath=$null});continue}
        $new=$candidates[0];[void]$remaining.Remove($new);$same=$f.bodySHA256 -eq $new.bodySHA256
        [void]$matches.Add([pscustomobject]@{Name=$f.name;BaselineAddress=$f.entryPoint;TargetAddress=$new.entryPoint;BaselineBodySHA256=$f.bodySHA256;TargetBodySHA256=$new.bodySHA256;BaselineBodyBytes=$f.bodyBytes;TargetBodyBytes=$new.bodyBytes;BinaryName=$null;BaselinePath=$null;TargetPath=$null;Status=if($same){'identical'}else{'changed'};MatchMethod='Exact function name; body bytes hashed by Ghidra';Confidence=$null;Caveat='No BinDiff confidence is available from this name-and-hash comparison. Compiler transformations, function splitting/merging, and instruction decoding can change hashes without establishing security impact.'})
    }
    $added=New-Object System.Collections.ArrayList;foreach($f in $remaining){[void]$added.Add([pscustomobject]@{Name=$f.name;TargetAddress=$f.entryPoint;TargetBodySHA256=$f.bodySHA256;TargetBodyBytes=$f.bodyBytes;BinaryName=$null;BaselinePath=$null;TargetPath=$null})}
    [pscustomobject]@{MatchedFunctionCount=$matches.Count;ChangedFunctionCount=@($matches|Where-Object {$_.Status -eq 'changed'}).Count;IdenticalFunctionCount=@($matches|Where-Object {$_.Status -eq 'identical'}).Count;AddedFunctions=@($added);RemovedFunctions=@($removed);ChangedFunctions=@($matches|Where-Object {$_.Status -eq 'changed'});Matches=@($matches);MatchConfidence=$null;Method='Ghidra function name and instruction-byte SHA-256';BinDiffUsed=$false;Status='completed'}
}

function Read-IosBinDiffDatabase {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path,[string]$PythonCommand='python',[int]$TimeoutSeconds=120)
    $database=[IO.Path]::GetFullPath($Path)
    if(-not(Test-Path -LiteralPath $database -PathType Leaf)){throw "BinDiff result database does not exist: $database"}
    $stream=[IO.File]::OpenRead($database)
    try{$header=New-Object byte[] 16;$read=$stream.Read($header,0,16)}finally{$stream.Dispose()}
    if($read -ne 16 -or [Text.Encoding]::ASCII.GetString($header,0,15) -ne 'SQLite format 3' -or $header[15] -ne 0){throw 'BinDiff result is not a SQLite format 3 database.'}
    $python=Get-Command -Name $PythonCommand -ErrorAction SilentlyContinue|Select-Object -First 1
    if(-not $python){throw "Python is required to parse BinDiff SQLite results but was not found: $PythonCommand"}
    $projectRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $parser=Join-Path $projectRoot 'adapters\BinDiff\ParseBinDiff.py'
    if(-not(Test-Path -LiteralPath $parser -PathType Leaf)){throw "BinDiff SQLite parser was not found: $parser"}
    $result=Invoke-IosLocalProcess -Executable $python.Source -Arguments @($parser,$database) -TimeoutSeconds $TimeoutSeconds
    if($result.TimedOut){throw 'BinDiff result parsing timed out.'}
    if($result.ExitCode -ne 0){throw "BinDiff result parser failed: $($result.StdErr)"}
    try{return ($result.StdOut|ConvertFrom-Json -ErrorAction Stop)}catch{throw "BinDiff result parser returned invalid JSON: $($_.Exception.Message)"}
}

function Invoke-IosBinDiff {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$BaselineBinExport,[Parameter(Mandatory=$true)][string]$TargetBinExport,[Parameter(Mandatory=$true)][string]$OutputDirectory,[string]$BinDiffCommand='bindiff',[string]$PythonCommand='python',[switch]$AllowFirmwareAccess,[switch]$AuthorizedResearch,[int]$TimeoutSeconds=3600)
    $null=Assert-IosResearchAuthorization -Config $Config -AuthorizedResearch:$AuthorizedResearch -AllowFirmwareAccess:$AllowFirmwareAccess
    foreach($path in @($BaselineBinExport,$TargetBinExport)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "BinExport input does not exist: $path"};if([IO.Path]::GetExtension($path) -notmatch '(?i)binexport'){throw "BinDiff inputs must be BinExport artifacts: $path"}}
    $out=[IO.Path]::GetFullPath($OutputDirectory);if(Test-Path -LiteralPath $out){throw 'BinDiff output directory already exists; refusing to overwrite.'}
    $command=Get-Command $BinDiffCommand -ErrorAction Stop|Select-Object -First 1
    $help=Invoke-IosLocalProcess -Executable $command.Source -Arguments @('--help') -TimeoutSeconds 30
    $helpText=$help.StdOut+"`n"+$help.StdErr
    if($help.TimedOut -or $helpText -notmatch '--primary' -or $helpText -notmatch '--secondary' -or $helpText -notmatch '--output_dir'){throw 'Installed BinDiff CLI does not advertise the required primary, secondary, and output_dir interface.'}
    $version=@(& $command.Source --logo 2>&1);$versionText=@($version|ForEach-Object {[string]$_}|Where-Object {$_ -match '^BinDiff\s'}|Select-Object -First 1)
    if(-not $versionText){throw 'BinDiff version could not be verified.'}
    $parent=Split-Path -Parent $out;if(-not(Test-Path $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null};New-Item -ItemType Directory -Path $out|Out-Null
    $args=@(('--primary='+[IO.Path]::GetFullPath($BaselineBinExport)),('--secondary='+[IO.Path]::GetFullPath($TargetBinExport)),('--output_dir='+$out),'--output_format=bin,log')
    $result=Invoke-IosLocalProcess -Executable $command.Source -Arguments $args -TimeoutSeconds $TimeoutSeconds
    $raw=@(Get-ChildItem -LiteralPath $out -File -Recurse|ForEach-Object {[pscustomobject]@{Path=$_.FullName;SizeBytes=$_.Length;SHA256=(Get-IosStateFileHash -Path $_.FullName)}})
    $database=@($raw|Where-Object {[IO.Path]::GetExtension($_.Path) -ieq '.BinDiff'}|Select-Object -First 1)
    $parsed=$null;$parseError=$null
    if($result.ExitCode -eq 0 -and $database){try{$parsed=Read-IosBinDiffDatabase -Path $database[0].Path -PythonCommand $PythonCommand -TimeoutSeconds ([Math]::Min($TimeoutSeconds,120))}catch{$parseError=$_.Exception.Message}}
    $status=if($result.TimedOut){'interrupted'}elseif($result.ExitCode -ne 0 -or -not $database -or $parseError){'failed'}else{'completed'}
    [pscustomobject]@{Status=$status;ToolVersion=$versionText[0];BaselineBinExport=$BaselineBinExport;TargetBinExport=$TargetBinExport;OutputDirectory=$out;RawOutputs=$raw;ResultDatabase=if($database){$database[0].Path}else{$null};ParsedResult=$parsed;FunctionMatchesParsed=($null -ne $parsed);FunctionMatches=if($parsed){$parsed.Matches}else{@()};ChangedFunctions=if($parsed){$parsed.ChangedFunctions}else{@()};AddedFunctions=if($parsed){$parsed.AddedFunctions}else{@()};RemovedFunctions=if($parsed){$parsed.RemovedFunctions}else{@()};ChangedFunctionCount=if($parsed){$parsed.ChangedFunctionCount}else{$null};MatchConfidenceSource=if($parsed){$parsed.ConfidenceSource}else{$null};ParseError=$parseError;StdOut=$result.StdOut;StdErr=$result.StdErr;ExitCode=$result.ExitCode;NetworkAccess=$false;Limitations=@('Function confidence and similarity are copied from BinDiff result database fields; they are not recalculated. Similarity below 1.0 is classified as changed-by-similarity, not as a vulnerability.')}
}

function Assert-IosBinDiffCompleted {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Result)
    if($Result.Status -ne 'completed' -or $Result.FunctionMatchesParsed -ne $true -or -not $Result.ParsedResult -or $Result.ParsedResult.Status -ne 'completed'){
        throw "BinDiff returned status '$($Result.Status)' (exit $($Result.ExitCode)). Raw output retained at $($Result.OutputDirectory). Function matches were not parsed."
    }
    return $Result
}

Export-ModuleMember -Function Compare-IosBinaryInventories,Compare-IosFunctionInventories,Read-IosBinDiffDatabase,Invoke-IosBinDiff,Assert-IosBinDiffCompleted
