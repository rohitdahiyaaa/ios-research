Set-StrictMode -Version 2.0

$script:ComponentPriority=[ordered]@{
    'JavaScriptCore'=30;'WebKit'=29;'ImageIO'=28;'CoreGraphics'=27;'CoreMedia'=26;'VideoToolbox'=25;'IOKit'=24;'Kernel'=24
}

function Get-IosComponentPriority {
    param([string]$Component,[string]$Path)
    foreach($name in $script:ComponentPriority.Keys){if($Component -match [regex]::Escape($name) -or $Path -match [regex]::Escape($name)){return [int]$script:ComponentPriority[$name]}}
    return 5
}

function Get-IosSecurityTokens {
    param([string]$Name)
    $text=([string]$Name).ToLowerInvariant()
    $map=[ordered]@{
        Parser=@('parse','decode','deserialize','unmarshal','readheader','readbox','readchunk')
        Bounds=@('bounds','range','length','overflow','checked','limit','size')
        Memory=@('alloc','free','release','retain','copy','memcpy','memmove','buffer','pointer')
        InputValidation=@('valid','verify','sanitize','validate','check','guard')
        Media=@('image','jpeg','png','gif','webp','heif','video','h264','h265','codec','font','xml','json')
        Kernel=@('copyin','copyout','ioctl','vm_','map','mach','ipc','trap')
    }
    $hits=New-Object System.Collections.ArrayList
    foreach($key in $map.Keys){foreach($token in $map[$key]){if($text.Contains($token)){[void]$hits.Add($key);break}}}
    return ,@($hits)
}

function Get-IosSecurityCandidates {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$BinaryDiff,[string]$BaselineVersion,[string]$BaselineBuild,[string]$TargetVersion,[string]$TargetBuild,[hashtable]$ComponentMap=@{})
    $candidates=New-Object System.Collections.ArrayList
    $functionDiff=$BinaryDiff.FunctionComparison
    if($functionDiff -and @($functionDiff.ChangedFunctions).Count){
        foreach($function in $functionDiff.ChangedFunctions){
            $binary=@($BinaryDiff.ChangedBinaries|Where-Object {$_.BaselinePath -and $_.BaselinePath -match [regex]::Escape([string]$function.BinaryName)})|Select-Object -First 1
            $name=if($function.BinaryName){[string]$function.BinaryName}else{'unknown binary'}
            $component=if($ComponentMap.ContainsKey($name)){$ComponentMap[$name]}else{$name}
            $functionName=if($function.Name){[string]$function.Name}elseif($function.TargetName){[string]$function.TargetName}else{[string]$function.BaselineName}
            $tokens=Get-IosSecurityTokens -Name $functionName
            $score=20+(Get-IosComponentPriority -Component $component -Path $name)+([Math]::Min(18,$tokens.Count*6))
            if($function.Status -eq 'added'){$score+=8};if($function.Status -eq 'removed'){$score+=6};$targetBytesProperty=$function.PSObject.Properties['TargetBodyBytes'];$baselineBytesProperty=$function.PSObject.Properties['BaselineBodyBytes'];if($targetBytesProperty -and $baselineBytesProperty -and $null -ne $targetBytesProperty.Value -and $null -ne $baselineBytesProperty.Value -and [Math]::Abs([long]$targetBytesProperty.Value-[long]$baselineBytesProperty.Value) -gt 32){$score+=4}
            $score=[Math]::Min(100,[int]$score)
            $reason=if($tokens.Count){'Changed function name contains heuristic security-relevant terms: '+($tokens -join ', ')}else{'Function instruction-byte hash changed; no semantic vulnerability claim is made.'}
            [void]$candidates.Add([pscustomobject]@{Rank=0;Score=$score;Confidence='low';Component=$component;Binary=$name;FunctionName=$functionName;Address=$function.TargetAddress;BaselineVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetVersion=$TargetVersion;TargetBuild=$TargetBuild;ComparisonEvidence=$function;Reason=$reason;SuggestedManualStep='Review disassembly and decompiler output at the changed function, compare callers and input validation, then confirm whether behavior changed.';SourceArtifacts=@($function.BaselinePath,$function.TargetPath)|Where-Object {$_};VulnerabilityFinding=$false})
        }
    }
    if($functionDiff){
        foreach($function in @($functionDiff.AddedFunctions)){$name=if($function.BinaryName){[string]$function.BinaryName}else{'unknown binary'};$component=if($ComponentMap.ContainsKey($name)){$ComponentMap[$name]}else{$name};$tokens=Get-IosSecurityTokens -Name $function.Name;$score=[Math]::Min(75,22+(Get-IosComponentPriority -Component $component -Path $name)+($tokens.Count*6));[void]$candidates.Add([pscustomobject]@{Rank=0;Score=$score;Confidence='low';Component=$component;Binary=$name;FunctionName=$function.Name;Address=$function.TargetAddress;BaselineVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetVersion=$TargetVersion;TargetBuild=$TargetBuild;ComparisonEvidence=$function;Reason='Function is present only in the target inventory. This may reflect compiler or symbol differences; security impact is unknown.';SuggestedManualStep='Review the new function and its callers, inputs, data flow, and error paths in the target binary.';SourceArtifacts=@($function.TargetPath)|Where-Object {$_};VulnerabilityFinding=$false})}
        foreach($function in @($functionDiff.RemovedFunctions)){$name=if($function.BinaryName){[string]$function.BinaryName}else{'unknown binary'};$component=if($ComponentMap.ContainsKey($name)){$ComponentMap[$name]}else{$name};$tokens=Get-IosSecurityTokens -Name $function.Name;$score=[Math]::Min(75,20+(Get-IosComponentPriority -Component $component -Path $name)+($tokens.Count*6));[void]$candidates.Add([pscustomobject]@{Rank=0;Score=$score;Confidence='low';Component=$component;Binary=$name;FunctionName=$function.Name;Address=$function.BaselineAddress;BaselineVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetVersion=$TargetVersion;TargetBuild=$TargetBuild;ComparisonEvidence=$function;Reason='Function is absent from the target inventory. This may reflect inlining, renaming, or compiler changes; removal of a security check is not established.';SuggestedManualStep='Determine whether the function was inlined, renamed, removed, or replaced, then inspect target-side callers and equivalent checks.';SourceArtifacts=@($function.BaselinePath)|Where-Object {$_};VulnerabilityFinding=$false})}
    }
    foreach($binary in @($BinaryDiff.ChangedBinaries)){
        $name=[string]$binary.Name;$component=if($ComponentMap.ContainsKey($name)){$ComponentMap[$name]}else{Get-IosFrameworkFromName -Name $name -Path $binary.TargetPath}
        $priority=Get-IosComponentPriority -Component $component -Path $binary.TargetPath
        $score=[Math]::Min(60,15+$priority)
        [void]$candidates.Add([pscustomobject]@{Rank=0;Score=$score;Confidence='low';Component=$component;Binary=$name;FunctionName=$null;Address=$null;BaselineVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetVersion=$TargetVersion;TargetBuild=$TargetBuild;ComparisonEvidence=$binary;Reason='Binary SHA-256 differs. This may reflect relocation, signature, or metadata changes; code changes are not established.';SuggestedManualStep='Use Ghidra on both binaries and compare function bodies after accounting for architecture, UUID, rebasing, relocation, and signatures.';SourceArtifacts=@($binary.BaselinePath,$binary.TargetPath);VulnerabilityFinding=$false})
    }
    foreach($binary in @($BinaryDiff.AddedBinaries)){$name=[string]$binary.Name;$component=if($ComponentMap.ContainsKey($name)){$ComponentMap[$name]}else{Get-IosFrameworkFromName -Name $name -Path $binary.Path};$score=[Math]::Min(65,18+(Get-IosComponentPriority -Component $component -Path $binary.Path));[void]$candidates.Add([pscustomobject]@{Rank=0;Score=$score;Confidence='low';Component=$component;Binary=$name;FunctionName=$null;Address=$null;BaselineVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetVersion=$TargetVersion;TargetBuild=$TargetBuild;ComparisonEvidence=$binary;Reason='Binary appears only in the target inventory; this is an inventory difference, not a security finding.';SuggestedManualStep='Inspect the binary purpose, reachable inputs, and interfaces before prioritizing function-level analysis.';SourceArtifacts=@($binary.Path);VulnerabilityFinding=$false})}
    foreach($binary in @($BinaryDiff.RemovedBinaries)){$name=[string]$binary.Name;$component=if($ComponentMap.ContainsKey($name)){$ComponentMap[$name]}else{Get-IosFrameworkFromName -Name $name -Path $binary.Path};$score=[Math]::Min(65,16+(Get-IosComponentPriority -Component $component -Path $binary.Path));[void]$candidates.Add([pscustomobject]@{Rank=0;Score=$score;Confidence='low';Component=$component;Binary=$name;FunctionName=$null;Address=$null;BaselineVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetVersion=$TargetVersion;TargetBuild=$TargetBuild;ComparisonEvidence=$binary;Reason='Binary appears only in the baseline inventory; absence in target does not prove removal of a security check.';SuggestedManualStep='Check target equivalents, callers, and replacement components before drawing conclusions.';SourceArtifacts=@($binary.Path);VulnerabilityFinding=$false})}
    $ranked=@($candidates|Sort-Object -Property @{Expression='Score';Descending=$true},@{Expression='Component';Descending=$false},@{Expression='Binary';Descending=$false})
    for($i=0;$i -lt $ranked.Count;$i++){$ranked[$i].Rank=$i+1}
    [pscustomobject]@{SchemaVersion=1;GeneratedAt=[DateTime]::UtcNow.ToString('o');RankingMethod='Transparent component priorities plus name-token and change-size heuristics';Candidates=$ranked;CandidateCount=$ranked.Count;VulnerabilityFindings=0;Disclaimer='Candidates are triage suggestions. No candidate is labeled a vulnerability or exploitability finding.'}
}

function Get-IosFrameworkFromName {
    param([string]$Name,[string]$Path)
    $text=$Name+' '+$Path
    foreach($component in @('JavaScriptCore','WebKit','ImageIO','CoreGraphics','CoreMedia','VideoToolbox','IOKit','Kernel')){if($text -match [regex]::Escape($component)){return $component}}
    return 'Other'
}

Export-ModuleMember -Function Get-IosSecurityCandidates,Get-IosComponentPriority,Get-IosSecurityTokens,Get-IosFrameworkFromName
