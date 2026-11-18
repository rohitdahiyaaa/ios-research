Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosResearchConfig.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosResearchState.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosFirmwareExtraction.psm1') -Force

function Get-IosIpswDyldCapabilities {
    [CmdletBinding()]
    param([string]$IpswCommand='ipsw')
    $command=Get-Command -Name $IpswCommand -ErrorAction SilentlyContinue|Select-Object -First 1
    if(-not $command){throw "ipsw command was not found: $IpswCommand"}
    $version=@(& $command.Source version 2>&1);if($LASTEXITCODE -ne 0){throw 'Unable to execute ipsw version probe.'}
    $infoHelp=@(& $command.Source dyld info --help 2>&1);$infoText=@($infoHelp|ForEach-Object {[string]$_})-join "`n"
    if($LASTEXITCODE -ne 0 -or $infoText -notmatch 'Usage:\s*ipsw dyld info'){throw 'Unable to verify ipsw dyld info interface from its actual help output.'}
    $help=@(& $command.Source dyld extract --help 2>&1);$text=@($help|ForEach-Object {[string]$_})-join "`n"
    if($LASTEXITCODE -ne 0 -or $text -notmatch 'Usage:\s*ipsw dyld extract'){throw 'Unable to verify ipsw dyld extract interface from its actual help output.'}
    $flags=@{InfoDylibs=$infoText.Contains('--dylibs');InfoJson=$infoText.Contains('--json');Output=$text.Contains('--output');All=$text.Contains('--all');Force=$text.Contains('--force')}
    if(-not $flags.InfoDylibs -or -not $flags.InfoJson){throw 'Installed ipsw dyld info help does not advertise required --dylibs and --json options.'}
    if(-not $flags.Output){throw 'Installed ipsw dyld extract command does not advertise --output.'}
    [pscustomobject]@{Executable=$command.Source;Version=(@($version|ForEach-Object {[string]$_})-join ' ').Trim();HelpText=$text;SupportedFlags=$flags}
}

function Find-IosDyldSharedCaches {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string[]]$Roots)
    $found=New-Object System.Collections.ArrayList
    foreach($root in $Roots){
        if(-not(Test-Path -LiteralPath $root)){continue}
        $items=Get-Item -LiteralPath $root -ErrorAction Stop
        $files=if($items.PSIsContainer){Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^dyld_shared_cache(?:_(?:arm64e|arm64|armv7|x86_64|i386))?$' -or $_.Extension -eq '.dyldcache'}}else{@($items)}
        foreach($file in $files){
            $arch=$null
            if($file.Name -match '(arm64e|arm64|armv7|x86_64|i386)'){$arch=$matches[1]}
            [void]$found.Add([pscustomobject]@{Path=$file.FullName;FileName=$file.Name;Architecture=$arch;SizeBytes=[long]$file.Length})
        }
    }
    return ,@($found | Sort-Object Path -Unique)
}

function Get-IosIpswDyldInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$CachePath,[string]$IpswCommand='ipsw')
    $command=Get-Command $IpswCommand -ErrorAction SilentlyContinue | Select-Object -First 1
    if(-not $command){throw "ipsw command was not found: $IpswCommand"}
    $out=@(& $command.Source dyld info --dylibs --json $CachePath 2>&1)
    if($LASTEXITCODE -ne 0){throw "ipsw dyld info failed for ${CachePath}: $(@($out | ForEach-Object {[string]$_}) -join ' ')"}
    $text=@($out | ForEach-Object {[string]$_}) -join "`n"
    try{$json=$text | ConvertFrom-Json -ErrorAction Stop}catch{throw "ipsw dyld info returned invalid JSON for ${CachePath}: $($_.Exception.Message)"}
    return $json
}

function Get-IosDylibRecords {
    param($Json)
    $records=New-Object System.Collections.ArrayList
    $queue=New-Object System.Collections.Queue;$queue.Enqueue($Json)
    while($queue.Count){
        $item=$queue.Dequeue()
        if($item -is [System.Array]){foreach($child in $item){$queue.Enqueue($child)};continue}
        if($item -is [System.Management.Automation.PSCustomObject]){
            $props=@{};foreach($prop in $item.PSObject.Properties){$props[$prop.Name]=$prop.Value;if($prop.Value -is [System.Array] -or $prop.Value -is [System.Management.Automation.PSCustomObject]){$queue.Enqueue($prop.Value)}}
            $path=$null;foreach($key in @('path','Path','installName','InstallName','dylib','Dylib','name','Name')){if($props[$key] -is [string] -and $props[$key].StartsWith('/')){$path=$props[$key];break}}
            if($path){[void]$records.Add([pscustomobject]@{InstallName=$path;Name=[IO.Path]::GetFileName($path);Version=if($props.ContainsKey('version')){[string]$props.version}else{$null};Raw=$item})}
        }
    }
    return ,@($records | Sort-Object InstallName -Unique)
}

function Select-IosDylibImages {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][object[]]$Caches,[string[]]$Architecture=@(),[string[]]$Components=@())
    $selected=New-Object System.Collections.ArrayList
    foreach($cache in $Caches){
        if($Architecture.Count -and $cache.Architecture -notin $Architecture){continue}
        foreach($image in @($cache.Images)){
            $component=$null
            foreach($candidate in $Components){if($candidate -and $image.InstallName.IndexOf([string]$candidate,[StringComparison]::OrdinalIgnoreCase) -ge 0){$component=[string]$candidate;break}}
            if($Components.Count -and -not $component){continue}
            [void]$selected.Add([pscustomobject]@{CachePath=$cache.CachePath;Architecture=$cache.Architecture;InstallName=$image.InstallName;Name=$image.Name;Component=$component;Image=$image})
        }
    }
    return ,@($selected)
}

function Get-IosSharedCacheInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string[]]$Roots,[string]$IpswCommand='ipsw',[string]$Role='target',[string[]]$Architecture=@(),[string[]]$Components=@(),[string]$ExtractionRoot,[int]$MaxDylibExtractions=0,[int]$TimeoutSeconds=3600,[switch]$AllowFirmwareAccess,[switch]$AllowExtraction,[switch]$AuthorizedResearch)
    $null=Assert-IosResearchAuthorization -Config $Config -AuthorizedResearch:$AuthorizedResearch -AllowFirmwareAccess:$AllowFirmwareAccess
    if($AllowExtraction){$null=Assert-IosResearchAuthorization -Config $Config -AuthorizedResearch:$AuthorizedResearch -AllowFirmwareAccess:$AllowFirmwareAccess -AllowExtraction;if($MaxDylibExtractions -lt 1){throw 'MaxDylibExtractions must be positive when shared-cache image extraction is enabled.'};if(-not $ExtractionRoot){throw 'ExtractionRoot is required when shared-cache image extraction is enabled.'}}
    $null=Get-IosIpswDyldCapabilities -IpswCommand $IpswCommand
    $allCaches=Find-IosDyldSharedCaches -Roots $Roots
    $unknownArchitectures=@($allCaches|Where-Object {-not $_.Architecture})
    $caches=@($allCaches|Where-Object {-not $Architecture.Count -or $_.Architecture -in $Architecture})
    if(-not $caches.Count){throw 'No dyld shared caches were found in the supplied extracted-firmware roots.'}
    $results=New-Object System.Collections.ArrayList
    foreach($cache in $caches){
        $hash=Get-IosStateFileHash -Path $cache.Path
        $metadata=Get-IosIpswDyldInfo -CachePath $cache.Path -IpswCommand $IpswCommand
        $images=Get-IosDylibRecords -Json $metadata
        [void]$results.Add([pscustomobject]@{CachePath=$cache.Path;Role=$Role;FileName=$cache.FileName;Architecture=$cache.Architecture;SizeBytes=$cache.SizeBytes;SHA256=$hash;ImageCount=$images.Count;Images=$images;ImageExtractions=@();Status='completed';Tool='ipsw dyld info --dylibs --json'})
    }
    $selectedImages=Select-IosDylibImages -Caches @($results) -Architecture $Architecture -Components $Components
    if($AllowExtraction -and $selectedImages.Count -gt $MaxDylibExtractions){throw "Selected $($selectedImages.Count) dylib images, above resource limit $MaxDylibExtractions. Narrow architecture/components or explicitly raise resourceLimits.maxDylibExtractions."}
    $imageExtractions=New-Object System.Collections.ArrayList
    if($AllowExtraction){
        $safeRoot=[IO.Path]::GetFullPath($ExtractionRoot);if(-not(Test-Path -LiteralPath $safeRoot -PathType Container)){New-Item -ItemType Directory -Path $safeRoot -Force|Out-Null}
        foreach($selection in $selectedImages){
            $cacheHash=Get-IosStateFileHash -Path $selection.CachePath
            $nameHash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($selection.InstallName))).Replace('-','').ToLowerInvariant().Substring(0,16)
            $dest=Join-Path $safeRoot (Join-Path $selection.Architecture (Join-Path $cacheHash.Substring(0,16) $nameHash))
            $destParent=Split-Path -Parent $dest;if(-not(Test-Path -LiteralPath $destParent -PathType Container)){New-Item -ItemType Directory -Path $destParent -Force|Out-Null}
            $resume=$false;if((Test-Path -LiteralPath $dest -PathType Container) -and (Test-Path -LiteralPath (Join-Path $dest 'dyld-extraction.json') -PathType Leaf)){$resume=$true}
            $state=Invoke-IosDylibExtraction -Config $Config -CachePath $selection.CachePath -InstallName $selection.InstallName -OutputDirectory $dest -IpswCommand $IpswCommand -AllowFirmwareAccess -AllowExtraction -AuthorizedResearch -Resume:$resume -TimeoutSeconds $TimeoutSeconds
            $entry=[pscustomobject]@{Role=$Role;Architecture=$selection.Architecture;Component=$selection.Component;CachePath=$selection.CachePath;InstallName=$selection.InstallName;Extraction=$state;OutputFiles=@($state.OutputFiles)}
            [void]$imageExtractions.Add($entry)
            $cacheRecord=@($results|Where-Object {$_.CachePath -eq $selection.CachePath})|Select-Object -First 1
            $cacheRecord.ImageExtractions=@($cacheRecord.ImageExtractions)+$entry
        }
    }
    [pscustomobject]@{SchemaVersion=1;GeneratedAt=[DateTime]::UtcNow.ToString('o');Role=$Role;SelectedArchitectures=@($Architecture);SelectedComponents=@($Components);Caches=@($results);ImageExtractions=@($imageExtractions);SkippedCaches=@($unknownArchitectures|ForEach-Object {[pscustomobject]@{Path=$_.Path;Reason='Architecture could not be identified from the cache filename.'}});Status='completed';NetworkAccess=$false}
}

function New-IosIpswDylibExtractArguments {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$CachePath,[Parameter(Mandatory=$true)][string]$InstallName,[Parameter(Mandatory=$true)][string]$OutputDirectory)
    if(-not $InstallName.StartsWith('/')){throw 'Dyld image install name must be an absolute cache path.'}
    return @('dyld','extract',[IO.Path]::GetFullPath($CachePath),$InstallName,'--output',[IO.Path]::GetFullPath($OutputDirectory))
}

function Invoke-IosDylibExtraction {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$CachePath,[Parameter(Mandatory=$true)][string]$InstallName,[Parameter(Mandatory=$true)][string]$OutputDirectory,[string]$IpswCommand='ipsw',[switch]$AllowFirmwareAccess,[switch]$AllowExtraction,[switch]$AuthorizedResearch,[switch]$Resume,[int]$TimeoutSeconds=1800)
    $null=Assert-IosResearchAuthorization -Config $Config -AuthorizedResearch:$AuthorizedResearch -AllowFirmwareAccess:$AllowFirmwareAccess -AllowExtraction:$AllowExtraction
    if(-not $AllowExtraction){throw 'Shared-cache image extraction requires -AllowExtraction.'}
    if(-not(Test-Path -LiteralPath $CachePath -PathType Leaf)){throw "Shared cache does not exist: $CachePath"}
    if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 86400){throw 'TimeoutSeconds must be between 1 and 86400.'}
    $caps=Get-IosIpswDyldCapabilities -IpswCommand $IpswCommand
    $cache=[IO.Path]::GetFullPath($CachePath);$cacheHash=Get-IosStateFileHash -Path $cache;$root=[IO.Path]::GetFullPath($OutputDirectory);$statePath=Join-Path $root 'dyld-extraction.json';$state=$null
    if(Test-Path -LiteralPath $root -PathType Container){
        if(-not $Resume -or -not(Test-Path -LiteralPath $statePath -PathType Leaf)){throw 'Output directory already exists; pass -Resume for a matching recorded operation or choose a new path.'}
        $state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
        if($state.CachePath -ne $cache -or $state.CacheSHA256 -ne $cacheHash -or $state.InstallName -ne $InstallName -or $state.IpswVersion -ne $caps.Version){throw 'Cannot resume shared-cache extraction because its input or ipsw version changed.'}
        if($state.Status -eq 'completed'){foreach($file in @($state.OutputFiles)){if(-not(Test-Path -LiteralPath $file.Path -PathType Leaf) -or (Get-IosStateFileHash -Path $file.Path) -ne $file.SHA256){throw 'Completed dyld output failed integrity verification.'}};return $state}
    }else{
        $parent=Split-Path -Parent $root;if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw "Output parent does not exist: $parent"};New-Item -ItemType Directory -Path $root|Out-Null
        $state=[pscustomobject]@{SchemaVersion=1;RunId=[guid]::NewGuid().ToString('N');CachePath=$cache;CacheSHA256=$cacheHash;InstallName=$InstallName;IpswVersion=$caps.Version;Status='pending';Attempts=@();OutputFiles=@();Diagnostics=$null;CompletedAt=$null;ExitCode=$null;NetworkAccess=$false}
        Save-IosRunState -State $state -Path $statePath
    }
    $attempt=[guid]::NewGuid().ToString('N');$attemptDir=Join-Path $root ('attempt-'+$attempt);New-Item -ItemType Directory -Path $attemptDir|Out-Null
    $attemptRecord=[pscustomobject]@{Id=$attempt;OutputDirectory=$attemptDir;StartedAt=[DateTime]::UtcNow.ToString('o');CompletedAt=$null;Status='running';ExitCode=$null;TimedOut=$false}
    $state.Attempts=@($state.Attempts)+$attemptRecord;$state.Status='running';Save-IosRunState -State $state -Path $statePath
    $args=New-IosIpswDylibExtractArguments -CachePath $cache -InstallName $InstallName -OutputDirectory $attemptDir
    try{$processResult=Invoke-IosLocalProcess -Executable $caps.Executable -Arguments $args -TimeoutSeconds $TimeoutSeconds}
    catch{$processResult=[pscustomobject]@{ExitCode=1;TimedOut=$false;StdOut='';StdErr=$_.Exception.Message}}
    $attemptRecord.CompletedAt=[DateTime]::UtcNow.ToString('o');$attemptRecord.ExitCode=$processResult.ExitCode;$attemptRecord.TimedOut=$processResult.TimedOut
    $files=@(Get-ChildItem -LiteralPath $attemptDir -Recurse -File -ErrorAction SilentlyContinue|ForEach-Object {[pscustomobject]@{Path=$_.FullName;SizeBytes=$_.Length;SHA256=(Get-IosStateFileHash -Path $_.FullName)}})
    $state.OutputFiles=$files;$state.CompletedAt=$attemptRecord.CompletedAt;$state.ExitCode=$processResult.ExitCode;$state.Diagnostics=[pscustomobject]@{StdOut=$processResult.StdOut;StdErr=$processResult.StdErr};$state.Status=if($processResult.ExitCode -eq 0 -and $files.Count){'completed'}elseif($processResult.TimedOut){'interrupted'}else{'failed'};$attemptRecord.Status=$state.Status
    Save-IosRunState -State $state -Path $statePath
    if($state.Status -ne 'completed'){throw "ipsw dyld extract $($state.Status); partial output retained under $attemptDir"}
    return $state
}

Export-ModuleMember -Function Find-IosDyldSharedCaches,Get-IosSharedCacheInventory,Get-IosDylibRecords,Select-IosDylibImages,Get-IosIpswDyldCapabilities,New-IosIpswDylibExtractArguments,Invoke-IosDylibExtraction
