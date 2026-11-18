Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosResearchConfig.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosResearchState.psm1') -Force

function Get-IosIpswCapabilities {
    [CmdletBinding()]
    param([string]$IpswCommand='ipsw')
    $command=Get-Command -Name $IpswCommand -ErrorAction SilentlyContinue | Select-Object -First 1
    if(-not $command){throw "ipsw command was not found: $IpswCommand"}
    $version=@(& $command.Source version 2>&1)
    if($LASTEXITCODE -ne 0){throw 'Unable to execute ipsw version probe.'}
    $help=@(& $command.Source extract --help 2>&1)
    $helpText=@($help | ForEach-Object {[string]$_}) -join "`n"
    if($LASTEXITCODE -ne 0 -or $helpText -notmatch 'Usage:\s*ipsw extract') {throw 'Unable to verify the installed ipsw extract interface from its help output.'}
    $supported=@{}
    foreach($flag in @('--dyld','--dyld-arch','--kernel','--dtree','--sys-ver','--output','--json','--json-format','--device','--remote')){$supported[$flag]=$helpText.Contains($flag)}
    if(-not $supported['--dyld'] -or -not $supported['--output']){throw 'Installed ipsw extract help does not advertise the required local dyld and output options.'}
    [pscustomobject]@{Executable=$command.Source;Version=(@($version | ForEach-Object {[string]$_}) -join ' ').Trim();HelpText=$helpText;SupportedFlags=$supported;RemoteSupported=[bool]$supported['--remote']}
}

function New-IosIpswExtractArguments {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$InputPath,[Parameter(Mandatory=$true)][string]$OutputDirectory,[string[]]$Components=@('dyld'),[string]$Device,[string[]]$Architecture=@())
    $map=@{dyld='--dyld';kernel='--kernel';dtree='--dtree';'system-version'='--sys-ver'}
    if(-not $Components -or $Components.Count -eq 0){throw 'At least one extraction component must be selected.'}
    $args=New-Object System.Collections.ArrayList
    [void]$args.Add('extract')
    foreach($component in $Components){if(-not $map.ContainsKey($component)){throw "Unsupported IPSW extraction component: $component"};[void]$args.Add($map[$component])}
    [void]$args.Add('--json'); [void]$args.Add('--json-format'); [void]$args.Add('artifacts'); [void]$args.Add('--output'); [void]$args.Add([IO.Path]::GetFullPath($OutputDirectory))
    if($Device){[void]$args.Add('--device');[void]$args.Add($Device)}
    foreach($arch in $Architecture){[void]$args.Add('--dyld-arch');[void]$args.Add($arch)}
    [void]$args.Add([IO.Path]::GetFullPath($InputPath))
    return ,@($args.ToArray())
}

function ConvertTo-IosWindowsArgument {
    param([Parameter(Mandatory=$true)][string]$Value)
    if($Value -notmatch '[\s"]'){return $Value}
    return '"' + ($Value -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1') + '"'
}

function ConvertTo-IosWslPath {
    param([Parameter(Mandatory=$true)][string]$Value)
    if($Value -match '^([A-Za-z]):[\\/]'){
        if($matches[1] -ine 'C'){throw "WSL IPSW extraction is restricted to C: paths: $Value"}
        return '/mnt/c/' + $Value.Substring(3).Replace('\','/')
    }
    return $Value
}

function Invoke-IosLocalProcess {
    param([Parameter(Mandatory=$true)][string]$Executable,[Parameter(Mandatory=$true)][string[]]$Arguments,[int]$TimeoutSeconds=3600)
    $start=New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName=$Executable; $start.Arguments=(@($Arguments | ForEach-Object {ConvertTo-IosWindowsArgument -Value ([string]$_)}) -join ' ')
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $process=New-Object System.Diagnostics.Process; $process.StartInfo=$start
    try {
        if(-not $process.Start()){throw 'Process did not start.'}
        $stdoutTask=$process.StandardOutput.ReadToEndAsync(); $stderrTask=$process.StandardError.ReadToEndAsync()
        $finished=$process.WaitForExit($TimeoutSeconds*1000)
        if(-not $finished){$process.Kill();$process.WaitForExit();return [pscustomobject]@{ExitCode=124;TimedOut=$true;StdOut=$stdoutTask.Result;StdErr=$stderrTask.Result}}
        $process.WaitForExit()
        return [pscustomobject]@{ExitCode=$process.ExitCode;TimedOut=$false;StdOut=$stdoutTask.Result;StdErr=$stderrTask.Result}
    } finally { $process.Dispose() }
}

function Invoke-IosWslIpswProcess {
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string[]]$Arguments,[Parameter(Mandatory=$true)][string]$ExpectedVersion,[int]$TimeoutSeconds=3600)
    $adapter=$Config.adapters.wsl
    if(-not $adapter.enabled){throw 'Windows dyld extraction requires adapters.wsl.enabled=true.'}
    $distro=if($adapter.distro){[string]$adapter.distro}else{'Ubuntu'}
    $userProperty=$adapter.PSObject.Properties['user']
    $wslName=if($adapter.command){[string]$adapter.command}else{'wsl.exe'}
    $wsl=Get-Command -Name $wslName -ErrorAction Stop | Select-Object -First 1
    $linuxIpsw=[string]$Config.toolPaths.ipswWsl
    if([string]::IsNullOrWhiteSpace($linuxIpsw) -or $linuxIpsw -notmatch '^/') {throw 'toolPaths.ipswWsl must be an absolute Linux executable path when WSL extraction is enabled.'}
    $wslPrefix=@('-d',$distro)
    if($userProperty -and $userProperty.Value){$wslPrefix+=@('-u',[string]$userProperty.Value)}
    $versionResult=$null;$versionText='';$versionLine=@()
    for($probe=1;$probe -le 3;$probe++){
        $versionResult=Invoke-IosLocalProcess -Executable $wsl.Source -Arguments (@($wslPrefix)+@('--',$linuxIpsw,'version')) -TimeoutSeconds 30
        $versionText=(@($versionResult.StdOut,$versionResult.StdErr)|Where-Object {$_}) -join "`n"
        $versionLine=@($versionText -split "`r?`n" | ForEach-Object {$_.Trim()} | Where-Object {$_ -match '^Version:'} | Select-Object -First 1)
        if($versionLine.Count){break}
        Start-Sleep -Seconds 2
    }
    if($versionResult.TimedOut -or $versionResult.ExitCode -ne 0 -or -not $versionLine.Count -or $versionLine[0] -ne $ExpectedVersion.Trim()){throw "WSL ipsw version does not match the verified Windows ipsw version. Expected '$ExpectedVersion'; got '$versionText'."}
    $wslArgs=New-Object System.Collections.ArrayList
    foreach($value in @($wslPrefix)+@('--','env','TMPDIR=/var/tmp',$linuxIpsw)+@($Arguments)){[void]$wslArgs.Add((ConvertTo-IosWslPath -Value ([string]$value)))}
    return Invoke-IosLocalProcess -Executable $wsl.Source -Arguments @($wslArgs.ToArray()) -TimeoutSeconds $TimeoutSeconds
}

function Invoke-IosFirmwareExtraction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$Config,
        [Parameter(Mandatory=$true)][string]$InputPath,
        [Parameter(Mandatory=$true)][string]$OutputDirectory,
        [string[]]$Components=@('dyld'),[string]$Device,[string[]]$Architecture=@(),[string]$IpswCommand='ipsw',
        [switch]$AllowFirmwareAccess,[switch]$AllowExtraction,[switch]$AuthorizedResearch,[switch]$Resume,[int]$TimeoutSeconds=3600
    )
    $null=Assert-IosResearchAuthorization -Config $Config -AuthorizedResearch:$AuthorizedResearch -AllowFirmwareAccess:$AllowFirmwareAccess -AllowExtraction:$AllowExtraction
    if(-not $AllowExtraction){throw 'Extraction blocked: explicit -AllowExtraction is required.'}
    $input=[IO.Path]::GetFullPath($InputPath)
    if(-not(Test-Path -LiteralPath $input -PathType Leaf)){throw "Local firmware input does not exist: $input"}
    if([IO.Path]::GetExtension($input).ToLowerInvariant() -notin @('.ipsw','.ota')){throw 'Extraction input must be a local .ipsw or .ota file.'}
    if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 86400){throw 'TimeoutSeconds must be between 1 and 86400.'}
    $caps=Get-IosIpswCapabilities -IpswCommand $IpswCommand
    foreach($component in $Components){$flag=@{dyld='--dyld';kernel='--kernel';dtree='--dtree';'system-version'='--sys-ver'}[$component];if(-not $flag -or -not $caps.SupportedFlags[$flag]){throw "Installed ipsw does not support extraction component '$component'."}}
    $root=[IO.Path]::GetFullPath($OutputDirectory)
    $parent=Split-Path -Parent $root
    if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw "Extraction parent directory does not exist: $parent"}
    $hash=(Get-FileHash -LiteralPath $input -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $statePath=Join-Path $root 'extraction.json'
    $state=$null
    if(Test-Path -LiteralPath $root -PathType Container){
        if(-not $Resume -or -not(Test-Path -LiteralPath $statePath -PathType Leaf)){throw 'Extraction output already exists; use a matching interrupted extraction with -Resume or choose a new output directory.'}
        $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if(-not $state.PSObject.Properties['ReportParseWarning']){$state|Add-Member -NotePropertyName ReportParseWarning -NotePropertyValue $null}
        $savedComponents=ConvertTo-Json -InputObject @($state.Components) -Compress -Depth 4
        $requestedComponents=ConvertTo-Json -InputObject @($Components) -Compress -Depth 4
        $savedArchitecture=ConvertTo-Json -InputObject @($state.Architecture) -Compress -Depth 4
        $requestedArchitecture=ConvertTo-Json -InputObject @($Architecture) -Compress -Depth 4
        $versionChanged=$state.IpswVersion -ne $caps.Version
        if($state.InputSHA256 -ne $hash -or $state.InputPath -ne $input -or $savedComponents -ne $requestedComponents -or $state.Device -ne $Device -or $savedArchitecture -ne $requestedArchitecture){throw 'Cannot resume: input, requested device/components, or architecture differs from the saved extraction.'}
        if($versionChanged){
            $hasSavedFiles=@($state.OutputFiles).Count -gt 0
            foreach($oldAttempt in @($state.Attempts)){
                if($oldAttempt.OutputDirectory -and (Test-Path -LiteralPath $oldAttempt.OutputDirectory -PathType Container) -and @(Get-ChildItem -LiteralPath $oldAttempt.OutputDirectory -File -Recurse -ErrorAction SilentlyContinue).Count -gt 0){$hasSavedFiles=$true}
            }
            if($state.Status -eq 'completed' -or $hasSavedFiles){throw 'Cannot resume with a changed ipsw version because completed or partial extraction output exists.'}
            $state.IpswVersion=$caps.Version
        }
        if($state.Status -eq 'completed'){
            foreach($file in @($state.OutputFiles)){if(-not(Test-Path -LiteralPath $file.Path -PathType Leaf) -or (Get-IosStateFileHash -Path $file.Path) -ne $file.SHA256){throw 'Completed extraction output failed integrity verification; refusing to overwrite.'}}
            return $state
        }
    } else {
        New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
        $state=[pscustomobject]@{SchemaVersion=1;RunId=[guid]::NewGuid().ToString('N');InputPath=$input;InputSHA256=$hash;IpswVersion=$caps.Version;Components=@($Components);Device=$Device;Architecture=@($Architecture);Status='pending';StartedAt=$null;CompletedAt=$null;ExitCode=$null;Attempts=@();OutputFiles=@();Diagnostics=$null;IpswReport=$null;ReportParseWarning=$null;NetworkAccess=$false}
        Save-IosRunState -State $state -Path $statePath
    }
    $attempt=[guid]::NewGuid().ToString('N'); $attemptDir=Join-Path $root ('attempt-'+$attempt)
    New-Item -ItemType Directory -Path $attemptDir -ErrorAction Stop | Out-Null
    $state.Status='running';$state.StartedAt=[DateTime]::UtcNow.ToString('o');$state.CompletedAt=$null
    $attemptRecord=[pscustomobject]@{Id=$attempt;OutputDirectory=$attemptDir;StartedAt=$state.StartedAt;CompletedAt=$null;Status='running';ExitCode=$null;TimedOut=$false}
    $state.Attempts=@($state.Attempts)+$attemptRecord
    Save-IosRunState -State $state -Path $statePath
    $args=New-IosIpswExtractArguments -InputPath $input -OutputDirectory $attemptDir -Components $Components -Device $Device -Architecture $Architecture
    $result=$null
    try{
        if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and $Components -contains 'dyld' -and $Config.adapters.wsl.enabled){
            $result=Invoke-IosWslIpswProcess -Config $Config -Arguments $args -ExpectedVersion $caps.Version -TimeoutSeconds $TimeoutSeconds
        }else{$result=Invoke-IosLocalProcess -Executable $caps.Executable -Arguments $args -TimeoutSeconds $TimeoutSeconds}
    }
    catch{$result=[pscustomobject]@{ExitCode=1;TimedOut=$false;StdOut='';StdErr=$_.Exception.Message}}
    $attemptRecord.CompletedAt=[DateTime]::UtcNow.ToString('o');$attemptRecord.ExitCode=$result.ExitCode;$attemptRecord.TimedOut=$result.TimedOut
    $state.CompletedAt=$attemptRecord.CompletedAt;$state.ExitCode=$result.ExitCode;$state.Diagnostics=[pscustomobject]@{StdOut=$result.StdOut;StdErr=$result.StdErr}
    $outputs=@(Get-ChildItem -LiteralPath $attemptDir -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {[pscustomobject]@{Path=$_.FullName;SHA256=(Get-IosStateFileHash -Path $_.FullName);SizeBytes=[long]$_.Length}})
    $ipswReport=$null;$reportComplete=$true
    if($result.StdOut){try{$ipswReport=$result.StdOut|ConvertFrom-Json -ErrorAction Stop;if($ipswReport.PSObject.Properties['complete'] -and -not $ipswReport.complete){$reportComplete=$false}}catch{$state.ReportParseWarning=$_.Exception.Message}}
    $state.IpswReport=$ipswReport
    $state.OutputFiles=$outputs
    if($result.ExitCode -eq 0 -and $outputs.Count -gt 0 -and $reportComplete){$state.Status='completed';$attemptRecord.Status='completed'}else{$state.Status=if($result.TimedOut){'interrupted'}else{'failed'};$attemptRecord.Status=$state.Status}
    Save-IosRunState -State $state -Path $statePath
    if($state.Status -ne 'completed'){throw "ipsw extraction $($state.Status) (exit $($state.ExitCode)). Partial output and diagnostics were retained at $attemptDir"}
    return $state
}

Export-ModuleMember -Function Get-IosIpswCapabilities,New-IosIpswExtractArguments,Invoke-IosFirmwareExtraction,Invoke-IosLocalProcess
