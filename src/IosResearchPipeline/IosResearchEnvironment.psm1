Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosFirmwareExtraction.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosGhidraAdapter.psm1') -Force

function Get-IosCommandPath {
    param([Parameter(Mandatory=$true)][string]$Name)
    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { return $null }
    if ($command.Source) { return [string]$command.Source }
    return [string]$command.Definition
}

function Invoke-IosVersionProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][string[]]$Arguments,[int]$TimeoutSeconds=15)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]@{ Executed=$false; ExitCode=$null; Output=@(); Error='Executable not found.' } }
    try {
        $result=Invoke-IosLocalProcess -Executable $Path -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
        $text=(@($result.StdOut,$result.StdErr)|Where-Object {$_}) -join "`n"
        $output=@($text -split "`r?`n" | Select-Object -First 80 | ForEach-Object { ([string]$_).Replace([string]([char]0),'').Trim() } | Where-Object { $_ })
        return [pscustomobject]@{ Executed=(!$result.TimedOut); ExitCode=$result.ExitCode; Output=$output; Error=if($result.TimedOut){'Version probe timed out.'}else{$null} }
    } catch {
        return [pscustomobject]@{ Executed=$false; ExitCode=$null; Output=@(); Error=$_.Exception.Message }
    }
}

function Get-IosWorkspacePermissionProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $probe = Join-Path $Path ('.ios-research-write-probe-' + [guid]::NewGuid().ToString('N'))
    try {
        $stream = New-Object IO.FileStream($probe,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $stream.Dispose()
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
        return [pscustomobject]@{ Writable=$true; Path=$Path; Error=$null }
    } catch {
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
        return [pscustomobject]@{ Writable=$false; Path=$Path; Error=$_.Exception.Message }
    }
}

function Get-IosEnvironmentInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[string]$WorkspacePath)
    $toolSettings = [ordered]@{
        ipsw=@{ Key='ipsw'; Args=@('version') }
        sevenZip=@{ Key='sevenZip'; Args=@('i') }
        ghidra=@{ Key='ghidra'; Args=@() }
        binDiff=@{ Key='binDiff'; Args=@('--help') }
        java=@{ Key='java'; Args=@('-version') }
        python=@{ Key='python'; Args=@('--version') }
        wsl=@{ Key='wsl'; Args=@('--status') }
    }
    $toolResults=[ordered]@{}
    foreach($key in $toolSettings.Keys) {
        $configured=[string]$Config.toolPaths.$key
        if (-not $configured) { $configured=[string]$key }
        $path=Get-IosCommandPath -Name $configured
        if (-not $path) { $toolResults[$key]=[pscustomobject]@{ Available=$false; Path=$null; Version=$null; Executed=$false; Optional=($key -in @('python','wsl')); Details='Command was not found.' }; continue }
        $args=@($toolSettings[$key].Args)
        $probe=$null
        if ($key -eq 'ghidra') {
            $ghidraRoot=Split-Path -Parent $path
            $properties=Join-Path $ghidraRoot 'Ghidra\application.properties'
            $version=$null
            if (Test-Path -LiteralPath $properties -PathType Leaf) {
                $match=Select-String -LiteralPath $properties -Pattern '^application\.version\s*=\s*(.+)$' | Select-Object -First 1
                if ($match) { $version=$match.Matches[0].Groups[1].Value.Trim() }
            }
            $headless=Join-Path $ghidraRoot 'support\analyzeHeadless.bat'
            if (Test-Path -LiteralPath $headless -PathType Leaf) {
                $headResult=Invoke-IosBatchProcess -BatchPath $headless -Arguments @('-help') -TimeoutSeconds 30
                $helpText=$headResult.StdOut+"`n"+$headResult.StdErr
                $helpOk=(!$headResult.TimedOut -and $helpText -match 'Headless Analyzer Usage: analyzeHeadless')
                $probe=[pscustomobject]@{ Executed=$helpOk; ExitCode=$headResult.ExitCode; Output=@($helpText -split "`r?`n"|Select-Object -First 30); Error=if($helpOk){$null}else{'Headless help output was not recognized.'} }
            } else { $probe=[pscustomobject]@{ Executed=$false; ExitCode=$null; Output=@(); Error='analyzeHeadless.bat was not found.' } }
            $toolResults[$key]=[pscustomobject]@{ Available=([bool]$probe.Executed -and [bool]$version); Path=$path; Version=$version; Executed=[bool]$probe.Executed; Optional=$false; Details=$probe.Error }
            continue
        }
        if ($key -eq 'binDiff') {
            $probe=Invoke-IosVersionProbe -Path $path -Arguments @('--help')
            $logo=Invoke-IosVersionProbe -Path $path -Arguments @('--logo')
            $versionLine=@($logo.Output | Where-Object { $_ -match '^BinDiff\s+\d+' } | Select-Object -First 1)
            $version=if($versionLine.Count){$versionLine[0]}else{$null}
        } elseif ($key -eq 'wsl') {
            $probe=Invoke-IosVersionProbe -Path $path -Arguments @('--status')
            $distro=Invoke-IosVersionProbe -Path $path -Arguments @('--list','--verbose')
            $distroText=(@($distro.Output) -join ' ') -replace '\x00',''
            $version=if($distroText -match '(?im)Ubuntu\s+Stopped\s+2'){ 'WSL2 Ubuntu (stopped)' } elseif($distroText -match '(?im)Ubuntu\s+Running\s+2'){ 'WSL2 Ubuntu (running)' } elseif($distroText){$distroText}else{$null}
        } else {
            $probe=Invoke-IosVersionProbe -Path $path -Arguments $args
            $version=$probe.Output | Select-Object -First 1
            if ($key -eq 'sevenZip' -and $probe.Output.Count) { $version=($probe.Output | Where-Object { $_ -match '^7-Zip\s' } | Select-Object -First 1) }
        }
        $supported=if($key -eq 'binDiff'){$probe.Executed -and [bool]$version}else{$probe.Executed -and ($probe.ExitCode -eq 0 -or ($key -eq 'java' -and [bool]$version))}
        $toolResults[$key]=[pscustomobject]@{ Available=[bool]$supported; Path=$path; Version=$version; Executed=[bool]$probe.Executed; Optional=($key -in @('python','wsl')); Details=$probe.Error }
    }
    $os=$null
    try { $os=Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop } catch { }
    if (-not $os) { try { $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { } }
    $workspace=if($WorkspacePath){[IO.Path]::GetFullPath($WorkspacePath)}else{(Get-Location).Path}
    $root=[IO.Path]::GetPathRoot($workspace)
    $disk=$null
    try { $disk=Get-WmiObject -Class Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $root.TrimEnd('\')) -ErrorAction Stop } catch { }
    if (-not $disk) { try { $disk=Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $root.TrimEnd('\')) -ErrorAction Stop } catch { } }
    $permission=Get-IosWorkspacePermissionProbe -Path $workspace
    $wslInfo=$toolResults.wsl.Version
    [pscustomobject]@{
        CollectedAt=[DateTime]::UtcNow.ToString('o')
        Windows=[pscustomobject]@{ Caption=if($os){$os.Caption}else{$null}; Version=if($os){$os.Version}else{[Environment]::OSVersion.VersionString}; Build=if($os){$os.BuildNumber}else{$null} }
        PowerShell=[pscustomobject]@{ Version=$PSVersionTable.PSVersion.ToString(); Edition=$PSVersionTable.PSEdition }
        Python=$toolResults.python
        WSL=[pscustomobject]@{ Available=[bool]$toolResults.wsl.Available; Details=$wslInfo; Tool=$toolResults.wsl }
        Ipsw=$toolResults.ipsw; Ghidra=$toolResults.ghidra; BinDiff=$toolResults.binDiff; Java=$toolResults.java; SevenZip=$toolResults.sevenZip
        Tools=$toolResults
        AvailableDiskBytes=if($disk){[long]$disk.FreeSpace}else{$null}
        TotalMemoryBytes=if($os){[long]$os.TotalVisibleMemorySize*1KB}else{$null}
        FreeMemoryBytes=if($os){[long]$os.FreePhysicalMemory*1KB}else{$null}
        WorkspacePermission=$permission
    }
}

Export-ModuleMember -Function Get-IosEnvironmentInventory,Get-IosWorkspacePermissionProbe,Invoke-IosVersionProbe
