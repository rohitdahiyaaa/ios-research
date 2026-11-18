Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosResearchConfig.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosFirmwareExtraction.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosResearchState.psm1') -Force

function Invoke-IosBatchProcess {
    param([Parameter(Mandatory=$true)][string]$BatchPath,[Parameter(Mandatory=$true)][string[]]$Arguments,[int]$TimeoutSeconds=3600)
    $quote={param([string]$x) '"'+($x -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1')+'"'}
    $command='call '+(& $quote $BatchPath)+' '+(@($Arguments|ForEach-Object {& $quote ([string]$_)}) -join ' ')
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=$env:ComSpec;$psi.Arguments='/d /s /c "'+$command+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
    try{$null=$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();$ok=$p.WaitForExit($TimeoutSeconds*1000);if(-not $ok){$p.Kill();$p.WaitForExit();return [pscustomobject]@{ExitCode=124;TimedOut=$true;StdOut=$out.Result;StdErr=$err.Result}};$p.WaitForExit();return [pscustomobject]@{ExitCode=$p.ExitCode;TimedOut=$false;StdOut=$out.Result;StdErr=$err.Result}}finally{$p.Dispose()}
}

function Invoke-IosGhidraFunctionInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$BinaryPath,[Parameter(Mandatory=$true)][string]$OutputDirectory,[string]$GhidraCommand='ghidraRun.bat',[string]$ScriptPath,[string]$BinExportPath,[switch]$ExportBinDiff,[switch]$AllowFirmwareAccess,[switch]$AuthorizedResearch,[int]$TimeoutSeconds=3600)
    $null=Assert-IosResearchAuthorization -Config $Config -AuthorizedResearch:$AuthorizedResearch -AllowFirmwareAccess:$AllowFirmwareAccess
    $binary=[IO.Path]::GetFullPath($BinaryPath);if(-not(Test-Path -LiteralPath $binary -PathType Leaf)){throw "Binary does not exist: $binary"}
    $output=[IO.Path]::GetFullPath($OutputDirectory)
    if(Test-Path -LiteralPath $output){throw 'Ghidra output directory already exists; refusing to overwrite.'}
    $ghidra=Get-Command $GhidraCommand -ErrorAction Stop | Select-Object -First 1
    $root=Split-Path -Parent $ghidra.Source;$headless=Join-Path $root 'support\analyzeHeadless.bat'
    if(-not(Test-Path -LiteralPath $headless -PathType Leaf)){throw 'Ghidra analyzeHeadless.bat was not found beside the configured launcher.'}
    $headlessHelp=Invoke-IosBatchProcess -BatchPath $headless -Arguments @('-help') -TimeoutSeconds 30
    if($headlessHelp.TimedOut -or (($headlessHelp.StdOut+"`n"+$headlessHelp.StdErr) -notmatch 'Headless Analyzer Usage: analyzeHeadless')){throw 'Ghidra headless command interface could not be verified from its actual help output.'}
    $projectRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $scriptFile=if($ScriptPath){[IO.Path]::GetFullPath($ScriptPath)}else{Join-Path $projectRoot 'adapters\Ghidra\ExportFunctionInventory.java'}
    if(-not(Test-Path -LiteralPath $scriptFile -PathType Leaf)){throw "Ghidra function export script was not found: $scriptFile"}
    $binExportScript=$null;$extensionVersion=$null;$ghidraVersion=$null
    $ghidraProperties=Join-Path (Split-Path -Parent $ghidra.Source) 'Ghidra\application.properties'
    if(Test-Path -LiteralPath $ghidraProperties -PathType Leaf){$versionMatch=Select-String -LiteralPath $ghidraProperties -Pattern '^application\.version\s*=\s*(.+)$'|Select-Object -First 1;if($versionMatch){$ghidraVersion=$versionMatch.Matches[0].Groups[1].Value.Trim()}}
    if($ExportBinDiff){
        if(-not $BinExportPath){$BinExportPath=Join-Path $output 'binary.BinExport'}
        $ghidraVersionDirectory='ghidra_'+$ghidraVersion+'_PUBLIC'
        $extensionsRoot=Join-Path $env:APPDATA (Join-Path 'ghidra' (Join-Path $ghidraVersionDirectory 'Extensions'))
        if(Test-Path -LiteralPath $extensionsRoot -PathType Container){
            foreach($extension in Get-ChildItem -LiteralPath $extensionsRoot -Directory){
                $properties=Join-Path $extension.FullName 'extension.properties'
                if(-not(Test-Path -LiteralPath $properties -PathType Leaf)){continue}
                $extensionText=Get-Content -LiteralPath $properties -Raw
                if($extensionText -match '(?m)^name\s*=\s*BinExport\s*$'){
                    if($extensionText -match '(?m)^version\s*=\s*(.+)$'){$extensionVersion=$matches[1].Trim()}
                    $candidate=Join-Path $extension.FullName 'ghidra_scripts\BinExportHeadless.java'
                    if(Test-Path -LiteralPath $candidate -PathType Leaf){$binExportScript=$candidate;break}
                }
            }
        }
        if(-not $binExportScript){throw "BinExport headless script was not found under the installed Ghidra user extension path: $extensionsRoot"}
        if($extensionVersion -ne $ghidraVersion){throw "BinExport extension version '$extensionVersion' does not match Ghidra '$ghidraVersion'."}
    }
    $parent=Split-Path -Parent $output;if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw "Ghidra output parent does not exist: $parent"}
    $inputHash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
    $projectPath=Join-Path $output 'project';New-Item -ItemType Directory -Path $projectPath | Out-Null
    $functionPath=Join-Path $output 'function-inventory.json';$logPath=Join-Path $output 'ghidra.log';$statePath=Join-Path $output 'ghidra-run.json'
    $state=[pscustomobject]@{SchemaVersion=1;RunId=[guid]::NewGuid().ToString('N');InputPath=$binary;InputSHA256=$inputHash;ToolVersion=$null;StartedAt=[DateTime]::UtcNow.ToString('o');CompletedAt=$null;Status='running';ExitCode=$null;OutputPath=$functionPath;LogPath=$logPath}
    $state.ToolVersion=$ghidraVersion
    $state|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $statePath -Encoding UTF8
    $cpuProperty=$Config.resourceLimits.PSObject.Properties['maxCpuThreads'];$cpu=if($cpuProperty){[int]$cpuProperty.Value}else{1}
    $scriptPaths=@((Split-Path -Parent $scriptFile));if($ExportBinDiff){$scriptPaths+=@(Split-Path -Parent $binExportScript)}
    $args=@($projectPath,('IosResearch_'+$state.RunId),'-import',$binary,'-scriptPath',($scriptPaths -join ';'),'-log',$logPath,'-max-cpu',[string]([Math]::Max(1,$cpu)),'-postScript',[IO.Path]::GetFileName($scriptFile),$functionPath)
    if($ExportBinDiff){$args+=@('-postScript',[IO.Path]::GetFileName($binExportScript),[IO.Path]::GetFullPath($BinExportPath))}
    try{$result=Invoke-IosBatchProcess -BatchPath $headless -Arguments $args -TimeoutSeconds $TimeoutSeconds}catch{$result=[pscustomobject]@{ExitCode=1;TimedOut=$false;StdOut='';StdErr=$_.Exception.Message}}
    if($result.StdOut){Add-Content -LiteralPath $logPath -Value $result.StdOut -Encoding UTF8};if($result.StdErr){Add-Content -LiteralPath $logPath -Value $result.StdErr -Encoding UTF8}
    $state.CompletedAt=[DateTime]::UtcNow.ToString('o');$state.ExitCode=$result.ExitCode;$state.Status=if($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $functionPath -PathType Leaf)){'completed'}elseif($result.TimedOut){'interrupted'}else{'failed'}
    $state|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $statePath -Encoding UTF8
    if($state.Status -ne 'completed'){throw "Ghidra headless analysis $($state.Status), exit $($state.ExitCode). See $logPath"}
    if($ExportBinDiff -and -not(Test-Path -LiteralPath $BinExportPath -PathType Leaf)){throw "Ghidra analysis completed but BinExport output was not created: $BinExportPath. See $logPath"}
    $inventory=Get-Content -LiteralPath $functionPath -Raw|ConvertFrom-Json
    [pscustomobject]@{Status='completed';BinaryPath=$binary;InputSHA256=$inputHash;ToolVersion=$state.ToolVersion;BinExportVersion=$extensionVersion;BinExportPath=if($ExportBinDiff){[IO.Path]::GetFullPath($BinExportPath)}else{$null};BinExportSHA256=if($ExportBinDiff){Get-IosStateFileHash -Path $BinExportPath}else{$null};FunctionCount=@($inventory.functions).Count;InventoryPath=$functionPath;RunState=$statePath;LogPath=$logPath;NetworkAccess=$false;Inventory=$inventory}
}

Export-ModuleMember -Function Invoke-IosGhidraFunctionInventory,Invoke-IosBatchProcess
