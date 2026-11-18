Set-StrictMode -Version 2.0

$script:SupportedStages = @('validate','environment','inventory','extract','shared-cache','macho','binary-diff','candidates','analyze-metadata','report')
Import-Module (Join-Path $PSScriptRoot 'IosResearchConfig.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosResearchEnvironment.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosResearchState.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosFirmwareInventory.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosFirmwareExtraction.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosSharedCache.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosMachOInventory.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosBinaryDiff.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosGhidraAdapter.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosSecurityAnalysis.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IosResearchReporting.psm1') -Force
$script:StageDependencies = @{
    'analyze-metadata' = @('inventory')
    'candidates' = @('binary-diff')
}

function Get-IosConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ConfigPath)
    return Get-IosPipelineConfig -ConfigPath $ConfigPath
}

function Assert-IosConfigShape {
    param([Parameter(Mandatory=$true)]$Config)
    if ([string]::IsNullOrWhiteSpace([string]$Config.workspace)) { throw 'Config must define a non-empty workspace.' }
    foreach ($field in @('deviceIdentifier','baselineFirmwareVersion','baselineBuild','targetFirmwareVersion','targetBuild','sourceType','inputFirmwarePaths','outputWorkspace','toolPaths','stages','resourceLimits','approvalPolicy')) {
        if ($null -eq $Config.PSObject.Properties[$field]) { throw "Config is missing required field: $field" }
    }
    if ($Config.sourceType -notin @('IPSW','OTA')) { throw 'sourceType must be IPSW or OTA.' }
    if ($Config.stages -isnot [System.Array] -or $Config.stages.Count -eq 0) { throw 'Config stages must be a non-empty array.' }
    if ($Config.inputFirmwarePaths -isnot [System.Array]) { throw 'inputFirmwarePaths must be an array.' }
    if ($null -eq $Config.approvalPolicy.PSObject.Properties['authorizedResearch'] -or $null -eq $Config.approvalPolicy.PSObject.Properties['approvedHosts']) { throw 'approvalPolicy must define authorizedResearch and approvedHosts.' }
    if ($null -eq $Config.resourceLimits.PSObject.Properties['maxRunMinutes'] -or [int]$Config.resourceLimits.maxRunMinutes -lt 1) { throw 'resourceLimits.maxRunMinutes must be a positive integer.' }
    foreach ($stage in @($Config.stages)) { if ([string]::IsNullOrWhiteSpace([string]$stage)) { throw 'Stage names cannot be empty.' } }
    return $true
}

function Test-IosResearchConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ConfigPath)
    $cfg = Get-IosConfig -ConfigPath $ConfigPath
    return Test-IosPipelineConfigDocument -Config $cfg
}

function Get-IosResearchPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ConfigPath,[string]$Product,[string]$Build)
    $cfg = Get-IosConfig -ConfigPath $ConfigPath
    if (-not $Product) { $Product = [string]$cfg.deviceIdentifier }
    if (-not $Build) { $Build = [string]$cfg.targetBuild }
    if ($Product -notmatch '^[A-Za-z0-9,._-]{1,80}$') { throw 'Product contains unsupported characters.' }
    if ($Build -notmatch '^[A-Za-z0-9,._-]{1,80}$') { throw 'Build contains unsupported characters.' }
    [pscustomobject]@{ Product=$Product; Build=$Build; Stages=@($cfg.stages); Mode='Mock'; NetworkAccess=$false; FirmwareExtraction=$false; VulnerabilityResearch=$false; VersionBuildVerified=$false }
}

function Get-IosSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    return Get-IosStateFileHash -Path $Path
}

function Get-IosInputHashes {
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$BasePath,[switch]$AllowFirmwareAccess)
    if(-not $AllowFirmwareAccess){return ,@()}
    $specs=New-Object System.Collections.ArrayList
    foreach($kind in @('inputFirmwarePaths','analysisInputPaths','sharedCacheRoots')){
        $property=$Config.PSObject.Properties[$kind];if(-not $property){continue}
        foreach($input in @($property.Value)){
            $path=if($input -is [string]){[string]$input}else{[string]$input.Path}
            if($path){[void]$specs.Add([pscustomobject]@{Kind=$kind;Path=$path})}
        }
    }
    $pairProperty=$Config.PSObject.Properties['binExportPairs'];if($pairProperty){foreach($pair in @($pairProperty.Value)) {foreach($side in @('BaselineBinExport','TargetBinExport')){$sideProperty=$pair.PSObject.Properties[$side];$p=if($sideProperty){[string]$sideProperty.Value}else{$null};if($p){[void]$specs.Add([pscustomobject]@{Kind='binExportPairs';Path=$p})}}}}
    $result=New-Object System.Collections.ArrayList
    foreach($spec in $specs){
        $path=if([IO.Path]::IsPathRooted($spec.Path)){[IO.Path]::GetFullPath($spec.Path)}else{[IO.Path]::GetFullPath((Join-Path $BasePath $spec.Path))}
        if(Test-Path -LiteralPath $path -PathType Leaf){$item=Get-Item -LiteralPath $path;[void]$result.Add([pscustomobject]@{Kind=$spec.Kind;Path=$path;SHA256=(Get-IosSha256 -Path $path);SizeBytes=[long]$item.Length});continue}
        if(Test-Path -LiteralPath $path -PathType Container){foreach($item in (Get-ChildItem -LiteralPath $path -File -Recurse -ErrorAction Stop|Sort-Object FullName)){[void]$result.Add([pscustomobject]@{Kind=$spec.Kind;Path=$item.FullName;SHA256=(Get-IosSha256 -Path $item.FullName);SizeBytes=[long]$item.Length})};continue}
        [void]$result.Add([pscustomobject]@{Kind=$spec.Kind;Path=$path;SHA256=$null;SizeBytes=$null})
    }
    return ,@($result)
}

function Get-IosConfigHash {
    param([Parameter(Mandatory=$true)][string]$ConfigPath)
    return Get-IosSha256 -Path $ConfigPath
}

function Write-IosJsonAtomic {
    param([Parameter(Mandatory=$true)]$Value,[Parameter(Mandatory=$true)][string]$Path)
    Save-IosRunState -State $Value -Path $Path
}

function Get-IosToolVersions {
    param([Parameter(Mandatory=$true)]$Config)
    return (Get-IosEnvironmentInventory -Config $Config).Tools
}

function Get-IosEnvironmentPreflight {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config)
    $inventory=Get-IosEnvironmentInventory -Config $Config
    [pscustomobject]@{ PowerShellVersion=$inventory.PowerShell.Version; AvailableStorageBytes=$inventory.AvailableDiskBytes; TotalRamBytes=$inventory.TotalMemoryBytes; FreeRamBytes=$inventory.FreeMemoryBytes; Windows=$inventory.Windows; Tools=$inventory.Tools; OptionalTools=@([pscustomobject]@{Name='python';Available=$inventory.Python.Available;Optional=$true},[pscustomobject]@{Name='wsl';Available=$inventory.WSL.Available;Optional=$true}); WorkspacePermission=$inventory.WorkspacePermission; CollectedAt=$inventory.CollectedAt }
}

function Get-IosConfiguredInputEntries {
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$BasePath)
    $entries=New-Object System.Collections.ArrayList;$index=0
    foreach($input in @($Config.inputFirmwarePaths)){
        if($input -is [string]){$path=[string]$input;$role=if($Config.inputFirmwarePaths.Count -eq 2){if($index -eq 0){'baseline'}else{'target'}}else{'target'};$expected=$null}
        else{$pathProperty=$input.PSObject.Properties['Path'];$roleProperty=$input.PSObject.Properties['Role'];$hashProperty=$input.PSObject.Properties['ExpectedSHA256'];$path=if($pathProperty){[string]$pathProperty.Value}else{$null};$role=if($roleProperty -and $roleProperty.Value){[string]$roleProperty.Value}else{'target'};$expected=if($hashProperty){[string]$hashProperty.Value}else{$null}}
        if(-not [IO.Path]::IsPathRooted($path)){$path=Join-Path $BasePath $path}
        [void]$entries.Add([pscustomobject]@{Path=[IO.Path]::GetFullPath($path);Role=$role;ExpectedSHA256=$expected})
        $index++
    }
    return $entries.ToArray()
}

function Get-IosAnalysisEntries {
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$BasePath)
    $entries=New-Object System.Collections.ArrayList;$index=0;$raw=@($Config.analysisInputPaths)
    foreach($entryItem in $raw){
        $path=if($entryItem -is [string]){[string]$entryItem}else{[string]$entryItem.Path}
        $roleProperty=if($entryItem -is [string]){$null}else{$entryItem.PSObject.Properties['Role']}
        $role=if($roleProperty -and $roleProperty.Value){[string]$roleProperty.Value}elseif($raw.Count -eq 2 -and $index -eq 0){'baseline'}else{'target'}
        if($role -notin @('baseline','target')){throw "Unsupported analysis input role '$role'. Use baseline or target."}
        if(-not $path){throw 'Analysis input path cannot be empty.'}
        if(-not [IO.Path]::IsPathRooted($path)){$path=Join-Path $BasePath $path}
        $path=[IO.Path]::GetFullPath($path)
        if(-not(Test-Path -LiteralPath $path)){throw "Analysis input does not exist: $path"}
        [void]$entries.Add([pscustomobject]@{Role=$role;Path=$path;Source='configured'});$index++
    }
    return $entries.ToArray()
}

function Get-IosExtractedAnalysisEntries {
    param([Parameter(Mandatory=$true)]$Record)
    $entries=New-Object System.Collections.ArrayList
    $cache=Get-IosPriorStageResult -Record $Record -Name 'shared-cache'
    if($cache){foreach($extraction in @($cache.ImageExtractions)){$componentProperty=$extraction.PSObject.Properties['Component'];$roleProperty=$extraction.PSObject.Properties['Role'];foreach($file in @($extraction.OutputFiles)){if($file.Path -and (Test-Path -LiteralPath $file.Path -PathType Leaf)){[void]$entries.Add([pscustomobject]@{Role=if($roleProperty){$roleProperty.Value}else{'target'};Path=[IO.Path]::GetFullPath([string]$file.Path);Source='shared-cache-dylib-extraction';Component=if($componentProperty){$componentProperty.Value}else{$null}})}}}}
    if(-not $entries.Count){$extract=Get-IosPriorStageResult -Record $Record -Name 'extract';if($extract){foreach($item in @($extract.Extractions)){$attempt=@($item.Attempts|Where-Object {$_.Status -eq 'completed'}|Select-Object -Last 1);if($attempt.Count -and $attempt[0].OutputDirectory -and (Test-Path -LiteralPath $attempt[0].OutputDirectory -PathType Container)){[void]$entries.Add([pscustomobject]@{Role=$item.Role;Path=[IO.Path]::GetFullPath([string]$attempt[0].OutputDirectory);Source='firmware-extraction'})}}}}
    return $entries.ToArray()
}

function Get-IosSharedCacheRootEntries {
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$BasePath)
    $result=New-Object System.Collections.ArrayList;$items=@($Config.sharedCacheRoots);$index=0
    foreach($rootItem in $items){$rawPath=if($rootItem -is [string]){[string]$rootItem}else{[string]$rootItem.Path};$roleProperty=if($rootItem -is [string]){$null}else{$rootItem.PSObject.Properties['Role']};$role=if($roleProperty -and $roleProperty.Value){[string]$roleProperty.Value}elseif($items.Count -eq 2 -and $index -eq 0){'baseline'}else{'target'};if($role -notin @('baseline','target')){throw "Unsupported shared-cache root role '$role'."};if(-not $rawPath){throw 'Shared-cache root path cannot be empty.'};if(-not [IO.Path]::IsPathRooted($rawPath)){$rawPath=Join-Path $BasePath $rawPath};[void]$result.Add([pscustomobject]@{Role=$role;Path=[IO.Path]::GetFullPath($rawPath)});$index++}
    return $result.ToArray()
}

function Get-IosUniqueRunArtifactPath {
    param([string]$RunDirectory,[string]$Name)
    $path=Join-Path $RunDirectory $Name
    if(Test-Path -LiteralPath $path){$path=Join-Path $RunDirectory ([IO.Path]::GetFileNameWithoutExtension($Name)+'-'+[guid]::NewGuid().ToString('N')+[IO.Path]::GetExtension($Name))}
    return $path
}

function Get-IosPriorStageResult {
    param($Record,[string]$Name)
    $stage=@($Record.Stages|Where-Object {$_.Name -eq $Name -and $_.Status -in @('completed','mocked')})|Select-Object -Last 1
    if($stage -and $stage.PSObject.Properties['ResultPath'] -and $stage.ResultPath -and (Test-Path -LiteralPath $stage.ResultPath -PathType Leaf)){
        return (Get-Content -LiteralPath $stage.ResultPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
    }
    if($stage -and $stage.PSObject.Properties['Result']){return $stage.Result};return $null
}

function Get-IosFinalRunStatus {
    param($Record,$Config)
    $failed=@($Record.Stages|Where-Object {$_.Status -eq 'failed'}).Count
    $interrupted=@($Record.Stages|Where-Object {$_.Status -eq 'interrupted'}).Count
    $incomplete=@($Config.stages|Where-Object {$requested=$_;@($Record.Stages|Where-Object {$_.Name -eq $requested -and $_.Status -in @('completed','mocked')}).Count -eq 0}).Count
    if($failed){return 'failed'};if($interrupted){return 'interrupted'};if($incomplete){return 'partial'};return 'completed'
}

function Set-IosStageResultArtifact {
    param([string]$StageName,$StageResult,$StageRecord,[string]$RunDirectory)
    $knownName=switch($StageName){
        'environment' {'environment-*.json'}
        'inventory' {'inventory-stage-result*.json'}
        'shared-cache' {'shared-cache-stage-result*.json'}
        'macho' {'macho-stage-result*.json'}
        'binary-diff' {'binary-diff-stage-result*.json'}
        'candidates' {'candidate-stage-result*.json'}
        default {$null}
    }
    $resultPath=$null
    if($knownName){$resultPath=@($StageRecord.OutputPaths|Where-Object {[IO.Path]::GetFileName($_) -like $knownName}|Select-Object -Last 1)[0]}
    if($StageName -eq 'extract'){
        $resultPath=Get-IosUniqueRunArtifactPath -RunDirectory $RunDirectory -Name 'extract-stage-result.json'
        $null=Write-IosUniqueArtifact -Directory $RunDirectory -Name ([IO.Path]::GetFileName($resultPath)) -Value $StageResult
        $StageRecord.OutputPaths=@($StageRecord.OutputPaths)+$resultPath
    }
    if($resultPath -and (Test-Path -LiteralPath $resultPath -PathType Leaf)){$StageRecord.ResultPath=$resultPath}
}

function Test-IosFirmwareAgainstRequest {
    param([Parameter(Mandatory=$true)]$Inventory,[Parameter(Mandatory=$true)]$Entries,[string]$Device,[string]$BaselineVersion,[string]$BaselineBuild,[string]$TargetVersion,[string]$TargetBuild)
    $checks=New-Object System.Collections.ArrayList;$errors=New-Object System.Collections.ArrayList
    foreach($item in $Inventory.Inputs){
        $entry=@($Entries|Where-Object {$_.Path -eq $item.Path})|Select-Object -First 1
        $role=if($entry){$entry.Role}else{'target'}
        $expectedBuild=if($role -eq 'baseline'){$BaselineBuild}else{$TargetBuild}
        $expectedVersion=if($role -eq 'baseline'){$BaselineVersion}else{$TargetVersion}
        $deviceMatch=$null;if(@($item.DeviceIdentifiers).Count){$deviceMatch=@($item.DeviceIdentifiers|Where-Object {$_ -eq $Device}).Count -gt 0}
        $buildMatch=if($expectedBuild){$item.Build -eq $expectedBuild}else{$null}
        $versionMatch=if($expectedVersion){$item.FirmwareVersion -eq $expectedVersion}else{$null}
        $check=[pscustomobject]@{Path=$item.Path;Role=$role;ExpectedDevice=$Device;ObservedDevices=$item.DeviceIdentifiers;DeviceMatch=$deviceMatch;ExpectedVersion=$expectedVersion;ObservedVersion=$item.FirmwareVersion;VersionMatch=$versionMatch;ExpectedBuild=$expectedBuild;ObservedBuild=$item.Build;BuildMatch=$buildMatch}
        if($deviceMatch -eq $false){[void]$errors.Add("$($item.Path) supports $($item.DeviceIdentifiers -join ', '), expected $Device")}
        if($buildMatch -eq $false){[void]$errors.Add("$($item.Path) build is $($item.Build), expected $expectedBuild for role $role")}
        if($versionMatch -eq $false){[void]$errors.Add("$($item.Path) version is $($item.FirmwareVersion), expected $expectedVersion for role $role")}
        [void]$checks.Add($check);$item|Add-Member -NotePropertyName Role -NotePropertyValue $role -Force;$item|Add-Member -NotePropertyName RequestValidation -NotePropertyValue $check -Force
    }
    $Inventory|Add-Member -NotePropertyName RequestValidation -NotePropertyValue ([pscustomobject]@{Status=if($errors.Count){'mismatch'}else{'verified'};Checks=@($checks);Errors=@($errors)}) -Force
    if($errors.Count){throw ('Firmware metadata does not match the requested device/build: '+($errors -join '; '))}
    return $Inventory
}

function Invoke-IosResearchPipeline {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Low')]
    param(
        [Parameter(Mandatory=$true)][string]$ConfigPath,
        [string]$Product,[string]$Build,[string]$BaselineBuild,[string]$BaselineVersion,[string]$TargetVersion,
        [switch]$Mock,[switch]$AllowFirmwareAccess,[switch]$AllowExtraction,[switch]$AuthorizedResearch,[switch]$AnalyzeFunctions,
        [string[]]$Stage,[string]$ResumeRunId
    )
    $cfg=Get-IosConfig -ConfigPath $ConfigPath;$null=Test-IosResearchConfig -ConfigPath $ConfigPath
    if(-not $Product){$Product=[string]$cfg.deviceIdentifier};if(-not $Build){$Build=[string]$cfg.targetBuild};if(-not $BaselineBuild){$BaselineBuild=[string]$cfg.baselineBuild};if(-not $BaselineVersion){$BaselineVersion=[string]$cfg.baselineFirmwareVersion};if(-not $TargetVersion){$TargetVersion=[string]$cfg.targetFirmwareVersion}
    foreach($value in @($Product,$Build,$BaselineBuild)){if($value -notmatch '^[A-Za-z0-9,._-]{1,80}$'){throw 'Device and build identifiers contain unsupported characters.'}}
    foreach($version in @($BaselineVersion,$TargetVersion)){if($version -and $version -notmatch '^[A-Za-z0-9._+-]{1,80}$'){throw 'Firmware version contains unsupported characters.'}}
    $selected=if($Stage -and $Stage.Count){@($Stage)}else{@($cfg.stages)}
    $unsupported=@($selected|Where-Object {$_ -notin $script:SupportedStages});if($unsupported.Count){throw "Unsupported stage(s): $($unsupported -join ', ')"}
    $firmwareStages=@('inventory','extract','shared-cache','macho','binary-diff','candidates','report','analyze-metadata')
    if(-not $Mock -and @($selected|Where-Object {$_ -in $firmwareStages}).Count){
        if(-not $AuthorizedResearch -or -not $cfg.approvalPolicy.authorizedResearch){throw 'Research stages require -AuthorizedResearch and approvalPolicy.authorizedResearch=true.'}
        if(@($selected|Where-Object {$_ -in @('inventory','shared-cache','macho','binary-diff','candidates')}).Count -and -not $AllowFirmwareAccess){throw 'Firmware analysis stages require -AllowFirmwareAccess.'}
        if($selected -contains 'extract' -and -not $AllowExtraction){throw 'Extraction stage requires explicit -AllowExtraction.'}
        if($selected -contains 'shared-cache' -and $AllowExtraction -and -not $AuthorizedResearch){throw 'Shared-cache dylib extraction requires explicit -AuthorizedResearch.'}
    }
    $rootBase=Split-Path -Parent ([IO.Path]::GetFullPath($ConfigPath))
    if([IO.Path]::IsPathRooted([string]$cfg.outputWorkspace)){throw 'outputWorkspace must be relative to the configuration directory.'}
    $root=[IO.Path]::GetFullPath((Join-Path $rootBase $cfg.outputWorkspace));$prefix=[IO.Path]::GetFullPath($rootBase).TrimEnd('\')+'\'
    if(-not $root.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'outputWorkspace cannot escape the configuration directory.'}
    $runs=Join-Path $root 'runs'
    if($WhatIfPreference){return [pscustomobject]@{RunId='not-created';Status='whatif';Mode=if($Mock){'mock'}else{'research'};DeviceIdentifier=$Product;Build=$Build;Stages=@($selected);NetworkAccess=$false;FirmwareExtraction=$false;VulnerabilityResearch=$false}}
    if(-not(Test-Path -LiteralPath $runs)){New-Item -ItemType Directory -Path $runs -ErrorAction Stop|Out-Null}
    $configHash=Get-IosConfigHash -ConfigPath $ConfigPath
    $inputHashes=if($Mock){@()}else{@(Get-IosInputHashes -Config $cfg -BasePath $rootBase -AllowFirmwareAccess:$AllowFirmwareAccess)}
    $environment=Get-IosEnvironmentInventory -Config $cfg -WorkspacePath $root
    $toolVersions=$environment.Tools;$now=[DateTime]::UtcNow.ToString('o')
    $minimumFree=[long]$cfg.resourceLimits.minimumFreeBytes
    if(-not $Mock -and @($selected|Where-Object {$_ -in $firmwareStages}).Count -and $null -ne $environment.AvailableDiskBytes -and [long]$environment.AvailableDiskBytes -lt $minimumFree){throw "Available output storage ($($environment.AvailableDiskBytes) bytes) is below configured minimum ($minimumFree bytes)."}
    if($ResumeRunId){
        if($ResumeRunId -notmatch '^\d{8}T\d{6}Z-[a-f0-9]{8}$'){throw 'Invalid resume run ID.'}
        $runDir=Join-Path $runs $ResumeRunId;$statePath=Join-Path $runDir 'run.json';if(-not(Test-Path -LiteralPath $statePath -PathType Leaf)){throw 'Resume state does not exist.'}
        $record=Get-IosRunState -Path $statePath -RunId $ResumeRunId;if($record.DeviceIdentifier -ne $Product){throw 'Resume device identifier differs from saved run.'}
        foreach($property in @(@{Name='ReportManifestPath';Value=$null},@{Name='DurationSeconds';Value=$null},@{Name='ElapsedSeconds';Value=$null},@{Name='ArtifactReferences';Value=@()})){if(-not $record.PSObject.Properties[$property.Name]){$record|Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value}}
        $requestedMode=if($Mock){'mock'}else{'research'}
        if($record.Mode -and $record.Mode -ne $requestedMode){throw "Cannot resume a $($record.Mode) run in $requestedMode mode. Start a new run instead."}
        $record.Mode=if($Mock){'mock'}else{'research'};$record.Status='running';$record.ResumedAt=$now;$record.CurrentConfigHash=$configHash;$record.CurrentInputHashes=$inputHashes;$record.ToolVersions=$toolVersions
        $record.Environment=$environment
        $configChanged=$record.ConfigurationHash -ne $configHash;$inputsChanged=(ConvertTo-Json -InputObject @($record.InputHashes) -Compress -Depth 5) -ne (ConvertTo-Json -InputObject @($inputHashes) -Compress -Depth 5)
        foreach($s in @($record.Stages)){$invalidate=$configChanged -or ($inputsChanged -and $s.Name -in $firmwareStages);if($invalidate -and $s.Status -in @('completed','mocked')){$s.Status='invalidated';$s.ValidationResult='Configuration or stage inputs changed since completion.'}}
        $record.ConfigurationHash=$configHash;$record.InputHashes=$inputHashes
    }else{
        $runId=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+([guid]::NewGuid().ToString('N').Substring(0,8));$runDir=Join-Path $runs $runId
        if(Test-Path -LiteralPath $runDir){throw 'Generated run directory already exists; refusing to overwrite.'};New-Item -ItemType Directory -Path $runDir -ErrorAction Stop|Out-Null
        $record=[pscustomobject]@{SchemaVersion=4;RunId=$runId;CreatedAt=$now;CompletedAt=$null;ResumedAt=$null;ReportPath=$null;ReportManifestPath=$null;DurationSeconds=$null;ElapsedSeconds=$null;ArtifactReferences=@();OutputPaths=@();DeviceIdentifier=$Product;Product=$Product;BaselineVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetVersion=$TargetVersion;Build=$Build;TargetBuild=$Build;ConfigurationHash=$configHash;CurrentConfigHash=$configHash;InputHashes=$inputHashes;CurrentInputHashes=$inputHashes;ToolVersions=$toolVersions;Environment=$environment;Status='running';Mode=if($Mock){'mock'}else{'research'};NetworkAccess=$false;FirmwareExtraction=$false;VulnerabilityResearch=$false;Stages=@()}
    }
    $runStarted=[DateTime]::UtcNow;$reportManifestPath=$null
    foreach($name in $selected){
        $existing=@($record.Stages|Where-Object {$_.Name -eq $name})|Select-Object -First 1
        if($existing){foreach($property in @(@{Name='Result';Value=$null},@{Name='ResultSummary';Value=$null},@{Name='ResultPath';Value=$null},@{Name='OutputPaths';Value=@()},@{Name='InputHashes';Value=@()},@{Name='Error';Value=$null})){if(-not $existing.PSObject.Properties[$property.Name]){$existing|Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value}}}
        if($existing -and $existing.Status -in @('completed','mocked')){continue}
        if($existing){$existing.Status='running';$existing.StartedAt=[DateTime]::UtcNow.ToString('o');$existing.CompletedAt=$null;$existing.ExitCode=$null}
        else{$existing=[pscustomobject]@{Name=$name;Status='pending';StartedAt=$null;CompletedAt=$null;ExitCode=$null;OutputPaths=@();InputHashes=$inputHashes;ValidationResult=$null;Details=$null;Error=$null;Result=$null;ResultSummary=$null;ResultPath=$null};$record.Stages+=$existing}
        if(-not $PSCmdlet.ShouldProcess($existing.Name,('Execute '+$record.Mode+' stage'))){$existing.Status='not-run';continue}
        $existing.Status='running';$existing.StartedAt=[DateTime]::UtcNow.ToString('o')
        try{
            $dependencies=if($script:StageDependencies.ContainsKey($name)){@($script:StageDependencies[$name])}else{@()}
            foreach($dependency in $dependencies){
                $dependencyResult=Get-IosPriorStageResult -Record $record -Name $dependency
                if(-not $dependencyResult){throw "Stage '$name' requires a successful '$dependency' stage in this run. Select the prerequisite stage or resume a run that completed it."}
            }
            if($name -ne 'report' -and ([DateTime]::UtcNow-$runStarted).TotalMinutes -ge [double]$cfg.resourceLimits.maxRunMinutes){throw 'Configured maximum run time was reached; stage was interrupted before execution.'}
            $remaining=[Math]::Max(1,[int](([double]$cfg.resourceLimits.maxRunMinutes*60)-([DateTime]::UtcNow-$runStarted).TotalSeconds))
            $configuredTimeout=[int]$cfg.resourceLimits.toolTimeoutSeconds;if($configuredTimeout -lt 1){$configuredTimeout=3600};$toolTimeout=[Math]::Min($configuredTimeout,$remaining)
            if($Mock){
                $stageResult=[pscustomobject]@{Status='mocked';Stage=$name;Findings=@();Claims='Simulated only; no firmware files were opened and no security analysis was performed.';NetworkAccess=$false}
                $existing.ValidationResult='Synthetic stage record only.';$existing.Details=$stageResult.Claims
                if($name -eq 'environment'){$stageResult=$environment;$existing.Details='Actual local environment/tool probes recorded; no firmware was opened.'}
                elseif($name -eq 'report'){
                    $reportPlan=Get-IosResearchReportPlan -RunDirectory $runDir
                    $existing.Status='mocked';$existing.ExitCode=0;$existing.CompletedAt=[DateTime]::UtcNow.ToString('o');$existing.OutputPaths=@($reportPlan.Values)
                    $record.Status=Get-IosFinalRunStatus -Record $record -Config $cfg;$record.CompletedAt=$existing.CompletedAt;$record.ReportManifestPath=$reportPlan['run-manifest.json']
                    $mockContext=[pscustomobject]@{RunId=$record.RunId;DeviceIdentifier=$Product;BaselineFirmwareVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetFirmwareVersion=$TargetVersion;TargetBuild=$Build;InputHashes=@();ToolVersions=$toolVersions;Status=$record.Status;Mode='mock';Stages=$record.Stages;CreatedAt=$record.CreatedAt;CompletedAt=$record.CompletedAt}
                    $mockReports=New-IosResearchReports -RunDirectory $runDir -Context $mockContext -Artifacts @{} -Plan $reportPlan -DeferManifest
                    $stageResult=[pscustomobject]@{Status='mocked';Claims='Reports generated from mock stage statuses only.';ReportPaths=$mockReports.ReportPaths;ManifestPath=$mockReports.ManifestPath;NetworkAccess=$false};$existing.OutputPaths=@($mockReports.ReportPaths.Values);$record.ReportPath=$mockReports.MarkdownPath;$reportManifestPath=$mockReports.ManifestPath
                }
            }else{
                $stageResult=$null
                switch($name){
                    'validate' {$stageResult=[pscustomobject]@{Status='completed';DeviceIdentifier=$Product;BaselineBuild=$BaselineBuild;TargetBuild=$Build;VersionBuildVerified=$false;Validation='Supplied identifiers validated syntactically only.'};$existing.ValidationResult=$stageResult.Validation}
                    'environment' {$stageResult=$environment;$path=Get-IosUniqueRunArtifactPath -RunDirectory $runDir -Name 'environment.json';$null=Write-IosUniqueArtifact -Directory $runDir -Name ([IO.Path]::GetFileName($path)) -Value $environment;$existing.OutputPaths=@($path)}
                    'inventory' {$entries=@(Get-IosConfiguredInputEntries -Config $cfg -BasePath $rootBase);$hashes=@{};foreach($e in $entries){if($e.ExpectedSHA256){$hashes[$e.Path]=$e.ExpectedSHA256}};$stageResult=Get-IosFirmwareInventory -Config $cfg -InputPaths @($entries|ForEach-Object {$_.Path}) -ExpectedHashes $hashes -IpswCommand ([string]$cfg.toolPaths.ipsw) -AllowFirmwareAccess -AuthorizedResearch;$stageResult=Test-IosFirmwareAgainstRequest -Inventory $stageResult -Entries $entries -Device $Product -BaselineVersion $BaselineVersion -BaselineBuild $BaselineBuild -TargetVersion $TargetVersion -TargetBuild $Build;$path=Get-IosUniqueRunArtifactPath -RunDirectory $runDir -Name 'inventory-stage-result.json';$null=Save-IosFirmwareManifest -Manifest $stageResult -Path $path;$existing.OutputPaths=@($path);$existing.ValidationResult='Local firmware metadata, device, requested build, and SHA-256 verified.'}
                    'extract' {$entries=@(Get-IosConfiguredInputEntries -Config $cfg -BasePath $rootBase);if(-not $entries.Count){throw 'No local IPSW/OTA inputs are configured.'};$parent=Join-Path $runDir 'extractions';if(-not(Test-Path $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};$items=New-Object System.Collections.ArrayList;foreach($entry in $entries){$role=$entry.Role -replace '[^A-Za-z0-9_-]','_';$out=Join-Path $parent ($role+'-'+[IO.Path]::GetFileNameWithoutExtension($entry.Path));$resume=$false;if(Test-Path -LiteralPath $out -PathType Container){$op=Join-Path $out 'extraction.json';if(Test-Path -LiteralPath $op){$previous=Get-Content -LiteralPath $op -Raw|ConvertFrom-Json;$currentHash=Get-IosStateFileHash -Path $entry.Path;if($previous.InputSHA256 -eq $currentHash){$resume=$true}else{$out=Join-Path $parent ($role+'-'+[IO.Path]::GetFileNameWithoutExtension($entry.Path)+'-'+[guid]::NewGuid().ToString('N'))}}else{$out=Join-Path $parent ($role+'-'+[guid]::NewGuid().ToString('N'))}};$r=Invoke-IosFirmwareExtraction -Config $cfg -InputPath $entry.Path -OutputDirectory $out -Device $Product -IpswCommand ([string]$cfg.toolPaths.ipsw) -AllowFirmwareAccess -AllowExtraction -AuthorizedResearch -Resume:$resume -TimeoutSeconds $toolTimeout;[void]$items.Add([pscustomobject]@{Role=$entry.Role;InputPath=$entry.Path;InputSHA256=(Get-IosStateFileHash -Path $entry.Path);Extraction=$r;Attempts=@($r.Attempts);OutputFiles=@($r.OutputFiles)});$existing.OutputPaths+=@($r.OutputFiles|ForEach-Object {$_.Path})};$record.FirmwareExtraction=$true;$stageResult=[pscustomobject]@{Status='completed';Extractions=@($items);NetworkAccess=$false}}
                    'shared-cache' {
                        $roleResults=New-Object System.Collections.ArrayList;$extractResult=Get-IosPriorStageResult -Record $record -Name 'extract';$configuredRoots=@(Get-IosSharedCacheRootEntries -Config $cfg -BasePath $rootBase)
                        $roles=@('baseline','target')
                        foreach($role in $roles){$roots=@();if($extractResult){$roots+=@($extractResult.Extractions|Where-Object {$_.Role -eq $role}|ForEach-Object {$_.Attempts|Where-Object {$_.Status -eq 'completed'}|Select-Object -Last 1|ForEach-Object {$_.OutputDirectory}})}
                            $roots+=@($configuredRoots|Where-Object {$_.Role -eq $role}|ForEach-Object {$_.Path})
                            if(-not $roots.Count){continue};$cacheOut=Join-Path $runDir ('dylib-extractions-'+$role);$maxDylibs=[int]$cfg.resourceLimits.maxDylibExtractions
                            $cacheResult=Get-IosSharedCacheInventory -Config $cfg -Roots @($roots) -Role $role -Architecture @($cfg.sharedCacheArchitectures) -Components @($cfg.components) -ExtractionRoot $cacheOut -MaxDylibExtractions $maxDylibs -TimeoutSeconds $toolTimeout -IpswCommand ([string]$cfg.toolPaths.ipsw) -AllowFirmwareAccess -AllowExtraction:$AllowExtraction -AuthorizedResearch:$AuthorizedResearch
                            [void]$roleResults.Add($cacheResult);$existing.OutputPaths+=@($cacheResult.ImageExtractions|ForEach-Object {$_.OutputFiles}|ForEach-Object {$_.Path})
                        }
                        if(-not $roleResults.Count){throw 'No extracted firmware roots or sharedCacheRoots were available for shared-cache inventory.'}
                        if($AllowExtraction){$record.FirmwareExtraction=$true}
                        $allExtractions=@($roleResults|ForEach-Object {$_.ImageExtractions});$stageResult=[pscustomobject]@{SchemaVersion=1;Status='completed';ByRole=@($roleResults);Caches=@($roleResults|ForEach-Object {$_.Caches});ImageExtractions=$allExtractions;NetworkAccess=$false;DylibExtractionEnabled=[bool]$AllowExtraction}
                        $path=Get-IosUniqueRunArtifactPath -RunDirectory $runDir -Name 'shared-cache-stage-result.json';$null=Write-IosUniqueArtifact -Directory $runDir -Name ([IO.Path]::GetFileName($path)) -Value $stageResult;$existing.OutputPaths+=@($path)
                    }
                    'macho' {
                        $inputs=@(Get-IosAnalysisEntries -Config $cfg -BasePath $rootBase)
                        if(-not $inputs.Count){$inputs=@(Get-IosExtractedAnalysisEntries -Record $record)}
                        if(-not $inputs.Count){throw 'No Mach-O inputs found. Supply analysisInputPaths or run shared-cache with -AllowExtraction to create individual images.'}
                        $inventories=New-Object System.Collections.ArrayList
                        foreach($role in @('baseline','target')){$roleInputs=@($inputs|Where-Object {$_.Role -eq $role});if(-not $roleInputs.Count){continue};$outPath=Get-IosUniqueRunArtifactPath -RunDirectory $runDir -Name ('macho-inventory-'+$role+'.json');$inventory=Get-IosMachOInventory -Roots @($roleInputs|ForEach-Object {$_.Path}) -Component @($cfg.components) -ManifestPath $outPath;foreach($binary in @($inventory.Binaries)){$binary|Add-Member -NotePropertyName Role -NotePropertyValue $role -Force;$source=@($roleInputs|Where-Object {$binary.Path -eq $_.Path -or $binary.Path.StartsWith($_.Path,[StringComparison]::OrdinalIgnoreCase)}|Select-Object -First 1);if($source.Count){$binary|Add-Member -NotePropertyName Source -NotePropertyValue $source[0].Source -Force}};$inventory|Add-Member -NotePropertyName Role -NotePropertyValue $role -Force;[void]$inventories.Add($inventory);$existing.OutputPaths+=@($outPath)}
                        if(-not $inventories.Count){throw 'Mach-O analysis inputs did not produce a baseline or target inventory.'}
                        $combinedBinaries=@($inventories|ForEach-Object {$_.Binaries});$parsedBinaries=@($combinedBinaries|Where-Object {$_.Status -eq 'parsed'});if(-not $parsedBinaries.Count){throw 'Mach-O stage found no supported Mach-O images in its configured or extracted inputs.'};$combined=[pscustomobject]@{SchemaVersion=1;Status='completed';ByRole=@($inventories);Binaries=$combinedBinaries;BinaryCount=$combinedBinaries.Count;ParsedBinaryCount=$parsedBinaries.Count;Inputs=$inputs;Discovery=if(@($cfg.analysisInputPaths).Count){'configured analysisInputPaths'}else{'successful extraction outputs'};ExecutionStatus='real-input-analysis'}
                        $path=Get-IosUniqueRunArtifactPath -RunDirectory $runDir -Name 'macho-stage-result.json';$null=Write-IosUniqueArtifact -Directory $runDir -Name ([IO.Path]::GetFileName($path)) -Value $combined;$existing.OutputPaths+=@($path);$stageResult=$combined;$existing.ValidationResult='Mach-O files discovered from configured inputs or completed extraction outputs.'
                    }
                    'binary-diff' {
                        $macho=Get-IosPriorStageResult -Record $record -Name 'macho'
                        if(-not $macho){$inputs=@(Get-IosAnalysisEntries -Config $cfg -BasePath $rootBase);if(-not $inputs.Count){$inputs=@(Get-IosExtractedAnalysisEntries -Record $record)};foreach($role in @('baseline','target')){$roleInputs=@($inputs|Where-Object {$_.Role -eq $role});if($roleInputs.Count){$inventory=Get-IosMachOInventory -Roots @($roleInputs|ForEach-Object {$_.Path});foreach($binary in @($inventory.Binaries)){$binary|Add-Member -NotePropertyName Role -NotePropertyValue $role -Force};if(-not $macho){$macho=[pscustomobject]@{ByRole=@();Binaries=@()}};$macho.ByRole+=@([pscustomobject]@{Role=$role;Binaries=$inventory.Binaries});$macho.Binaries+=@($inventory.Binaries)}}}
                        $baseList=New-Object System.Collections.ArrayList;$targetList=New-Object System.Collections.ArrayList
                        if($macho){foreach($roleInventory in @($macho.ByRole)){if($roleInventory.Role -eq 'baseline'){foreach($binary in @($roleInventory.Binaries)){[void]$baseList.Add($binary)}}elseif($roleInventory.Role -eq 'target'){foreach($binary in @($roleInventory.Binaries)){[void]$targetList.Add($binary)}}}}
                        $base=$baseList.ToArray();$target=$targetList.ToArray()
                        if(-not $base.Count -or -not $target.Count){throw 'binary-diff requires successful baseline and target Mach-O inventories from the macho stage or role-tagged analysisInputPaths.'}
                        $stageResult=Compare-IosBinaryInventories -Baseline ([pscustomobject]@{Build=$BaselineBuild;Binaries=$base}) -Target ([pscustomobject]@{Build=$Build;Binaries=$target})
                        $functionPairs=New-Object System.Collections.ArrayList;$binDiffRuns=New-Object System.Collections.ArrayList
                        if($AnalyzeFunctions){
                            $maxBinaries=[int]$cfg.resourceLimits.maxGhidraBinaries;if($maxBinaries -lt 1){throw 'maxGhidraBinaries must be positive when -AnalyzeFunctions is used.'}
                            $changed=@($stageResult.ChangedBinaries|Select-Object -First $maxBinaries)
                            foreach($pair in $changed){
                                $left=Join-Path $runDir ('ghidra-baseline-'+[guid]::NewGuid().ToString('N'));$right=Join-Path $runDir ('ghidra-target-'+[guid]::NewGuid().ToString('N'))
                                $leftExport=Join-Path $left 'binary.BinExport';$rightExport=Join-Path $right 'binary.BinExport'
                                $l=Invoke-IosGhidraFunctionInventory -Config $cfg -BinaryPath $pair.BaselinePath -OutputDirectory $left -GhidraCommand ([string]$cfg.toolPaths.ghidra) -BinExportPath $leftExport -ExportBinDiff -AllowFirmwareAccess -AuthorizedResearch -TimeoutSeconds $toolTimeout
                                $r=Invoke-IosGhidraFunctionInventory -Config $cfg -BinaryPath $pair.TargetPath -OutputDirectory $right -GhidraCommand ([string]$cfg.toolPaths.ghidra) -BinExportPath $rightExport -ExportBinDiff -AllowFirmwareAccess -AuthorizedResearch -TimeoutSeconds $toolTimeout
                                $existing.OutputPaths+=@($l.InventoryPath,$r.InventoryPath,$l.LogPath,$r.LogPath,$l.BinExportPath,$r.BinExportPath)
                                $binDiffOut=Join-Path $runDir ('bindiff-'+[guid]::NewGuid().ToString('N'));$bindiff=Invoke-IosBinDiff -Config $cfg -BaselineBinExport $l.BinExportPath -TargetBinExport $r.BinExportPath -OutputDirectory $binDiffOut -BinDiffCommand ([string]$cfg.toolPaths.binDiff) -PythonCommand ([string]$cfg.toolPaths.python) -AllowFirmwareAccess -AuthorizedResearch -TimeoutSeconds $toolTimeout;$bindiff=Assert-IosBinDiffCompleted -Result $bindiff
                                foreach($setName in @('FunctionMatches','ChangedFunctions','AddedFunctions','RemovedFunctions')){foreach($item in @($bindiff.$setName)){$item|Add-Member -NotePropertyName BinaryName -NotePropertyValue $pair.Name -Force;$item|Add-Member -NotePropertyName BaselinePath -NotePropertyValue $pair.BaselinePath -Force;$item|Add-Member -NotePropertyName TargetPath -NotePropertyValue $pair.TargetPath -Force;if(-not $item.PSObject.Properties['Name']){$functionName=if($item.TargetName){$item.TargetName}else{$item.BaselineName};$item|Add-Member -NotePropertyName Name -NotePropertyValue $functionName -Force};if(-not $item.PSObject.Properties['TargetAddress']){$item|Add-Member -NotePropertyName TargetAddress -NotePropertyValue $item.TargetAddress -Force}}}
                                [void]$functionPairs.Add($bindiff);[void]$binDiffRuns.Add($bindiff);$existing.OutputPaths+=@($bindiff.RawOutputs|ForEach-Object {$_.Path})
                            }
                            if($functionPairs.Count){$allMatches=@($functionPairs|ForEach-Object {$_.FunctionMatches});$changedFunctions=@($functionPairs|ForEach-Object {$_.ChangedFunctions});$addedFunctions=@($functionPairs|ForEach-Object {$_.AddedFunctions});$removedFunctions=@($functionPairs|ForEach-Object {$_.RemovedFunctions});$matchedCount=0;foreach($bd in $functionPairs){$matchedCount+=[int]$bd.ParsedResult.MatchedFunctionCount};$stageResult|Add-Member -NotePropertyName FunctionComparison -NotePropertyValue ([pscustomobject]@{MatchedFunctionCount=$matchedCount;ChangedFunctions=$changedFunctions;AddedFunctions=$addedFunctions;RemovedFunctions=$removedFunctions;Matches=$allMatches;ChangedFunctionCount=$changedFunctions.Count;BinDiffUsed=$true;ConfidenceSource='BinDiff SQLite function.confidence column; native values preserved';Pairs=@($functionPairs);Status='completed'}) -Force}
                        }
                        foreach($pair in @($cfg.binExportPairs)){
                            $baseProperty=$pair.PSObject.Properties['BaselineBinExport'];$targetProperty=$pair.PSObject.Properties['TargetBinExport']
                            if(-not $baseProperty -or -not $targetProperty){throw 'Each binExportPairs entry requires BaselineBinExport and TargetBinExport paths.'}
                            $baseExport=[string]$baseProperty.Value;$targetExport=[string]$targetProperty.Value
                            if(-not [IO.Path]::IsPathRooted($baseExport)){$baseExport=Join-Path $rootBase $baseExport};if(-not [IO.Path]::IsPathRooted($targetExport)){$targetExport=Join-Path $rootBase $targetExport}
                            $binDiffOut=Join-Path $runDir ('bindiff-'+[guid]::NewGuid().ToString('N'))
                            $bindiff=Invoke-IosBinDiff -Config $cfg -BaselineBinExport $baseExport -TargetBinExport $targetExport -OutputDirectory $binDiffOut -BinDiffCommand ([string]$cfg.toolPaths.binDiff) -PythonCommand ([string]$cfg.toolPaths.python) -AllowFirmwareAccess -AuthorizedResearch -TimeoutSeconds $toolTimeout
                            $bindiff=Assert-IosBinDiffCompleted -Result $bindiff;[void]$binDiffRuns.Add($bindiff);$existing.OutputPaths+=@($bindiff.RawOutputs|ForEach-Object {$_.Path})
                        }
                        if($binDiffRuns.Count -and -not $stageResult.FunctionComparison){$matches=New-Object System.Collections.ArrayList;$changedFunctions=New-Object System.Collections.ArrayList;$addedFunctions=New-Object System.Collections.ArrayList;$removedFunctions=New-Object System.Collections.ArrayList;$matchCount=0;foreach($bd in $binDiffRuns){$matchCount+=[int]$bd.ParsedResult.MatchedFunctionCount;$binaryName=if($bd.ParsedResult.TargetFile.exefilename){[string]$bd.ParsedResult.TargetFile.exefilename}else{[string]$bd.ParsedResult.TargetFile.filename};foreach($setName in @('FunctionMatches','ChangedFunctions','AddedFunctions','RemovedFunctions')){foreach($function in @($bd.$setName)){if(-not $function.PSObject.Properties['Name']){$functionName=if($function.TargetName){$function.TargetName}else{$function.BaselineName};$function|Add-Member -NotePropertyName Name -NotePropertyValue $functionName -Force};$function|Add-Member -NotePropertyName BinaryName -NotePropertyValue $binaryName -Force;$function|Add-Member -NotePropertyName BaselinePath -NotePropertyValue $bd.BaselineBinExport -Force;$function|Add-Member -NotePropertyName TargetPath -NotePropertyValue $bd.TargetBinExport -Force;if($setName -eq 'FunctionMatches'){[void]$matches.Add($function)}elseif($setName -eq 'ChangedFunctions'){[void]$changedFunctions.Add($function)}elseif($setName -eq 'AddedFunctions'){[void]$addedFunctions.Add($function)}else{[void]$removedFunctions.Add($function)}}}};$stageResult|Add-Member -NotePropertyName FunctionComparison -NotePropertyValue ([pscustomobject]@{MatchedFunctionCount=$matchCount;ChangedFunctions=@($changedFunctions);AddedFunctions=@($addedFunctions);RemovedFunctions=@($removedFunctions);Matches=@($matches);ChangedFunctionCount=$changedFunctions.Count;BinDiffUsed=$true;ConfidenceSource='BinDiff SQLite function.confidence column; native values preserved';Pairs=@($binDiffRuns);Status='completed'}) -Force}
                        if($binDiffRuns.Count){$stageResult|Add-Member -NotePropertyName BinDiffRuns -NotePropertyValue @($binDiffRuns) -Force}
                        $stageResult|Add-Member -NotePropertyName BaselineBuild -NotePropertyValue $BaselineBuild -Force;$stageResult|Add-Member -NotePropertyName TargetBuild -NotePropertyValue $Build -Force
                        $path=Get-IosUniqueRunArtifactPath -RunDirectory $runDir -Name 'binary-diff-stage-result.json'
                        $null=Write-IosUniqueArtifact -Directory $runDir -Name ([IO.Path]::GetFileName($path)) -Value $stageResult;$existing.OutputPaths+=@($path)
                    }
                    'candidates' {$diff=Get-IosPriorStageResult -Record $record -Name 'binary-diff';if(-not $diff){throw 'Run binary-diff before candidates.'};$stageResult=Get-IosSecurityCandidates -BinaryDiff $diff -BaselineVersion $BaselineVersion -BaselineBuild $BaselineBuild -TargetVersion $TargetVersion -TargetBuild $Build;$path=Get-IosUniqueRunArtifactPath -RunDirectory $runDir -Name 'candidate-stage-result.json';$null=Write-IosUniqueArtifact -Directory $runDir -Name ([IO.Path]::GetFileName($path)) -Value $stageResult;$existing.OutputPaths=@($path)}
                    'analyze-metadata' {$inv=Get-IosPriorStageResult -Record $record -Name 'inventory';if(-not $inv){throw "Stage 'analyze-metadata' requires a successful 'inventory' stage in this run."};$stageResult=[pscustomobject]@{Status='completed';FirmwareInventoryPath=$inv.ManifestPath;Analysis='Firmware metadata only; no binary findings generated.'}}
                    'report' {
                        $artifactMap=@{};$artifactReferences=@{}
                        foreach($s in @($record.Stages)){
                            if($s.Name -in @('inventory','macho','shared-cache','binary-diff','candidates')){
                                $key=switch($s.Name){'inventory'{'firmware-inventory'}'macho'{'macho-inventory'}'shared-cache'{'shared-cache-inventory'}'binary-diff'{'binary-diff-summary'}'candidates'{'candidate-ranking'}}
                                $summary=if($s.ResultSummary){$s.ResultSummary}else{Get-IosStageResultSummary -StageName $s.Name -Result $s.Result}
                                if($summary){$artifactMap[$key]=$summary}
                                if($s.ResultPath -and (Test-Path -LiteralPath $s.ResultPath -PathType Leaf)){$artifactReferences[$key]=Get-IosArtifactFileReference -Path $s.ResultPath -Kind 'stage-result' -Metadata @{Stage=$s.Name} -IncludeHash}
                            }
                        }
                        $reportPlan=Get-IosResearchReportPlan -RunDirectory $runDir
                        $existing.Status='completed';$existing.ExitCode=0;$existing.CompletedAt=[DateTime]::UtcNow.ToString('o');$existing.OutputPaths=@($reportPlan.Values)
                        $record.Status=Get-IosFinalRunStatus -Record $record -Config $cfg;$record.CompletedAt=$existing.CompletedAt;$record.ReportManifestPath=$reportPlan['run-manifest.json']
                        $context=[pscustomobject]@{RunId=$record.RunId;DeviceIdentifier=$Product;BaselineFirmwareVersion=$BaselineVersion;BaselineBuild=$BaselineBuild;TargetFirmwareVersion=$TargetVersion;TargetBuild=$Build;InputHashes=$inputHashes;ToolVersions=$toolVersions;Status=$record.Status;Mode='research';Stages=$record.Stages;CreatedAt=$record.CreatedAt;CompletedAt=$record.CompletedAt}
                        $reports=New-IosResearchReports -RunDirectory $runDir -Context $context -Artifacts $artifactMap -ArtifactReferences $artifactReferences -Plan $reportPlan -DeferManifest
                        $stageResult=[pscustomobject]@{Status='completed';ReportPaths=$reports.ReportPaths;ManifestPath=$reports.ManifestPath};$existing.OutputPaths=@($reports.ReportPaths.Values);$record.ReportPath=$reports.MarkdownPath;$reportManifestPath=$reports.ManifestPath
                    }
                    default {throw "Stage '$name' has no research implementation."}
                }
                $existing.Details='Research stage completed with the documented inputs and limitations.'
            }
            $existing.Result=$stageResult;$existing.ResultSummary=Get-IosStageResultSummary -StageName $name -Result $stageResult;$existing.ExitCode=0;$existing.Status=if($Mock -and $name -ne 'environment'){'mocked'}else{'completed'};$existing.CompletedAt=[DateTime]::UtcNow.ToString('o')
            if($name -ne 'report'){Set-IosStageResultArtifact -StageName $name -StageResult $stageResult -StageRecord $existing -RunDirectory $runDir}
            Write-IosJsonAtomic -Value $record -Path (Join-Path $runDir 'run.json')
            $stageLog=[pscustomobject]@{Timestamp=$existing.CompletedAt;RunId=$record.RunId;Event='stage_finished';Stage=$name;Status=$existing.Status;ExitCode=$existing.ExitCode;Mock=[bool]$Mock;OutputPaths=$existing.OutputPaths};$stageLog|ConvertTo-Json -Compress|Add-Content -LiteralPath (Join-Path $runDir 'pipeline.log') -Encoding UTF8
        }catch{$wasInterrupted=$_.Exception.Message -match '(?i)interrupted|timed out|timeout';$existing.Status=if($wasInterrupted){'interrupted'}else{'failed'};$existing.ExitCode=if($wasInterrupted){124}else{1};$existing.CompletedAt=[DateTime]::UtcNow.ToString('o');$existing.Details=$_.Exception.Message;$existing.Error=$_.Exception.Message;$existing.Result=[pscustomobject]@{Status=$existing.Status;Error=$_.Exception.Message};$existing.ResultSummary=Get-IosStageResultSummary -StageName $name -Result $existing.Result;$existing.ResultPath=$null;$record.Status=$existing.Status;Write-IosJsonAtomic -Value $record -Path (Join-Path $runDir 'run.json');$failureLog=[pscustomobject]@{Timestamp=$existing.CompletedAt;RunId=$record.RunId;Event=if($wasInterrupted){'stage_interrupted'}else{'stage_failed'};Stage=$name;Status=$existing.Status;ExitCode=$existing.ExitCode;Error=$_.Exception.Message};$failureLog|ConvertTo-Json -Compress|Add-Content -LiteralPath (Join-Path $runDir 'pipeline.log') -Encoding UTF8;throw}
    }
    $record.OutputPaths=@(@($record.Stages|ForEach-Object {$_.OutputPaths})|Where-Object {$_}|Select-Object -Unique)
    $record.Status=Get-IosFinalRunStatus -Record $record -Config $cfg;$record.CompletedAt=[DateTime]::UtcNow.ToString('o')
    $stageSeconds=0.0;foreach($stageRecord in @($record.Stages)){if($stageRecord.StartedAt -and $stageRecord.CompletedAt){try{$stageSeconds+=([DateTime]::Parse($stageRecord.CompletedAt).ToUniversalTime()-[DateTime]::Parse($stageRecord.StartedAt).ToUniversalTime()).TotalSeconds}catch{}}}
    $record.DurationSeconds=$stageSeconds;$record.ElapsedSeconds=$null
    if($record.CreatedAt){try{$record.ElapsedSeconds=([DateTime]::Parse($record.CompletedAt).ToUniversalTime()-[DateTime]::Parse($record.CreatedAt).ToUniversalTime()).TotalSeconds}catch{}}
    Write-IosJsonAtomic -Value $record -Path (Join-Path $runDir 'run.json')

    $reportStage=@($record.Stages|Where-Object {$_.Name -eq 'report' -and $_.Status -in @('completed','mocked')}|Select-Object -Last 1)
    if($reportStage.Count -and $record.ReportManifestPath){
        if(-not(Test-Path -LiteralPath $record.ReportManifestPath -PathType Leaf)){
            $refs=New-Object System.Collections.ArrayList
            foreach($stageRecord in @($record.Stages)){
                if($stageRecord.ResultPath -and (Test-Path -LiteralPath $stageRecord.ResultPath -PathType Leaf)){
                    [void]$refs.Add((Get-IosArtifactFileReference -Path $stageRecord.ResultPath -Kind 'stage-result' -Metadata @{Stage=$stageRecord.Name} -IncludeHash))
                }
            }
            foreach($path in @($reportStage[0].OutputPaths)){
                if($path -ne $record.ReportManifestPath -and (Test-Path -LiteralPath $path -PathType Leaf)){
                    [void]$refs.Add((Get-IosReportFileReference -Kind 'report-output' -Path $path -Metadata @{Stage='report'} -IncludeHash))
                }
            }
            $context=[pscustomobject]@{RunId=$record.RunId;Status=$record.Status;Mode=$record.Mode;DeviceIdentifier=$record.DeviceIdentifier;BaselineFirmwareVersion=$record.BaselineVersion;BaselineBuild=$record.BaselineBuild;TargetFirmwareVersion=$record.TargetVersion;TargetBuild=$record.Build;CreatedAt=$record.CreatedAt;CompletedAt=$record.CompletedAt;DurationSeconds=$record.DurationSeconds;ElapsedSeconds=$record.ElapsedSeconds;InputHashes=$record.InputHashes;ToolVersions=$record.ToolVersions;Stages=$record.Stages}
            $manifest=New-IosCompactRunManifest -Context $context -ArtifactReferences @($refs) -ReportManifestPath $record.ReportManifestPath
            Write-IosUniqueArtifact -Directory $runDir -Path $record.ReportManifestPath -Value $manifest | Out-Null
            $manifestReference=Get-IosReportFileReference -Kind 'run-manifest' -Path $record.ReportManifestPath -Metadata @{Stage='report'} -IncludeHash
            $refs.Add($manifestReference)|Out-Null;$record.ArtifactReferences=@($refs)
            Write-IosJsonAtomic -Value $record -Path (Join-Path $runDir 'run.json')
        }
    }
    $line=[pscustomobject]@{Timestamp=[DateTime]::UtcNow.ToString('o');RunId=$record.RunId;Event='run_finished';Status=$record.Status;Mock=[bool]$Mock};$line|ConvertTo-Json -Compress|Add-Content -LiteralPath (Join-Path $runDir 'pipeline.log') -Encoding UTF8
    return $record
}

function Assert-IosDownloadApproval {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Sha256,[switch]$AllowDownload,[switch]$AuthorizedResearch)
    if (-not $AllowDownload) { throw 'Download blocked: explicit -AllowDownload is required.' }
    $policyProperty = $Config.PSObject.Properties['approvalPolicy']
    $policy = if ($policyProperty -and $policyProperty.Value) { $policyProperty.Value } else { $Config }
    $authorizedProperty = $policy.PSObject.Properties['authorizedResearch']
    $hostsProperty = $policy.PSObject.Properties['approvedHosts']
    if (-not $AuthorizedResearch -or -not $authorizedProperty -or -not $authorizedProperty.Value) { throw 'Download blocked: explicit authorization and authorizedResearch=true are required.' }
    if ($Sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Download blocked: expected SHA-256 must be 64 hexadecimal characters.' }
    $uri = $null
    if (-not [Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or ($uri.Port -ne 443)) { throw 'Download blocked: only absolute HTTPS URLs on port 443 without embedded credentials are accepted.' }
    $hostName = $uri.DnsSafeHost.ToLowerInvariant()
    if (-not $hostsProperty -or @($hostsProperty.Value | ForEach-Object { ([string]$_).ToLowerInvariant() }) -notcontains $hostName) { throw 'Download blocked: source host is not on the approvedHosts allowlist.' }
    return $uri
}

function Invoke-IosApprovedDownload {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Sha256,[Parameter(Mandatory=$true)][string]$Destination,[switch]$AllowDownload,[switch]$AuthorizedResearch)
    $null = Assert-IosDownloadApproval -Config $Config -Url $Url -Sha256 $Sha256 -AllowDownload:$AllowDownload -AuthorizedResearch:$AuthorizedResearch
    if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'Download blocked: destination is required.' }
    if (Test-Path -LiteralPath $Destination) { throw 'Download blocked: destination already exists; refusing to overwrite.' }
    throw 'Network download adapter is not implemented in this mock release; no request was made.'
}

function Invoke-IosApprovedExtraction {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$InputPath,[Parameter(Mandatory=$true)][string]$Destination,[switch]$AllowExtraction,[switch]$AuthorizedResearch)
    if (-not $AllowExtraction -or -not $AuthorizedResearch) { throw 'Extraction blocked: explicit -AllowExtraction and -AuthorizedResearch are required.' }
    if ([string]::IsNullOrWhiteSpace($InputPath) -or [string]::IsNullOrWhiteSpace($Destination)) { throw 'Extraction blocked: input and destination are required.' }
    if (Test-Path -LiteralPath $Destination) { throw 'Extraction blocked: destination already exists; refusing to overwrite.' }
    throw 'Firmware extraction adapter is not implemented in this mock release; no files were extracted.'
}

Export-ModuleMember -Function Test-IosResearchConfig,Get-IosResearchPlan,Invoke-IosResearchPipeline,Assert-IosDownloadApproval,Invoke-IosApprovedDownload,Invoke-IosApprovedExtraction,Get-IosEnvironmentPreflight,Get-IosEnvironmentInventory,Get-IosFirmwareInventory,Get-IosFirmwareMetadata,Save-IosFirmwareManifest,Get-IosIpswCapabilities,New-IosIpswExtractArguments,Invoke-IosFirmwareExtraction,Find-IosDyldSharedCaches,Get-IosDylibRecords,Select-IosDylibImages,Get-IosIpswDyldCapabilities,New-IosIpswDylibExtractArguments,Invoke-IosDylibExtraction,Get-IosMachOInventory,Compare-IosBinaryInventories,Compare-IosFunctionInventories,Read-IosBinDiffDatabase,Invoke-IosBinDiff,Assert-IosBinDiffCompleted,Invoke-IosGhidraFunctionInventory,Get-IosSecurityCandidates,New-IosResearchReports,Get-IosRunSummary,Save-IosRunState
