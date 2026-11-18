Set-StrictMode -Version 2.0

$script:KnownStages = @('validate','environment','inventory','extract','shared-cache','macho','binary-diff','candidates','report','analyze-metadata')

function Get-IosPipelineConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ConfigPath)
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Config file not found: $ConfigPath" }
    try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON config: $($_.Exception.Message)" }
    if ($cfg.schemaVersion -ne 1) { throw 'Unsupported config schemaVersion; expected 1.' }
    $null = Test-IosPipelineConfigDocument -Config $cfg
    return $cfg
}

function Test-IosPipelineConfigDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config)
    foreach ($field in @('deviceIdentifier','baselineFirmwareVersion','baselineBuild','targetFirmwareVersion','targetBuild','sourceType','inputFirmwarePaths','outputWorkspace','toolPaths','stages','resourceLimits','approvalPolicy')) {
        if ($null -eq $Config.PSObject.Properties[$field]) { throw "Config is missing required field: $field" }
    }
    if ($Config.sourceType -notin @('IPSW','OTA')) { throw 'sourceType must be IPSW or OTA.' }
    if ($Config.stages -isnot [System.Array] -or $Config.stages.Count -eq 0) { throw 'Config stages must be a non-empty array.' }
    if ($Config.inputFirmwarePaths -isnot [System.Array]) { throw 'inputFirmwarePaths must be an array.' }
    if ($null -eq $Config.approvalPolicy.PSObject.Properties['authorizedResearch'] -or $null -eq $Config.approvalPolicy.PSObject.Properties['approvedHosts']) { throw 'approvalPolicy must define authorizedResearch and approvedHosts.' }
    if ($null -eq $Config.resourceLimits.PSObject.Properties['maxRunMinutes'] -or [int]$Config.resourceLimits.maxRunMinutes -lt 1) { throw 'resourceLimits.maxRunMinutes must be a positive integer.' }
    foreach ($stage in @($Config.stages)) { if ([string]::IsNullOrWhiteSpace([string]$stage)) { throw 'Stage names cannot be empty.' }; if ($stage -notin $script:KnownStages) { throw "Unsupported stage: $stage" } }
    if (@($Config.stages | Select-Object -Unique).Count -ne @($Config.stages).Count) { throw 'Config stages cannot contain duplicates.' }
    if ([string]::IsNullOrWhiteSpace([string]$Config.outputWorkspace)) { throw 'outputWorkspace cannot be empty.' }
    if ($Config.resourceLimits.minimumFreeBytes -and [long]$Config.resourceLimits.minimumFreeBytes -lt 0) { throw 'minimumFreeBytes cannot be negative.' }
    return [pscustomobject]@{ Valid=$true; SchemaVersion=$Config.schemaVersion; StageCount=$Config.stages.Count; NetworkEnabled=$false; ExtractionEnabled=($Config.stages -contains 'extract') }
}

function Assert-IosResearchAuthorization {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Config,[switch]$AuthorizedResearch,[switch]$AllowFirmwareAccess,[switch]$AllowExtraction)
    if (-not $AuthorizedResearch -or -not $Config.approvalPolicy.authorizedResearch) { throw 'Firmware operation blocked: explicit -AuthorizedResearch and approvalPolicy.authorizedResearch=true are required.' }
    if (-not $AllowFirmwareAccess -and -not $AllowExtraction) { throw 'Firmware operation blocked: pass -AllowFirmwareAccess for inventory or -AllowExtraction for extraction.' }
    if ($AllowExtraction -and -not $AllowFirmwareAccess -and -not $AuthorizedResearch) { throw 'Extraction requires explicit authorized research confirmation.' }
    return $true
}

Export-ModuleMember -Function Get-IosPipelineConfig,Test-IosPipelineConfigDocument,Assert-IosResearchAuthorization
