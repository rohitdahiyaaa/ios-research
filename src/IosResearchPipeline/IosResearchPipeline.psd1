@{
    RootModule = 'IosResearchPipeline.psm1'
    ModuleVersion = '2.0.0'
    GUID = '74007df3-807c-438d-b9f9-b1edb1ff30a5'
    Author = 'iOS Research Pipeline'
    Description = 'Approval-gated local iOS firmware inventory and binary analysis pipeline for Windows PowerShell 5.1.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Test-IosResearchConfig','Get-IosResearchPlan','Invoke-IosResearchPipeline','Assert-IosDownloadApproval','Invoke-IosApprovedDownload','Invoke-IosApprovedExtraction','Get-IosEnvironmentPreflight','Get-IosEnvironmentInventory','Get-IosFirmwareInventory','Get-IosFirmwareMetadata','Save-IosFirmwareManifest','Get-IosIpswCapabilities','New-IosIpswExtractArguments','Invoke-IosFirmwareExtraction','Find-IosDyldSharedCaches','Get-IosSharedCacheInventory','Get-IosDylibRecords','Select-IosDylibImages','Get-IosIpswDyldCapabilities','New-IosIpswDylibExtractArguments','Invoke-IosDylibExtraction','Get-IosMachOInventory','Compare-IosBinaryInventories','Compare-IosFunctionInventories','Read-IosBinDiffDatabase','Invoke-IosBinDiff','Assert-IosBinDiffCompleted','Invoke-IosGhidraFunctionInventory','Get-IosSecurityCandidates','New-IosResearchReports','Get-IosRunSummary','Save-IosRunState')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
