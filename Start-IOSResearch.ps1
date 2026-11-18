[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Low')]
param(
    [string]$ConfigPath,
    [string]$Device,
    [string]$BaselineVersion,
    [string]$BaselineBuild,
    [string]$TargetVersion,
    [string]$TargetBuild,
    [string[]]$Stage,
    [string]$ResumeRunId,
    [switch]$Mock,
    [switch]$AllowFirmwareAccess,
    [switch]$AllowExtraction,
    [switch]$AuthorizedResearch,
    [switch]$AnalyzeFunctions
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $scriptRoot 'config\pipeline.json' }
$modulePath = Join-Path $scriptRoot 'src\IosResearchPipeline\IosResearchPipeline.psd1'
Import-Module $modulePath -Force -ErrorAction Stop

$config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$validation = Test-IosResearchConfig -ConfigPath $ConfigPath
if (-not $Device) { $Device = [string]$config.deviceIdentifier }
if (-not $BaselineVersion) { $BaselineVersion = [string]$config.baselineFirmwareVersion }
if (-not $BaselineBuild) { $BaselineBuild = [string]$config.baselineBuild }
if (-not $TargetVersion) { $TargetVersion = [string]$config.targetFirmwareVersion }
if (-not $TargetBuild) { $TargetBuild = [string]$config.targetBuild }
if ([string]::IsNullOrWhiteSpace($Device) -or [string]::IsNullOrWhiteSpace($BaselineBuild) -or [string]::IsNullOrWhiteSpace($TargetBuild)) {
    throw 'Device, baseline build, and target build are required through parameters or config. Version/build validity is not inferred or verified.'
}

if ($WhatIfPreference) {
    $preview = Invoke-IosResearchPipeline -ConfigPath $ConfigPath -Product $Device -Build $TargetBuild -BaselineBuild $BaselineBuild -BaselineVersion $BaselineVersion -TargetVersion $TargetVersion -Stage $Stage -ResumeRunId $ResumeRunId -Mock:$Mock -AllowFirmwareAccess:$AllowFirmwareAccess -AllowExtraction:$AllowExtraction -AuthorizedResearch:$AuthorizedResearch -AnalyzeFunctions:$AnalyzeFunctions -WhatIf
    [pscustomobject]@{ Validation=$validation; Plan=$preview }
    return
}

$run = Invoke-IosResearchPipeline -ConfigPath $ConfigPath -Product $Device -Build $TargetBuild -BaselineBuild $BaselineBuild -BaselineVersion $BaselineVersion -TargetVersion $TargetVersion -Stage $Stage -ResumeRunId $ResumeRunId -Mock:$Mock -AllowFirmwareAccess:$AllowFirmwareAccess -AllowExtraction:$AllowExtraction -AuthorizedResearch:$AuthorizedResearch -AnalyzeFunctions:$AnalyzeFunctions
if ($run.Status -ne 'whatif' -and $run.RunId -ne 'not-created') {
    (Get-IosRunSummary -State $run) | ConvertTo-Json -Depth 12
} else {
    [pscustomobject]@{ Validation=$validation; Preflight=$preflight; Plan=$run }
}
