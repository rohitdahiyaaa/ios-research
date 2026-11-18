# iOS Research Pipeline

Windows PowerShell 5.1 orchestration for authorized, local iOS firmware research. The project has offline mock execution, local IPSW/OTA inventory, explicitly gated `ipsw` extraction, dyld cache and per-image inventory/extraction, Mach-O inventory, Ghidra headless function export, BinExport generation, SQLite BinDiff result parsing, heuristic candidate ranking, persistent run state, and structured reports.

The project does not download firmware. Acquisition remains disabled. Firmware identity is checked against the supplied device/build/version labels where local metadata exposes those fields; no Apple version/build pairing is assumed valid without that observed metadata. A changed-function candidate is an observation, never a vulnerability finding.

## Offline mock workflow

Run from this project root in Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-MockTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-IOSResearch.ps1 `
  -Device 'iPhone15,2' `
  -BaselineVersion '17.0' -BaselineBuild '21A329' `
  -TargetVersion '17.1' -TargetBuild '21B74' `
  -Mock
```

The mock makes no network requests and does not open firmware inputs. It records simulated stages as `mocked`; environment inventory is a real local probe. Runs are written beneath `outputWorkspace`, relative to the configuration file directory. With the checked-in config, each run writes to `config/data/runs/<run-id>`. Add `-WhatIf` to preview without creating a run. Use `-Stage validate,environment,report` to choose independent stages. Use `-ResumeRunId <id>` to resume the same run; successfully completed stages are reused only while their recorded inputs and config remain unchanged.

## Local firmware workflow (not run during development)

Set `inputFirmwarePaths` to locally supplied firmware files. For two images, use objects with `Role` (`baseline` or `target`), `Path`, and optional `ExpectedSHA256`. Configure `sourceType`, builds, tools, workspace, resource limits, and `approvalPolicy.authorizedResearch=true` after confirming the work is authorized. First inventory local file metadata:

```powershell
.\Start-IOSResearch.ps1 -Device 'iPhone15,2' -BaselineBuild '21A329' -TargetBuild '21B74' `
  -Stage inventory -AllowFirmwareAccess -AuthorizedResearch
```

Extraction requires a separate explicit approval and confirmation. Save the returned `RunId`; later stages must resume that same run to consume the extraction result:

```powershell
.\Start-IOSResearch.ps1 -Device 'iPhone15,2' -BaselineBuild '21A329' -TargetBuild '21B74' `
  -Stage extract -AllowFirmwareAccess -AllowExtraction -AuthorizedResearch
```

These commands were not run on real firmware for this delivery. Extraction creates a fresh output directory per input, checks live `ipsw` help/version, records output and hashes, and can resume a compatible interrupted attempt. It refuses to overwrite existing outputs. Resume the `extract` run with `-ResumeRunId <id> -Stage shared-cache,macho,binary-diff,candidates,report` to pass completed extraction outputs to later stages. Completed extraction results retain baseline/target roles. The `macho` stage discovers binaries from completed per-image shared-cache extraction results, or falls back to completed firmware extraction directories; `analysisInputPaths` remains available for caller-supplied binary roots/files. Two untagged paths map to baseline then target; role-tagged entries are preferred.

The `shared-cache` stage inventories caches by configured architecture and component. Individual image extraction is off by default and requires `-AllowExtraction -AllowFirmwareAccess -AuthorizedResearch`, plus `approvalPolicy.authorizedResearch=true` and a positive `resourceLimits.maxDylibExtractions`. `-AnalyzeFunctions` runs Ghidra headless on changed Mach-O binaries, exports functions and BinExport files, then runs BinDiff and parses its SQLite database. Caller-supplied BinExport pairs in `binExportPairs` use the same parser.

## Reports

The report stage emits `firmware-inventory.json`, `macho-inventory.json`, `shared-cache-inventory.json`, `binary-diff-summary.json`, `candidate-ranking.json`, `research-report.md`, and `run-manifest.json` as applicable. Reports separate observed facts, automated observations, heuristic rankings, and manual review requirements. Artifacts use create-new semantics and unique names; prior run records and artifacts are retained.

## Implementation limits

- No automatic download functionality exists; the legacy download adapter remains fail-closed.
- `ipsw` extraction and dyld image extraction use the installed CLI commands verified by the environment adapter. Real extraction was intentionally not executed during development.
- Mach-O parser handles thin/fat Mach-O headers, UUID, linked libraries, and external symbols; it does not fully decode all load commands or symbol semantics.
- Ghidra headless and the installed, version-matched BinExport script were executed on a Windows system DLL sample. The function exporter records addresses, names, sizes, and instruction-byte hashes. No iOS firmware binary was analyzed.
- BinDiff's SQLite database parser preserves native function similarity and confidence fields and emits matched, changed-by-similarity, added, and removed records. The parser was exercised on a synthetic database and on the generated sample-binary database. The identical sample pair had no changed functions; this does not validate cross-version firmware comparisons.
- Python's standard-library SQLite support is required for BinDiff result parsing. Python and WSL remain optional for the PowerShell core.
- Matching and candidate scores are heuristics. Rebasing, relocation, stripped symbols, architecture differences, and incomplete extraction can affect comparisons.
- Python and WSL are optional inventory probes; the PowerShell core does not depend on them.

See [architecture](docs/architecture.md), [execution guide](docs/execution-guide.md), [troubleshooting](docs/troubleshooting.md), and [methodology](docs/research-methodology.md).
