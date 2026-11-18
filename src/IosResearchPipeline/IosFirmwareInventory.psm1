Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosResearchConfig.psm1') -Force

function Get-IosPlistMetadataFromStream {
    param([Parameter(Mandatory=$true)][System.IO.Stream]$Stream)
    $doc=New-Object System.Xml.XmlDocument
    $doc.XmlResolver=$null
    $settings=New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing=[System.Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=67108864
    $xmlReader=[System.Xml.XmlReader]::Create($Stream,$settings)
    try{$doc.Load($xmlReader)}finally{$xmlReader.Dispose()}
    $values=@{ProductVersion=$null;ProductBuildVersion=$null;ProductType=$null;DeviceClass=$null;SupportedProductTypes=$null}
    foreach($key in @('ProductVersion','ProductBuildVersion','ProductType','DeviceClass','SupportedProductTypes')) {
        $nodes=@($doc.SelectNodes("//key[.='$key']"))
        foreach($node in $nodes) {
            $next=$node.NextSibling
            while($next -and $next.NodeType -ne [System.Xml.XmlNodeType]::Element){$next=$next.NextSibling}
            if($next) {
                if($next.LocalName -eq 'array') { $values[$key]=@($next.ChildNodes | Where-Object {$_.NodeType -eq [System.Xml.XmlNodeType]::Element} | ForEach-Object {$_.InnerText}) }
                else { $values[$key]=$next.InnerText }
                break
            }
        }
    }
    return $values
}

function Get-IosFirmwareMetadata {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path,[string]$IpswCommand='ipsw')
    $stream=$null; $archive=$null; $entry=$null; $metadata=@{ProductVersion=$null;ProductBuildVersion=$null;ProductType=$null;DeviceClass=$null;SupportedProductTypes=$null}
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $archive=[System.IO.Compression.ZipFile]::OpenRead($Path)
        $entry=$archive.Entries | Where-Object { $_.FullName -match '(^|/)BuildManifest\.plist$' } | Select-Object -First 1
        if($entry -and $entry.Length -gt 67108864){throw 'BuildManifest.plist exceeds the 64 MiB metadata parsing limit.'}
        if($entry) { $stream=$entry.Open(); $metadata=Get-IosPlistMetadataFromStream -Stream $stream; $stream.Dispose(); $stream=$null }
    } catch { $metadata=@{ProductVersion=$null;ProductBuildVersion=$null;ProductType=$null;DeviceClass=$null;SupportedProductTypes=$null} }
    finally { if($stream){$stream.Dispose()}; if($archive){$archive.Dispose()} }
    if(-not $metadata.ProductVersion -or -not $metadata.ProductBuildVersion) {
        $command=Get-Command $IpswCommand -ErrorAction SilentlyContinue | Select-Object -First 1
        if($command) {
            try {
                $raw=@(& $command.Source info --json $Path 2>&1)
                if($LASTEXITCODE -eq 0) {
                    $text=(@($raw | ForEach-Object {[string]$_}) -join "`n")
                    $json=$text | ConvertFrom-Json -ErrorAction Stop
                    $queue=New-Object System.Collections.Queue; $queue.Enqueue($json)
                    while($queue.Count -gt 0) {
                        $item=$queue.Dequeue()
                        if($item -is [System.Array]) { foreach($x in $item){$queue.Enqueue($x)}; continue }
                        if($item -is [System.Management.Automation.PSCustomObject]) {
                            foreach($prop in $item.PSObject.Properties) {
                                if($prop.Name -in @('ProductVersion','version') -and -not $metadata.ProductVersion){$metadata.ProductVersion=[string]$prop.Value}
                                elseif($prop.Name -in @('ProductBuildVersion','build') -and -not $metadata.ProductBuildVersion){$metadata.ProductBuildVersion=[string]$prop.Value}
                                elseif($prop.Name -in @('ProductType','DeviceClass','SupportedProductTypes') -and -not $metadata[$prop.Name]){$metadata[$prop.Name]=$prop.Value}
                                elseif($prop.Name -eq 'product' -and $item.PSObject.Properties['name']){$metadata.SupportedProductTypes=@($metadata.SupportedProductTypes)+[string]$prop.Value}
                                if($null -ne $prop.Value -and ($prop.Value -is [System.Management.Automation.PSCustomObject] -or $prop.Value -is [System.Array])){$queue.Enqueue($prop.Value)}
                            }
                        }
                    }
                }
            } catch { }
        }
    }
    if(-not $metadata.ProductVersion -or -not $metadata.ProductBuildVersion) { throw "Firmware metadata is missing ProductVersion or ProductBuildVersion: $Path" }
    $devices=@()
    if($metadata.ProductType){$devices+=@($metadata.ProductType)}
    if($metadata.SupportedProductTypes){$devices+=@($metadata.SupportedProductTypes)}
    return [pscustomobject]@{ FirmwareVersion=[string]$metadata.ProductVersion; Build=[string]$metadata.ProductBuildVersion; DeviceIdentifiers=@($devices | Where-Object {$_} | Select-Object -Unique); MetadataSource=if($entry){'BuildManifest.plist'}else{'ipsw info --json'} }
}

function Get-IosExpectedHash {
    param($ExpectedHashes,[string]$Path)
    if($null -eq $ExpectedHashes){return $null}
    if($ExpectedHashes -is [System.Collections.IDictionary]) {
        if($ExpectedHashes.Contains($Path)){return [string]$ExpectedHashes[$Path]}
        $name=[IO.Path]::GetFileName($Path); if($ExpectedHashes.Contains($name)){return [string]$ExpectedHashes[$name]}
    }
    return $null
}

function Save-IosFirmwareManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Manifest,[Parameter(Mandatory=$true)][string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    $parent=Split-Path -Parent $full
    if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw "Manifest directory does not exist: $parent"}
    $json=$Manifest | ConvertTo-Json -Depth 15
    $bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $fs=$null
    try{$fs=New-Object IO.FileStream($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$fs.Write($bytes,0,$bytes.Length)}
    catch{throw "Cannot write firmware manifest without overwriting existing data: $full. $($_.Exception.Message)"}
    finally{if($fs){$fs.Dispose()}}
    return $full
}

function Get-IosFirmwareInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$Config,
        [string[]]$InputPaths,
        [System.Collections.IDictionary]$ExpectedHashes,
        [string]$IpswCommand='ipsw',
        [switch]$AllowFirmwareAccess,
        [switch]$AuthorizedResearch,
        [string]$ManifestPath
    )
    $null=Assert-IosResearchAuthorization -Config $Config -AuthorizedResearch:$AuthorizedResearch -AllowFirmwareAccess:$AllowFirmwareAccess
    if(-not $InputPaths){$InputPaths=@($Config.inputFirmwarePaths | ForEach-Object {if($_ -is [string]){$_}else{[string]$_.Path}})}
    if(-not $InputPaths -or $InputPaths.Count -eq 0){throw 'No local firmware input paths are configured.'}
    $records=New-Object System.Collections.ArrayList
    $seenPaths=@{}; $seenHashes=@{}
    foreach($rawPath in $InputPaths) {
        if([string]::IsNullOrWhiteSpace($rawPath)){throw 'Firmware input path cannot be empty.'}
        $path=[IO.Path]::GetFullPath($rawPath)
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Firmware input does not exist: $path"}
        $extension=[IO.Path]::GetExtension($path).ToLowerInvariant()
        if($extension -notin @('.ipsw','.ota')){throw "Unsupported firmware source extension '$extension': $path"}
        if($Config.sourceType -eq 'IPSW' -and $extension -ne '.ipsw'){throw "Configured sourceType is IPSW but input is ${extension}: $path"}
        if($Config.sourceType -eq 'OTA' -and $extension -ne '.ota'){throw "Configured sourceType is OTA but input is ${extension}: $path"}
        $info=Get-Item -LiteralPath $path -ErrorAction Stop
        $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $expected=Get-IosExpectedHash -ExpectedHashes $ExpectedHashes -Path $path
        if($expected -and $expected -notmatch '^[A-Fa-f0-9]{64}$'){throw "Expected SHA-256 is invalid for $path"}
        if($expected -and $hash -ne $expected.ToLowerInvariant()){throw "SHA-256 mismatch for $path. Expected $expected, got $hash."}
        $duplicateOf=$null
        if($seenPaths.ContainsKey($path.ToLowerInvariant())){$duplicateOf=$seenPaths[$path.ToLowerInvariant()]}
        elseif($seenHashes.ContainsKey($hash)){$duplicateOf=$seenHashes[$hash]}
        $seenPaths[$path.ToLowerInvariant()]=$path; $seenHashes[$hash]=$path
        $metadata=Get-IosFirmwareMetadata -Path $path -IpswCommand $IpswCommand
        $record=[pscustomobject]@{Path=$path;FileName=[IO.Path]::GetFileName($path);SourceType=if($extension -eq '.ipsw'){'IPSW'}else{'OTA'};FileSizeBytes=[long]$info.Length;SHA256=$hash;ExpectedSHA256=$expected;FirmwareVersion=$metadata.FirmwareVersion;Build=$metadata.Build;DeviceIdentifiers=$metadata.DeviceIdentifiers;MetadataSource=$metadata.MetadataSource;DuplicateOf=$duplicateOf;Validation='valid'}
        [void]$records.Add($record)
    }
    $manifest=[pscustomobject]@{SchemaVersion=1;GeneratedAt=[DateTime]::UtcNow.ToString('o');SourceType=$Config.sourceType;NetworkAccess=$false;Inputs=@($records);UniqueInputCount=@($records|Where-Object {-not $_.DuplicateOf}).Count;DuplicateInputCount=@($records|Where-Object {$_.DuplicateOf}).Count;Validation='valid'}
    if($ManifestPath){$manifest | Add-Member -NotePropertyName ManifestPath -NotePropertyValue (Save-IosFirmwareManifest -Manifest $manifest -Path $ManifestPath)}
    return $manifest
}

Export-ModuleMember -Function Get-IosFirmwareMetadata,Get-IosFirmwareInventory,Save-IosFirmwareManifest
