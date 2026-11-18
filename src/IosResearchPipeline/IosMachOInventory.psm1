Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IosResearchState.psm1') -Force

function Read-IosUInt32 {
    param([Parameter(Mandatory=$true)][System.IO.BinaryReader]$Reader,[bool]$BigEndian=$false)
    $b=$Reader.ReadBytes(4);if($b.Length -ne 4){throw 'Unexpected end of Mach-O file.'};if($BigEndian){[Array]::Reverse($b)};[BitConverter]::ToUInt32($b,0)
}
function Read-IosUInt64 {
    param([Parameter(Mandatory=$true)][System.IO.BinaryReader]$Reader,[bool]$BigEndian=$false)
    $b=$Reader.ReadBytes(8);if($b.Length -ne 8){throw 'Unexpected end of Mach-O file.'};if($BigEndian){[Array]::Reverse($b)};[BitConverter]::ToUInt64($b,0)
}
function Read-IosUInt16 {
    param([Parameter(Mandatory=$true)][System.IO.BinaryReader]$Reader,[bool]$BigEndian=$false)
    $b=$Reader.ReadBytes(2);if($b.Length -ne 2){throw 'Unexpected end of Mach-O file.'};if($BigEndian){[Array]::Reverse($b)};[BitConverter]::ToUInt16($b,0)
}
function Convert-IosCpuName {
    param([uint32]$Cpu,[uint32]$Subtype=0)
    switch($Cpu){12{'armv7'} 16777228{'arm64'} 7{'i386'} 16777223{'x86_64'} default{('cpu-0x{0:x8}' -f $Cpu)}}
}
function Get-IosFrameworkName {
    param([string]$Path)
    $Path=$Path -replace '\\','/'
    if($Path -match '/Frameworks/([^/]+\.framework)/') {return $matches[1] -replace '\.framework$',''}
    if($Path -match '/([^/]+)\.framework/'){return $matches[1]}
    if($Path -match '/usr/lib/([^/]+)'){return $matches[1]}
    return $null
}

function Read-IosMachOSlice {
    param([Parameter(Mandatory=$true)][System.IO.FileStream]$Stream,[Parameter(Mandatory=$true)][long]$Offset,[Parameter(Mandatory=$true)][long]$Length)
    $Stream.Position=$Offset
    $r=New-Object System.IO.BinaryReader($Stream,[System.Text.Encoding]::UTF8,$true)
    $m=$r.ReadBytes(4);if($m.Length -ne 4){throw 'Mach-O header is truncated.'}
    $hex=([BitConverter]::ToString($m)).Replace('-','').ToUpperInvariant()
    $is64=$false;$big=$false
    switch($hex){'CEFAEDFE'{$big=$false} 'CFFAEDFE'{$big=$false;$is64=$true} 'FEEDFACE'{$big=$true} 'FEEDFACF'{$big=$true;$is64=$true} default{throw "Unsupported Mach-O magic: $hex"}}
    $cpu=Read-IosUInt32 -Reader $r -BigEndian $big;$subtype=Read-IosUInt32 -Reader $r -BigEndian $big;$filetype=Read-IosUInt32 -Reader $r -BigEndian $big
    $ncmds=Read-IosUInt32 -Reader $r -BigEndian $big;$sizeofcmds=Read-IosUInt32 -Reader $r -BigEndian $big;$null=Read-IosUInt32 -Reader $r -BigEndian $big
    if($is64){$null=Read-IosUInt32 -Reader $r -BigEndian $big}
    if($ncmds -gt 100000 -or $sizeofcmds -gt $Length){throw 'Mach-O load-command bounds are invalid.'}
    $uuid=$null;$libs=New-Object System.Collections.ArrayList;$symtab=$null
    for($i=0;$i -lt $ncmds;$i++){
        if(($Stream.Position-$Offset) -ge $Length){throw 'Mach-O load commands exceed the slice boundary.'}
        $command=Read-IosUInt32 -Reader $r -BigEndian $big;$cmdSize=Read-IosUInt32 -Reader $r -BigEndian $big
        if($cmdSize -lt 8 -or $cmdSize -gt ($Offset+$Length-$Stream.Position+8)){throw 'Invalid Mach-O load command size.'}
        $cmdStart=$Stream.Position-8
        if($command -eq 0x1b -and $cmdSize -ge 24){$uuidBytes=$r.ReadBytes(16);$uuidHex=([BitConverter]::ToString($uuidBytes)).Replace('-','').ToLowerInvariant();$uuid=$uuidHex.Substring(0,8)+'-'+$uuidHex.Substring(8,4)+'-'+$uuidHex.Substring(12,4)+'-'+$uuidHex.Substring(16,4)+'-'+$uuidHex.Substring(20,12)}
        elseif(($command -band 0x7fffffff) -in @(0x0c,0x18,0x1f,0x20,0x23) -and $cmdSize -ge 24){
            $nameOffset=Read-IosUInt32 -Reader $r -BigEndian $big;$null=$r.ReadBytes(12);$namePosition=$cmdStart+$nameOffset
            if($nameOffset -ge 8 -and $nameOffset -lt $cmdSize){$saved=$Stream.Position;$Stream.Position=$namePosition;$bytes=New-Object System.Collections.ArrayList;while($Stream.Position -lt ($cmdStart+$cmdSize)){$v=$r.ReadByte();if($v -eq 0){break};[void]$bytes.Add($v)};[void]$libs.Add([Text.Encoding]::UTF8.GetString([byte[]]$bytes.ToArray()));$Stream.Position=$saved}
        } elseif($command -eq 0x2 -and $cmdSize -ge 24){
            $symoff=Read-IosUInt32 -Reader $r -BigEndian $big;$nsyms=Read-IosUInt32 -Reader $r -BigEndian $big;$stroff=Read-IosUInt32 -Reader $r -BigEndian $big;$strsize=Read-IosUInt32 -Reader $r -BigEndian $big
            $symtab=[pscustomobject]@{SymOffset=[long]$symoff;Count=[long]$nsyms;StringOffset=[long]$stroff;StringSize=[long]$strsize;Is64=$is64;BigEndian=$big}
        }
        $Stream.Position=$cmdStart+$cmdSize
    }
    $symbols=New-Object System.Collections.ArrayList
    $symbolTableCount=if($symtab){[long]$symtab.Count}else{0L}
    $symbolEntryLimit=10000
    $symbolEntriesRead=0
    $entrySize=if($is64){16}else{12}
    if($symtab -and $symtab.Count -gt 0 -and $symtab.StringSize -lt 134217728 -and ($Offset+$symtab.SymOffset+$symtab.Count*$entrySize) -le ($Offset+$Length) -and ($Offset+$symtab.StringOffset+$symtab.StringSize) -le ($Offset+$Length)){
        $symbolEntriesRead=[int][Math]::Min([long]$symtab.Count,[long]$symbolEntryLimit)
        for($i=0;$i -lt $symbolEntriesRead;$i++){
            $Stream.Position=$Offset+$symtab.SymOffset+$i*$entrySize;$strx=Read-IosUInt32 -Reader $r -BigEndian $big;$type=$r.ReadByte();$null=$r.ReadByte();$null=Read-IosUInt16 -Reader $r -BigEndian $big
            if($is64){$null=Read-IosUInt64 -Reader $r -BigEndian $big}else{$null=Read-IosUInt32 -Reader $r -BigEndian $big}
            if(($type -band 0x0e) -eq 0x0e -and $strx -gt 0 -and $strx -lt $symtab.StringSize){
                $Stream.Position=$Offset+$symtab.StringOffset+$strx;$bytes=New-Object System.Collections.ArrayList;while($bytes.Count -lt 1024 -and $Stream.Position -lt ($Offset+$symtab.StringOffset+$symtab.StringSize)){$v=$r.ReadByte();if($v -eq 0){break};[void]$bytes.Add($v)}
                $symbol=[Text.Encoding]::UTF8.GetString([byte[]]$bytes.ToArray()).TrimStart('_');if($symbol){[void]$symbols.Add($symbol)}
            }
        }
    }
    $fileTypeName=switch($filetype){2{'executable'} 6{'dylib'} 8{'bundle'} 11{'kext'} default{('type-'+$filetype)}}
    $archName=Convert-IosCpuName -Cpu $cpu -Subtype $subtype
    if($cpu -eq 16777228 -and ($subtype -band 0xff) -eq 2){$archName='arm64e'}
    [pscustomobject]@{Architecture=$archName;CpuType=$cpu;CpuSubtype=$subtype;UUID=$uuid;MachOType=$fileTypeName;LinkedLibraries=@($libs|Select-Object -Unique);Symbols=@($symbols|Select-Object -Unique);SymbolTableCount=$symbolTableCount;SymbolEntriesSampled=$symbolEntriesRead;SymbolsTruncated=($symbolTableCount -gt $symbolEntriesRead);Offset=$Offset;SliceSizeBytes=$Length}
}

function Get-IosMachOInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string[]]$Roots,[string[]]$Framework,[string[]]$Component,[string]$ManifestPath)
    $files=New-Object System.Collections.ArrayList
    foreach($root in $Roots){if(Test-Path -LiteralPath $root -PathType Leaf){[void]$files.Add((Get-Item -LiteralPath $root))}elseif(Test-Path -LiteralPath $root -PathType Container){foreach($f in Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue){[void]$files.Add($f)}}}
    $records=New-Object System.Collections.ArrayList
    foreach($file in $files){
        if($file.Length -lt 4){continue}
        $fs=$null;$reader=$null
        try{
            $fs=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $reader=New-Object IO.BinaryReader($fs,[Text.Encoding]::UTF8,$true);$magic=$reader.ReadBytes(4);$hex=([BitConverter]::ToString($magic)).Replace('-','').ToUpperInvariant();$slices=@()
            if($hex -notin @('CAFEBABE','BEBAFECA','CAFEBABF','BFBAFECA','CEFAEDFE','CFFAEDFE','FEEDFACE','FEEDFACF')){continue}
            if($hex -in @('CAFEBABE','BEBAFECA','CAFEBABF','BFBAFECA')){
                $fatBig=$hex -in @('CAFEBABE','CAFEBABF');$fat64=$hex -in @('CAFEBABF','BFBAFECA');$n=Read-IosUInt32 -Reader $reader -BigEndian $fatBig;if($n -gt 128){throw 'Fat Mach-O contains too many architectures.'}
                for($i=0;$i -lt $n;$i++){$cpu=Read-IosUInt32 -Reader $reader -BigEndian $fatBig;$sub=Read-IosUInt32 -Reader $reader -BigEndian $fatBig;if($fat64){$off=Read-IosUInt64 -Reader $reader -BigEndian $fatBig;$size=Read-IosUInt64 -Reader $reader -BigEndian $fatBig;$null=$reader.ReadBytes(8)}else{$off=Read-IosUInt32 -Reader $reader -BigEndian $fatBig;$size=Read-IosUInt32 -Reader $reader -BigEndian $fatBig;$null=$reader.ReadBytes(4)};if($off+$size -gt $fs.Length){throw 'Fat Mach-O architecture slice is out of bounds.'};$slices+=@([pscustomobject]@{Offset=[long]$off;Size=[long]$size})}
            } else {$slices=@([pscustomobject]@{Offset=0L;Size=[long]$fs.Length})}
            $fileHash=Get-IosStateFileHash -Path $file.FullName
            foreach($slice in $slices){$meta=Read-IosMachOSlice -Stream $fs -Offset $slice.Offset -Length $slice.Size;$frameworkName=Get-IosFrameworkName -Path $file.FullName
                if($Framework -and $frameworkName -notin $Framework){continue};if($Component -and -not(@($Component|Where-Object {$file.FullName -match [regex]::Escape([string]$_)}).Count)){continue}
                [void]$records.Add([pscustomobject]@{Name=$file.Name;Path=$file.FullName;SHA256=$fileHash;FileSizeBytes=[long]$file.Length;Architecture=$meta.Architecture;UUID=$meta.UUID;MachOType=$meta.MachOType;LinkedLibraries=$meta.LinkedLibraries;Symbols=$meta.Symbols;SymbolTableCount=$meta.SymbolTableCount;SymbolEntriesSampled=$meta.SymbolEntriesSampled;SymbolsTruncated=$meta.SymbolsTruncated;Framework=$frameworkName;SliceOffset=$meta.Offset;SliceSizeBytes=$meta.SliceSizeBytes;Status='parsed'})
            }
        } catch {
            if ($_.Exception.Message -match 'Mach-O|header|load commands|architecture slice|magic') {
                $bad=[pscustomobject]@{
                    Name=$file.Name; Path=$file.FullName; SHA256=(Get-IosStateFileHash -Path $file.FullName)
                    FileSizeBytes=[long]$file.Length; Architecture=$null; UUID=$null; MachOType=$null
                    LinkedLibraries=@(); Symbols=@(); Framework=(Get-IosFrameworkName -Path $file.FullName)
                    SliceOffset=$null; SliceSizeBytes=$null; Status='unsupported'; Error=$_.Exception.Message
                }
                [void]$records.Add($bad)
            } else { throw }
        }
        finally{if($reader){$reader.Dispose()};if($fs){$fs.Dispose()}}
    }
    $manifest=[pscustomobject]@{SchemaVersion=1;GeneratedAt=[DateTime]::UtcNow.ToString('o');BinaryCount=$records.Count;Binaries=@($records);Status='completed'}
    if($ManifestPath){$path=[IO.Path]::GetFullPath($ManifestPath);$json=$manifest|ConvertTo-Json -Depth 15;$bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($json);$fsOut=$null;try{$fsOut=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$fsOut.Write($bytes,0,$bytes.Length)}catch{throw "Cannot write Mach-O manifest without overwriting an existing artifact: $path. $($_.Exception.Message)"}finally{if($fsOut){$fsOut.Dispose()}};$manifest|Add-Member -NotePropertyName ManifestPath -NotePropertyValue $path}
    return $manifest
}

Export-ModuleMember -Function Get-IosMachOInventory,Read-IosMachOSlice
