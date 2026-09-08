#Requires -Version 5.1
<#
.SYNOPSIS
Installs Sysmon if absent and synchronizes its config with the GitHub XML.

.DESCRIPTION
Run in BreezeRMM as SYSTEM using Windows PowerShell 5.1 or later.
No parameters are required. A six-hour schedule and 600-second timeout are
reasonable starting settings; this script does not create its own schedule.

Each run downloads the XML and compares its SHA256 with the Config hash
reported by the installed Sysmon executable (-c). The XML Version comment
is informational: any byte change is detected without bumping that comment.

Before changing anything in Sysmon, rejects malformed XML, DTDs, active
file-blocking rules, deleted-file archiving, clipboard capture, unknown
global/event elements, and the original Event 11 contains-colon catch-all.
No remote PowerShell is downloaded or executed. Sysmon is obtained from
Microsoft and its Authenticode signature and product identity are checked.

An existing Sysmon binary is reused, not upgraded or reinstalled. A stopped
service is started; a disabled service is reported as an error. If a config
needs a newer schema, update Sysmon separately; this script will not force it.
An available built-in Windows Sysmon executable is reused on a fresh install,
without enabling Windows optional features or installing a second copy.

No reboot, uninstall, service restart, AV exclusion, machine execution-policy
change, or certificate-validation bypass is performed. Logging still has
resource overhead; validate on representative Windows machines before rollout.

Cache: %ProgramData%\BreezeSysmonConfigSync (SYSTEM/Administrators only).
After success, retains the current config and the previous active hash when
that config was cached by this script. On update failure, attempts rollback
only when that exact previous config is cached and passes the same policy.
An arbitrary pre-existing configuration cannot be reconstructed for rollback.

Exit 0: installed, updated, already current, or another run owns the lock.
Exit 1: failure; the console log explains why. No hash cache is treated as
proof of success: a successful apply requires Sysmon's reported hash to match.

.NOTES
Script version: 1.0.1
Captures native stdout/stderr as bytes and decodes each stream independently.
Schema discovery accepts XML or labelled output and falls back to -? config.
Unknown schemas remain an error before installing or applying a configuration.

Sources:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon
#>
[CmdletBinding()]
param(
    [string]$ConfigUrl = 'https://raw.githubusercontent.com/JustinTDCT/Scripts/refs/heads/main/sysmon_dfir.xml',
    [string]$WorkingDirectory = (Join-Path $env:ProgramData 'BreezeSysmonConfigSync'),
    [ValidateRange(10,120)][int]$DownloadTimeoutSeconds = 45,
    [ValidateRange(30,300)][int]$CommandTimeoutSeconds = 120
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-SyncLog {
    param([string]$Message)
    Write-Host ('[SysmonSync] {0} {1}' -f [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'), $Message)
}

function Assert-WindowsAdministrator {
    if ($env:OS -ne 'Windows_NT') { throw 'This script supports Windows only.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Run this BreezeRMM script as SYSTEM or an elevated administrator.'
        }
    } finally { $identity.Dispose() }
}

function Initialize-SyncDirectory {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'The working directory must be an ordinary local directory, not a reparse point.'
        }
    } else { [void](New-Item -ItemType Directory -Path $Path -Force) }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $access = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        [void]$acl.AddAccessRule($access)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Resolve-SyncRoot {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full -notmatch '^[A-Za-z]:\\' -or
        [IO.Path]::GetFileName($full) -ne 'BreezeSysmonConfigSync') {
        throw 'The dedicated local working directory must be named BreezeSysmonConfigSync.'
    }
    # Do not follow junctions/symlinks through custom parent directories.
    $parent = [IO.Directory]::GetParent($full)
    while ($parent) {
        if ($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'The working directory must not be below a reparse point.'
        }
        $parent = $parent.Parent
    }
    return $full
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-HttpsFile {
    param([string]$Url, [string]$Destination, [long]$MaximumBytes, [int]$TimeoutSeconds)
    $uri = [Uri]$Url
    if ($uri.Scheme -ne 'https') { throw 'Downloads require HTTPS.' }
    $builder = New-Object UriBuilder($uri)
    $query = $builder.Query.TrimStart('?')
    $nonce = 'breezesync=' + [Guid]::NewGuid().ToString('N')
    $builder.Query = if ($query) { $query + '&' + $nonce } else { $nonce }
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            Invoke-WebRequest -Uri $builder.Uri.AbsoluteUri -UseBasicParsing -OutFile $Destination `
                -TimeoutSec $TimeoutSeconds -MaximumRedirection 3 `
                -Headers @{ 'Cache-Control' = 'no-cache'; 'Pragma' = 'no-cache' } `
                -UserAgent 'BreezeRMM-SysmonConfigSync/1.0' -ErrorAction Stop | Out-Null
            $length = (Get-Item -LiteralPath $Destination).Length
            if ($length -le 0 -or $length -gt $MaximumBytes) {
                throw "Unexpected download size: $length bytes; allowed maximum is $MaximumBytes."
            }
            return
        } catch {
            if ($attempt -eq 2) { throw }
            Write-SyncLog 'Download failed; retrying once.'
            Start-Sleep -Seconds 2
        }
    }
}

function Read-PassiveSysmonConfig {
    param([string]$Path)
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 2097152
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
    } finally { $reader.Dispose() }
    if ($document.DocumentElement.PSBase.Name -cne 'Sysmon') { throw 'Expected a Sysmon XML document.' }
    foreach ($node in $document.SelectNodes('//*')) {
        if ($node.PSBase.NamespaceURI) { throw 'Namespaced XML is not accepted by this configuration policy.' }
    }
    $schemaText = $document.DocumentElement.GetAttribute('schemaversion')
    $schema = $null
    if (-not [Version]::TryParse($schemaText, [ref]$schema)) { throw 'Missing or invalid Sysmon schema version.' }
    $globalNames = @('HashAlgorithms','CheckRevocation','DnsLookup','CopyOnDeletePE','ArchiveDirectory','FieldSizes','EventFiltering')
    foreach ($node in $document.SelectNodes('/Sysmon/*')) {
        $elementName = $node.PSBase.Name
        if ($globalNames -cnotcontains $elementName) { throw "Unexpected or disallowed global setting: $elementName." }
        if ($document.SelectNodes('/Sysmon/' + $elementName).Count -ne 1) { throw "Duplicate global setting: $elementName." }
    }
    if ($document.SelectNodes('/Sysmon/EventFiltering').Count -ne 1) { throw 'Exactly one EventFiltering element is required.' }
    foreach ($node in $document.SelectNodes('//CopyOnDeletePE')) {
        if ($node.PSBase.InnerText.Trim() -cne 'false' -or $node.SelectNodes('*').Count) {
            throw 'CopyOnDeletePE must be false; file archiving is prohibited.'
        }
    }
    # Empty include, or an absent tag, is the only accepted form for these features.
    foreach ($name in @('FileBlockExecutable','FileBlockShredding','FileDelete','ClipboardChange')) {
        foreach ($node in $document.SelectNodes('//' + $name)) {
            if ($node.GetAttribute('onmatch') -cne 'include' -or $node.SelectNodes('*').Count -ne 0 -or $node.PSBase.InnerText.Trim()) {
                throw "Rejected ${name}: file blocking, file archiving and clipboard capture must remain disabled."
            }
        }
    }
    $eventNames = @('ProcessCreate','FileCreateTime','NetworkConnect','ProcessTerminate','DriverLoad',
        'ImageLoad','CreateRemoteThread','RawAccessRead','ProcessAccess','FileCreate','RegistryEvent',
        'FileCreateStreamHash','PipeEvent','WmiEvent','DnsQuery','FileDelete','ClipboardChange',
        'ProcessTampering','FileDeleteDetected','FileBlockExecutable','FileBlockShredding','FileExecutableDetected')
    foreach ($node in $document.SelectNodes('/Sysmon/EventFiltering/* | /Sysmon/EventFiltering/RuleGroup/*')) {
        $elementName = $node.PSBase.Name
        if ($elementName -ceq 'RuleGroup' -and $node.ParentNode.PSBase.Name -ceq 'EventFiltering') { continue }
        if ($eventNames -cnotcontains $elementName) { throw "Unexpected event element: $elementName." }
        if (@('include','exclude') -cnotcontains $node.GetAttribute('onmatch')) { throw "Invalid onmatch for $elementName." }
    }
    foreach ($name in $eventNames) {
        foreach ($mode in @('include','exclude')) {
            if ($document.SelectNodes('//'+$name+'[@onmatch="'+$mode+'"]').Count -gt 1) {
                throw "Duplicate $name $mode sections; combine them before deployment."
            }
        }
    }
    if ($document.SelectNodes('//FileCreate[@onmatch="include"]//TargetFilename[@condition="contains" and normalize-space(.)=":"]').Count) {
        throw 'Rejected Event 11 contains-colon rule: it matches ordinary drive-letter paths.'
    }
    $label = '(no Version comment)'
    foreach ($comment in $document.SelectNodes('//comment()')) {
        $versionMatch = [regex]::Match($comment.Value, '(?im)^\s*Version:\s*([^\r\n]+)')
        if ($versionMatch.Success) { $label = $versionMatch.Groups[1].Value.Trim(); break }
    }
    return [pscustomobject]@{ Schema = $schema; Label = $label; Hash = (Get-Sha256 $Path) }
}

function Resolve-ServiceExecutable {
    param([string]$CommandLine)
    $value = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    $match = [regex]::Match($value, '^(?:"([^"]+\.exe)"|(.+?\.exe))(?=\s|$)', 'IgnoreCase')
    if (-not $match.Success) { return $null }
    $path = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
    if ($path.StartsWith('\??\')) { $path = $path.Substring(4) }
    if ($path -notmatch '^[A-Za-z]:\\') { return $null }
    # A 32-bit RMM host must address the real native System32 executable.
    $system32 = $env:windir.TrimEnd('\') + '\System32\'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and
        $path.StartsWith($system32, [StringComparison]::OrdinalIgnoreCase)) {
        $path = $env:windir.TrimEnd('\') + '\Sysnative\' + $path.Substring($system32.Length)
    }
    return $path
}

function Test-SysmonProduct {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        return ($info.ProductName -match '(?i)\bSysmon\b' -or $info.FileDescription -eq 'System activity monitor')
    } catch { return $false }
}

function Assert-MicrosoftSysmon {
    param([string]$Path)
    if (-not (Test-SysmonProduct $Path)) { throw "Executable does not identify as Sysmon: $Path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(?i)(?:^|,\s*)(?:CN|O)=Microsoft (?:Corporation|Windows)(?:,|$)') {
        throw "Sysmon does not have a valid Microsoft signature: $Path (status $($signature.Status))."
    }
}

function Find-SysmonInstallation {
    $candidates = New-Object 'Collections.Generic.List[object]'
    $metadata = @{}
    foreach ($service in Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) {
        $path = Resolve-ServiceExecutable ([string]$service.PathName)
        if (-not $path) {
            if ($service.Name -match '^(?i)Sysmon(?:64|64a)?$') { throw 'Sysmon service has an unreadable executable path.' }
            continue
        }
        if (-not $metadata.ContainsKey($path)) { $metadata[$path] = Test-SysmonProduct $path }
        if ($metadata[$path]) {
            [void]$candidates.Add([pscustomobject]@{ Name=$service.Name; Path=$path; State=$service.State; StartMode=$service.StartMode })
        } elseif ($service.Name -match '^(?i)Sysmon(?:64|64a)?$') {
            throw "A Sysmon-named service has a missing or unexpected executable: $($service.Name)."
        }
    }
    if ($candidates.Count -gt 1) { throw 'Multiple Sysmon installations found; no installation was selected or changed.' }
    if ($candidates.Count -eq 1) { return $candidates[0] }
    return $null
}

function Ensure-SysmonRunning {
    param($Installation)
    if ($Installation.StartMode -eq 'Disabled') { throw "Sysmon service $($Installation.Name) is disabled; startup policy was not overridden." }
    $service = Get-Service -Name $Installation.Name -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        Write-SyncLog "Starting existing service $($Installation.Name)."
        Start-Service -Name $Installation.Name -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    }
}

function ConvertFrom-SysmonOutputBytes {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    $encoding = $null
    $offset = 0
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        $encoding = [Text.Encoding]::UTF8; $offset = 3
    } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        $encoding = [Text.Encoding]::Unicode; $offset = 2
    } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        $encoding = [Text.Encoding]::BigEndianUnicode; $offset = 2
    } else {
        # Redirected Unicode text can lack a BOM. Schema/hash labels are ASCII,
        # so their UTF-16 representation has NULs consistently on one byte lane.
        $pairs = [Math]::Min([int][Math]::Floor($Bytes.Length / 2), 256)
        $evenNuls = 0; $oddNuls = 0
        for ($i = 0; $i -lt $pairs; $i++) {
            if ($Bytes[2 * $i] -eq 0) { $evenNuls++ }
            if ($Bytes[2 * $i + 1] -eq 0) { $oddNuls++ }
        }
        if ($pairs -ge 4 -and $oddNuls -gt ($pairs * 0.6) -and $evenNuls -lt ($pairs * 0.1)) {
            $encoding = [Text.Encoding]::Unicode
        } elseif ($pairs -ge 4 -and $evenNuls -gt ($pairs * 0.6) -and $oddNuls -lt ($pairs * 0.1)) {
            $encoding = [Text.Encoding]::BigEndianUnicode
        }
    }
    if ($encoding) { return $encoding.GetString($Bytes, $offset, $Bytes.Length - $offset) }
    try { return ([Text.UTF8Encoding]::new($false, $true)).GetString($Bytes) }
    catch [Text.DecoderFallbackException] { return [Console]::OutputEncoding.GetString($Bytes) }
}

function Invoke-SysmonCommand {
    param([string]$Executable, [string[]]$Arguments, [int]$TimeoutSeconds, [int[]]$AllowedExitCodes = @(0))
    $quoted = foreach ($argument in $Arguments) {
        if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'Unexpected native argument; refusing ambiguous quoting.' }
        '"' + $argument + '"'
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = $quoted -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $stdoutBytes = New-Object IO.MemoryStream
    $stderrBytes = New-Object IO.MemoryStream
    try {
        if (-not $process.Start()) { throw 'Could not start the Sysmon command.' }
        # Reading through the default StreamReader can turn BOM-less UTF-16
        # into NUL-interleaved text, breaking both schema and active-hash checks.
        $stdout = $process.StandardOutput.BaseStream.CopyToAsync($stdoutBytes)
        $stderr = $process.StandardError.BaseStream.CopyToAsync($stderrBytes)
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            # This is the child CLI process created above, never the resident service PID.
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw 'Sysmon command timed out; check installation/configuration state before retrying.'
        }
        [void]$stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        $outText = ConvertFrom-SysmonOutputBytes -Bytes ($stdoutBytes.ToArray())
        $errText = ConvertFrom-SysmonOutputBytes -Bytes ($stderrBytes.ToArray())
        $text = $outText + "`n" + $errText
        if ($AllowedExitCodes -notcontains $process.ExitCode) {
            $detail = $text.Trim()
            if ($detail.Length -gt 2000) { $detail = $detail.Substring(0,2000) }
            throw "Sysmon exited with code $($process.ExitCode): $detail"
        }
        return $text
    } finally {
        $process.Dispose()
        $stdoutBytes.Dispose()
        $stderrBytes.Dispose()
    }
}

function Get-ReportedConfigHash {
    param([string]$OutputText)
    $match = [regex]::Match($OutputText, '(?im)^\s*-?\s*(?:Config\s+hash|Configuration(?:\s+file)?\s+hash)\s*:\s*SHA256\s*=\s*([A-F0-9]{64})\s*$')
    if ($match.Success) { return $match.Groups[1].Value.ToUpperInvariant() }
    return $null
}

function Read-LiveConfigHash {
    param([string]$Executable, [int]$TimeoutSeconds)
    $text = Invoke-SysmonCommand $Executable @('-accepteula','-c') $TimeoutSeconds
    return Get-ReportedConfigHash $text
}

function Get-ReportedSchemaVersion {
    param([string]$OutputText)
    $match = [regex]::Match($OutputText, '(?is)<(?:manifest|Sysmon)\b[^>]*?\bschemaversion\s*=\s*(?<quote>["''])(?<schema>[0-9]+(?:\.[0-9]+)+)\k<quote>')
    if (-not $match.Success) {
        $match = [regex]::Match($OutputText, '(?im)^\s*(?:Current\s+)?(?:Sysmon\s+)?schema\s+version\s*:\s*(?<schema>[0-9]+(?:\.[0-9]+)+)\s*$')
    }
    $version = $null
    if ($match.Success -and [Version]::TryParse($match.Groups['schema'].Value, [ref]$version)) { return $version }
    return $null
}

function Assert-SchemaSupported {
    param([string]$Executable, [Version]$RequiredSchema, [int]$TimeoutSeconds)
    $probes = @(
        [pscustomobject]@{ Name = '-s'; Arguments = @('-accepteula','-s'); ExitCodes = @(0) },
        # Help can return 1. This allowance applies only to the read-only help
        # probe; install/update/config-dump commands must still return zero.
        [pscustomobject]@{ Name = '-? config'; Arguments = @('-accepteula','-?','config'); ExitCodes = @(0,1) }
    )
    $details = New-Object 'Collections.Generic.List[string]'
    $available = $null
    foreach ($probe in $probes) {
        try {
            $text = Invoke-SysmonCommand -Executable $Executable -Arguments $probe.Arguments -TimeoutSeconds $TimeoutSeconds -AllowedExitCodes $probe.ExitCodes
            $available = Get-ReportedSchemaVersion $text
            if ($available) { break }
        } catch { $text = $_.Exception.Message }
        $preview = [regex]::Replace($text, '[\r\n\t]+', ' ').Trim()
        if (-not $preview) { $preview = '(empty output)' }
        if ($preview.Length -gt 700) { $preview = $preview.Substring(0,700) }
        $details.Add($probe.Name + ': ' + $preview)
    }
    if (-not $available) {
        throw ('Could not determine the schema supported by this Sysmon executable. No configuration was applied. Executable: ' + $Executable + '. ' + ($details -join ' | '))
    }
    Write-SyncLog "Supported schema: $available; required schema: $RequiredSchema."
    if ($RequiredSchema -gt $available) {
        throw "Config requires schema $RequiredSchema; installed Sysmon supports $available. Upgrade Sysmon separately, then rerun."
    }
}

function Get-SysmonInstallExecutable {
    param([string]$Root, [string]$Staging, [int]$TimeoutSeconds)
    $native = Resolve-ServiceExecutable ('"' + (Join-Path $env:windir 'System32\Sysmon.exe') + '"')
    if ($native -and (Test-Path -LiteralPath $native -PathType Leaf)) {
        Assert-MicrosoftSysmon $native
        Write-SyncLog 'Using the available Windows Sysmon executable; no second copy will be installed.'
        return $native
    }
    $architecture = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
    $filename = switch ($architecture.ToUpperInvariant()) {
        'AMD64' { 'Sysmon64.exe' }
        'ARM64' { 'Sysmon64a.exe' }
        'X86' { 'Sysmon.exe' }
        default { throw "Unsupported Windows architecture: $architecture" }
    }
    $zipPath = Join-Path $Staging 'Sysmon.zip'
    Write-SyncLog 'Downloading the Microsoft Sysmon package for this new installation.'
    Get-HttpsFile 'https://download.sysinternals.com/files/Sysmon.zip' $zipPath 26214400 $TimeoutSeconds
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
    $candidate = Join-Path $Staging $filename
    try {
        $entry = $archive.GetEntry($filename)
        if (-not $entry -or $entry.Length -le 0 -or $entry.Length -gt 20971520) { throw 'Expected Sysmon executable was not found in the package.' }
        # Extract exactly one named entry, never arbitrary archive paths.
        $inputStream = $entry.Open()
        $outputStream = [IO.File]::Create($candidate)
        try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
    } finally { $archive.Dispose() }
    Assert-MicrosoftSysmon $candidate
    $destination = Join-Path $Root $filename
    Copy-Item -LiteralPath $candidate -Destination $destination -Force
    Assert-MicrosoftSysmon $destination
    return $destination
}

function Get-CachedConfigPath {
    param([string]$Root, [string]$Hash)
    if ($Hash -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid config hash for a cache filename.' }
    return Join-Path $Root ('config-' + $Hash.ToLowerInvariant() + '.xml')
}

function Remove-OldConfigCache {
    param([string]$Root, [string[]]$KeepHashes)
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Filter 'config-*.xml') {
        $match = [regex]::Match($file.Name, '^config-([a-f0-9]{64})\.xml$')
        if ($match.Success -and $KeepHashes -notcontains $match.Groups[1].Value.ToUpperInvariant()) {
            Remove-Item -LiteralPath $file.FullName -Force
        }
    }
}

function Invoke-SysmonSync {
    param([string]$Url, [string]$Root, [int]$DownloadTimeout, [int]$NativeTimeout)
    Assert-WindowsAdministrator
    Write-SyncLog 'Script version: 1.0.1.'
    $rootPath = Resolve-SyncRoot $Root
    Initialize-SyncDirectory $rootPath
    $lockStream = $null
    $staging = $null
    $oldTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        try { $lockStream = [IO.File]::Open((Join-Path $rootPath 'sync.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
        catch [IO.IOException] {
            if (($_.Exception.HResult -band 65535) -in @(32,33)) {
                return 'SKIPPED: another synchronization owns the lock.'
            }
            throw
        }
        [Net.ServicePointManager]::SecurityProtocol = $oldTls -bor [Net.SecurityProtocolType]::Tls12
        $staging = Join-Path $rootPath ('run-' + [Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $staging)
        $download = Join-Path $staging 'download.xml'
        $installation = Find-SysmonInstallation
        Write-SyncLog ('Sysmon installation: ' + $(if ($installation) { $installation.Name } else { 'not found' }))
        Get-HttpsFile $Url $download 2097152 $DownloadTimeout
        $config = Read-PassiveSysmonConfig $download
        Write-SyncLog "Remote config version: $($config.Label); SHA256=$($config.Hash)."
        $previousHash = $null
        $rollbackPath = $null
        if ($installation) {
            Assert-MicrosoftSysmon $installation.Path
            Ensure-SysmonRunning $installation
            $executable = $installation.Path
            $previousHash = Read-LiveConfigHash $executable $NativeTimeout
            if ($previousHash -eq $config.Hash) {
                return "UNCHANGED: Sysmon already reports SHA256=$($config.Hash)."
            }
            if ($previousHash) {
                $priorFile = Get-CachedConfigPath $rootPath $previousHash
                if (Test-Path -LiteralPath $priorFile -PathType Leaf) {
                    try {
                        $prior = Read-PassiveSysmonConfig $priorFile
                        if ($prior.Hash -eq $previousHash) { $rollbackPath = $priorFile }
                    } catch { Write-SyncLog 'Previous cached config is not eligible for automatic rollback.' }
                }
            }
        } else {
            $remainingDriver = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name LIKE 'Sysmon%'" -ErrorAction Stop)
            if ($remainingDriver.Count) { throw 'A Sysmon driver remains without a recognized service. Repair the partial installation before retrying.' }
            $executable = Get-SysmonInstallExecutable $rootPath $staging $DownloadTimeout
        }
        Assert-SchemaSupported $executable $config.Schema $NativeTimeout
        $candidatePath = Get-CachedConfigPath $rootPath $config.Hash
        Copy-Item -LiteralPath $download -Destination $candidatePath -Force
        if ((Get-Sha256 $candidatePath) -ne $config.Hash) { throw 'The staged config hash changed; nothing was applied.' }
        $operation = if ($installation) { 'UPDATED' } else { 'INSTALLED' }
        try {
            if ($installation) {
                Write-SyncLog 'Configuration differs; applying the validated XML.'
                [void](Invoke-SysmonCommand $executable @('-accepteula','-c',$candidatePath) $NativeTimeout)
            } else {
                Write-SyncLog 'Installing Sysmon with the validated configuration.'
                [void](Invoke-SysmonCommand $executable @('-accepteula','-i',$candidatePath) $NativeTimeout)
            }
            $verifiedInstallation = Find-SysmonInstallation
            if (-not $verifiedInstallation) { throw 'Sysmon service was not found after the command completed.' }
            Assert-MicrosoftSysmon $verifiedInstallation.Path
            Ensure-SysmonRunning $verifiedInstallation
            $reported = Read-LiveConfigHash $verifiedInstallation.Path $NativeTimeout
            if ($reported -ne $config.Hash) { throw "Applied config could not be verified. Expected $($config.Hash); reported $reported." }
        } catch {
            $applyError = $_.Exception.Message
            if ($rollbackPath) {
                try {
                    Write-SyncLog 'Apply failed; restoring the exact previous cached passive configuration.'
                    [void](Invoke-SysmonCommand $executable @('-accepteula','-c',$rollbackPath) $NativeTimeout)
                    if ((Read-LiveConfigHash $executable $NativeTimeout) -ne $previousHash) { throw 'Rollback hash verification failed.' }
                    Write-SyncLog 'Previous configuration restored and its hash verified.'
                } catch { Write-SyncLog ('Rollback failed: ' + $_.Exception.Message) }
            } else { Write-SyncLog 'No verified previous passive config is cached for automatic rollback.' }
            throw $applyError
        }
        try { Remove-OldConfigCache $rootPath @($config.Hash, $previousHash) }
        catch { Write-SyncLog ('Config is applied, but old-cache cleanup failed: ' + $_.Exception.Message) }
        return "$operation`: version=$($config.Label); SHA256=$($config.Hash); service=$($verifiedInstallation.Name)."
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $oldTls
        if ($staging -and (Test-Path -LiteralPath $staging)) {
            try { Remove-Item -LiteralPath $staging -Recurse -Force }
            catch { Write-SyncLog ('Temporary-file cleanup failed: ' + $_.Exception.Message) }
        }
        if ($lockStream) { $lockStream.Dispose() }
    }
}

try {
    $result = Invoke-SysmonSync $ConfigUrl $WorkingDirectory $DownloadTimeoutSeconds $CommandTimeoutSeconds
    Write-SyncLog ('RESULT=' + $result)
    exit 0
} catch {
    Write-SyncLog ('RESULT=FAILED: ' + $_.Exception.Message)
    exit 1
}
