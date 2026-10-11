<#
.SYNOPSIS
    Parses package manager history: what was installed, upgraded or removed, when, and by whom.

.DESCRIPTION
    Reads every package log a Debian or RHEL family host keeps, with rotated and gzipped history:

      dpkg.log            Debian/Ubuntu. One line per package action.
      apt/history.log     Debian/Ubuntu. One block per apt run, with the command line and the
                          user who ran it via sudo - the only package log that says who.
      dnf.rpm.log         RHEL 8+ and Fedora. One line per package action.
      yum.log             RHEL 7 and older. One line per package action.

    Two CSVs come out. Actions is one row per package per action, from whichever of dpkg.log,
    dnf.rpm.log and yum.log exist. Transactions is one row per apt run, which is where an attacker
    installing tooling shows up as a command line and a user rather than a list of libraries.

    TIMESTAMPS: every package log is written in the host's local time. They are reported as
    written, not converted - check the timezone in SystemInfo before lining them up against UTC
    output. yum.log carries no year, which is inferred from the file's last-write time exactly as
    LinuxAuth does, and flagged in YearInferred.

    Not read: dnf's own history database (/var/lib/dnf/history.sqlite), which holds the dnf
    command lines and users that dnf.rpm.log lacks, and zypper history on SUSE.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force -Path $Out | Out-Null }

# Problems go to stderr, not Write-Warning: the engine marks a module for review only when
# something reaches stderr, and a warning stream does not.
function Write-Problem([string]$Message) { [Console]::Error.WriteLine($Message) }

# GzipStream ends quietly at the end of a truncated file, so a partial copy would read as a short
# log. The gzip trailer records the uncompressed length; a mismatch means the copy is incomplete.
# The lines that could be read are still returned.
function Read-MaybeGzip([System.IO.FileInfo]$File) {
    try {
        if ($File.Extension -ne '.gz') { return Get-Content -LiteralPath $File.FullName -ErrorAction Stop }

        $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
        $in = New-Object System.IO.MemoryStream(,$bytes)
        $out = New-Object System.IO.MemoryStream
        try {
            $gz = New-Object System.IO.Compression.GzipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
            try { $gz.CopyTo($out) }
            catch { Write-Problem "$($File.Name): incomplete - $($_.Exception.Message)" }
            finally { $gz.Dispose() }
        } finally { $in.Dispose() }

        if ($bytes.Length -lt 18) {
            Write-Problem "$($File.Name): too short to be a complete gzip file - truncated?"
        } elseif ([BitConverter]::ToUInt32($bytes, $bytes.Length - 4) -ne [uint32]($out.Length % 4294967296)) {
            Write-Problem "$($File.Name): gzip data ends before its recorded length - file truncated? Lines up to that point were read."
        }
        return [System.Text.Encoding]::UTF8.GetString($out.ToArray()) -split "`r?`n"
    } catch {
        Write-Problem "could not read $($File.Name): $($_.Exception.Message)"
        return @()
    }
}

# Oldest first: dpkg.log.4.gz ... dpkg.log.1, dpkg.log. Sorting by name alone would put the live
# file first and .10 before .2. Date-suffixed RHEL rotations (yum.log-20230101) sort by the date.
function Get-Rotated([string]$Dir, [string]$Pattern) {
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }
    Get-ChildItem -LiteralPath $Dir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $Pattern } |
        Sort-Object @{ Expression = {
            if ($_.Name -match '\.(\d+)(\.gz)?$') { -[int]$Matches[1] }
            elseif ($_.Name -match '-(\d{8})(\.gz)?$') { [int]$Matches[1] - 100000000 }
            else { 0 }
        } }, Name
}

# name-version-release.arch, as rpm writes it. The name may itself contain hyphens, so split from
# the right: the last two hyphen-separated fields are version and release.
function Split-Nevra([string]$Value) {
    $arch = ''
    $body = $Value
    if ($body -match '^(.*)\.(x86_64|i686|i386|noarch|aarch64|ppc64le|s390x|armv7hl|src)$') {
        $body = $Matches[1]; $arch = $Matches[2]
    }
    if ($body -match '^(.+)-([^-]+)-([^-]+)$') {
        return @{ Package = $Matches[1]; Version = "$($Matches[2])-$($Matches[3])"; Arch = $arch }
    }
    return @{ Package = $body; Version = ''; Arch = $arch }
}

$logDir = Join-Path $Root 'var/log'
if (-not (Test-Path -LiteralPath $logDir)) { Write-Host "No var/log under $Root"; exit 0 }

$actions = New-Object System.Collections.Generic.List[object]
$transactions = New-Object System.Collections.Generic.List[object]
$filesRead = 0

# ---------------------------------------------------------------------------------------- dpkg
# 2026-05-28 18:47:20 upgrade libcups2:amd64 2.4.1-1ubuntu4.12 2.4.1-1ubuntu4.16
# 'status' and 'configure' lines repeat every action several times over as the package moves
# through its states; the four verbs below are the actions themselves.
foreach ($file in Get-Rotated $logDir '^dpkg\.log(\.\d+)?(\.gz)?$') {
    $filesRead++
    foreach ($line in Read-MaybeGzip $file) {
        if ($line -notmatch '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (install|upgrade|remove|purge) (\S+) (\S+) (\S+)') { continue }
        $time = $Matches[1]; $verb = $Matches[2]; $pkg = $Matches[3]; $old = $Matches[4]; $new = $Matches[5]

        $arch = ''
        if ($pkg -match '^(.+):(\S+)$') { $pkg = $Matches[1]; $arch = $Matches[2] }
        if ($old -eq '<none>') { $old = '' }
        if ($new -eq '<none>') { $new = '' }

        $actions.Add([pscustomobject]@{
            Timestamp    = $time
            RawTime      = $time
            YearInferred = 'no'
            Action       = (Get-Culture).TextInfo.ToTitleCase($verb)
            Package      = $pkg
            Arch         = $arch
            OldVersion   = $old
            NewVersion   = $new
            Manager      = 'dpkg'
            SourceFile   = $file.Name
        })
    }
}

# ------------------------------------------------------------------------------------- dnf.rpm
# 2023-05-01T10:15:02+0100 SUBDEBUG Upgrade: openssl-1:3.0.7-17.el9.x86_64
# 'Upgrade' is the incoming package and 'Upgraded' the outgoing one; likewise Downgrade(d) and
# Reinstall(ed). Both halves are kept so the old version is visible, labelled as dnf labels them.
foreach ($file in Get-Rotated $logDir '^dnf\.rpm\.log(\.\d+)?(\.gz)?$') {
    $filesRead++
    foreach ($line in Read-MaybeGzip $file) {
        if ($line -notmatch '^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S*\s+\S+\s+(Installed|Installing|Upgrade|Upgraded|Upgrading|Downgrade|Downgraded|Downgrading|Erase|Erased|Removed|Reinstall|Reinstalled|Obsoleted|Obsoleting):\s+(\S+)') { continue }
        $raw = ($line -split '\s+')[0]
        $time = "$($Matches[1]) $($Matches[2])"
        $verb = $Matches[3]
        $nevra = Split-Nevra $Matches[4]

        $actions.Add([pscustomobject]@{
            Timestamp    = $time
            RawTime      = $raw
            YearInferred = 'no'
            Action       = $verb
            Package      = $nevra.Package
            Arch         = $nevra.Arch
            OldVersion   = if ($verb -match '^(Upgraded|Downgraded|Erase|Erased|Removed|Obsoleted)$') { $nevra.Version } else { '' }
            NewVersion   = if ($verb -match '^(Upgraded|Downgraded|Erase|Erased|Removed|Obsoleted)$') { '' } else { $nevra.Version }
            Manager      = 'dnf'
            SourceFile   = $file.Name
        })
    }
}

# ----------------------------------------------------------------------------------------- yum
# Jan 05 10:15:02 Installed: nmap-6.40-19.el7.x86_64
# Epoch prefixes appear as '2:nmap-...' - strip before splitting.
$months = @{ Jan=1; Feb=2; Mar=3; Apr=4; May=5; Jun=6; Jul=7; Aug=8; Sep=9; Oct=10; Nov=11; Dec=12 }
foreach ($file in Get-Rotated $logDir '^yum\.log(-\d{8})?(\.\d+)?(\.gz)?$') {
    $filesRead++
    $reference = $file.LastWriteTime
    foreach ($line in Read-MaybeGzip $file) {
        if ($line -notmatch '^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(Installed|Updated|Erased|Obsoleted|Downgraded|Reinstalled):\s+(\S+)') { continue }
        $monthName = $Matches[1]; $day = [int]$Matches[2]
        $hour = [int]$Matches[3]; $minute = [int]$Matches[4]; $second = [int]$Matches[5]
        $verb = $Matches[6]; $spec = $Matches[7]

        $month = $months[$monthName]
        if (-not $month) { continue }

        $timestamp = ''
        try {
            # The constructor rejects an impossible date; Get-Date quietly rolls Feb 30 into March.
            $candidate = New-Object DateTime ($reference.Year, $month, $day, $hour, $minute, $second)
            if ($candidate -gt $reference.AddDays(1)) { $candidate = $candidate.AddYears(-1) }
            $timestamp = $candidate.ToString('yyyy-MM-dd HH:mm:ss')
        } catch { }

        $spec = $spec -replace '^\d+:', ''
        $nevra = Split-Nevra $spec
        $removed = $verb -in @('Erased', 'Obsoleted')

        $actions.Add([pscustomobject]@{
            Timestamp    = $timestamp
            RawTime      = "$monthName $day $($hour.ToString('00')):$($minute.ToString('00')):$($second.ToString('00'))"
            YearInferred = 'yes'
            Action       = $verb
            Package      = $nevra.Package
            Arch         = $nevra.Arch
            OldVersion   = if ($removed) { $nevra.Version } else { '' }
            NewVersion   = if ($removed) { '' } else { $nevra.Version }
            Manager      = 'yum'
            SourceFile   = $file.Name
        })
    }
}

# ------------------------------------------------------------------------------ apt history.log
# Start-Date: 2026-05-28  18:56:23
# Commandline: apt install python3 python3-pip git -y
# Requested-By: someone (1000)
# Install: pkg:amd64 (1.0-1), dep:amd64 (2.0-1, automatic)
# End-Date: 2026-05-28  18:56:40
#
# A block with no Requested-By was run as root directly or by unattended-upgrades, which is itself
# worth knowing: the absence is reported as such rather than left blank.
$aptDir = Join-Path $logDir 'apt'
foreach ($file in Get-Rotated $aptDir '^history\.log(\.\d+)?(\.gz)?$') {
    $filesRead++
    $block = $null

    $flush = {
        if ($null -eq $block) { return }
        $explicit = New-Object System.Collections.Generic.List[string]
        $counts = [ordered]@{ Install = 0; Upgrade = 0; Downgrade = 0; Reinstall = 0; Remove = 0; Purge = 0 }
        foreach ($kind in @($counts.Keys)) {
            if (-not $block.Contains($kind)) { continue }
            # Split on the '), ' between entries - versions contain commas only inside the parens.
            $entries = $block[$kind] -split '\),\s*'
            $counts[$kind] = @($entries | Where-Object { $_.Trim() }).Count
            foreach ($entry in $entries) {
                if ($entry -notmatch '^\s*([^:\s]+)(?::\S+)?\s+\((.*)$') { continue }
                # 'automatic' marks a dependency pulled in, not something anyone asked for.
                if ($Matches[2] -notmatch 'automatic') { $explicit.Add("$kind $($Matches[1])") }
            }
        }

        $requestedBy = ''; $uid = ''
        if ($block.Contains('Requested-By') -and $block['Requested-By'] -match '^(\S+)\s*\((\d+)\)') {
            $requestedBy = $Matches[1]; $uid = $Matches[2]
        } elseif ($block.Contains('Requested-By')) {
            $requestedBy = $block['Requested-By']
        } else {
            $requestedBy = '(none - root or unattended)'
        }

        $script:transactions.Add([pscustomobject]@{
            StartDate   = ($block['Start-Date'] -replace '\s+', ' ')
            EndDate     = ($block['End-Date'] -replace '\s+', ' ')
            RequestedBy = $requestedBy
            Uid         = $uid
            Commandline = $block['Commandline']
            Installed   = $counts.Install
            Upgraded    = $counts.Upgrade
            Downgraded  = $counts.Downgrade
            Reinstalled = $counts.Reinstall
            Removed     = $counts.Remove
            Purged      = $counts.Purge
            Explicit    = ($explicit -join '; ')
            Error       = $block['Error']
            SourceFile  = $file.Name
        })
    }

    foreach ($line in Read-MaybeGzip $file) {
        if ($line -match '^Start-Date:\s*(.*)$') {
            # Capture before flushing: the flush runs -match of its own, which replaces $Matches.
            $start = $Matches[1].Trim()
            . $flush
            $block = [ordered]@{ 'Start-Date' = $start }
            continue
        }
        if ($null -eq $block) { continue }
        if ($line -match '^([A-Za-z-]+):\s?(.*)$') { $block[$Matches[1]] = $Matches[2].Trim() }
    }
    . $flush
}

if ($filesRead -eq 0) { Write-Host "No dpkg.log, apt/history.log, dnf.rpm.log or yum.log under $logDir"; exit 0 }

if ($actions.Count -gt 0) {
    $sorted = $actions | Sort-Object Timestamp
    $sorted | Export-Csv -LiteralPath (Join-Path $Out 'LinuxPackages_Actions.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxPackages_Actions.csv       {0} row(s)" -f $actions.Count)
}
if ($transactions.Count -gt 0) {
    $sorted = $transactions | Sort-Object StartDate
    $sorted | Export-Csv -LiteralPath (Join-Path $Out 'LinuxPackages_Transactions.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxPackages_Transactions.csv  {0} row(s)" -f $transactions.Count)
}
if ($actions.Count -eq 0 -and $transactions.Count -eq 0) { Write-Host "Package logs present in $filesRead file(s) but no actions in them" }
