<#
.SYNOPSIS
    Parses Linux authentication logs into CSV, including rotated and gzipped history.

.DESCRIPTION
    Reads auth.log (Debian) and secure (RHEL) plus their rotated siblings, and classifies the lines
    that matter for triage: logins accepted and failed, sudo use, session open and close, and
    account creation or modification.

    TIMESTAMPS: classic syslog lines carry no year - 'Oct 29 10:23:45' and nothing more. The year
    is taken from the file's last-write time, and rolled back one year when that would place the
    entry in the future relative to the file, which is what happens for entries written before a
    new year in a log rotated after it. Every row records the raw field and whether the year was
    inferred, so nothing is lost to the guess.

    On an exported copy the last-write time may be the time of the copy rather than of the log, in
    which case the inference is only as good as that timestamp. RawTime is always preserved.

    rsyslog on Debian 12 and later writes RFC 3339 instead: '2026-10-29T10:23:45.123456+01:00'.
    Those lines carry their year and offset, so YearInferred is 'no' and TimestampUtc is filled.
    Timestamp is host local time for both formats, so the column means one thing throughout;
    TimestampUtc is blank for classic lines, which do not say what zone they were written in.
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

# Rotated logs are gzipped, and they hold most of the history. A parser that reads only the live
# file silently reports the last few days and looks like it worked.
#
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

# 'root(uid=0)' is how pam writes a user; the suffix is noise in a User column.
function Clean-User([string]$Value) {
    if (-not $Value) { return '' }
    return ($Value -replace '\(uid=\d+\)', '' -replace '[,:;.]+$', '').Trim()
}

$logDir = Join-Path $Root 'var/log'
if (-not (Test-Path -LiteralPath $logDir)) { Write-Host "No var/log under $Root"; exit 0 }

$files = Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue |
         Where-Object { $_.Name -match '^(auth\.log|secure)(\.\d+|-\d{8})?(\.gz)?$' } |
         Sort-Object @{ Expression = {
             # Oldest first. Debian numbers rotations (auth.log.2.gz); RHEL's default dateext
             # names them by date (secure-20260920), which the .N pattern alone never matched.
             if ($_.Name -match '\.(\d+)(\.gz)?$') { -[int]$Matches[1] }
             elseif ($_.Name -match '-(\d{8})(\.gz)?$') { [int]$Matches[1] - 100000000 }
             else { 0 }
         } }, Name

if (@($files).Count -eq 0) { Write-Host "No auth.log or secure files in $logDir"; exit 0 }

$months = @{ Jan=1; Feb=2; Mar=3; Apr=4; May=5; Jun=6; Jul=7; Aug=8; Sep=9; Oct=10; Nov=11; Dec=12 }
$rows = @()

foreach ($file in $files) {
    $reference = $file.LastWriteTime

    foreach ($line in Read-MaybeGzip $file) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $timestamp = ''; $timestampUtc = ''

        if ($line -match '^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})\s+(\S+)\s+([^:\[]+?)(?:\[(\d+)\])?:\s*(.*)$') {
            # 2026-10-29T10:23:45.123456+01:00 host process[pid]: message
            # RFC 3339, rsyslog's default on Debian 12 and later. Carries the year and the offset,
            # so nothing is inferred and the UTC time is exact.
            $rawTime   = $line.Substring(0, $line.IndexOf(' '))
            $fraction  = $Matches[3]
            $hostName  = $Matches[5]
            $process   = $Matches[6].Trim()
            $processId = $Matches[7]
            $message   = $Matches[8]
            $inferred  = 'no'

            try {
                $parsed = [DateTimeOffset]::Parse($rawTime, [Globalization.CultureInfo]::InvariantCulture)
                $format = if ($fraction) { 'yyyy-MM-dd HH:mm:ss.ffffff' } else { 'yyyy-MM-dd HH:mm:ss' }
                # Timestamp stays host local time, as written, so the column means the same thing
                # whichever format a file uses. TimestampUtc is filled only where the line says how.
                $timestamp    = $parsed.DateTime.ToString($format, [Globalization.CultureInfo]::InvariantCulture)
                $timestampUtc = $parsed.UtcDateTime.ToString($format, [Globalization.CultureInfo]::InvariantCulture)
            } catch { }
        }
        elseif ($line -match '^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^:\[]+?)(?:\[(\d+)\])?:\s*(.*)$') {
            # Oct 29 10:23:45 host process[pid]: message

            # Capture every group NOW. Any later -match overwrites $Matches, and reading it afterwards
            # silently yields fields from the wrong regex.
            $monthName = $Matches[1]
            $day       = [int]$Matches[2]
            $hour      = [int]$Matches[3]
            $minute    = [int]$Matches[4]
            $second    = [int]$Matches[5]
            $hostName  = $Matches[6]
            $process   = $Matches[7].Trim()
            $processId = $Matches[8]
            $message   = $Matches[9]
            $inferred  = 'yes'
            $rawTime   = "$monthName $day $($hour.ToString('00')):$($minute.ToString('00')):$($second.ToString('00'))"

            $month = $months[$monthName]
            if (-not $month) { continue }

            try {
                $candidate = Get-Date -Year $reference.Year -Month $month -Day $day `
                                      -Hour $hour -Minute $minute -Second $second -Millisecond 0
                # A log rotated in January still holds December entries. If the entry lands after the
                # file was written, it belongs to the previous year.
                if ($candidate -gt $reference.AddDays(1)) { $candidate = $candidate.AddYears(-1) }
                $timestamp = $candidate.ToString('yyyy-MM-dd HH:mm:ss')
            } catch { }
        }
        else { continue }

        $event = switch -Regex ($message) {
            'Accepted (password|publickey|keyboard-interactive)' { 'LoginSuccess';    break }
            'Failed (password|publickey)'                        { 'LoginFailed';     break }
            'Invalid user|invalid user'                          { 'InvalidUser';     break }
            'authentication failure|auth could not'              { 'AuthFailure';     break }
            'COMMAND='                                           { 'SudoCommand';     break }
            'session opened|New session'                         { 'SessionOpen';     break }
            'session closed|Removed session'                     { 'SessionClose';    break }
            'new user:|new group:'                               { 'AccountCreated';  break }
            'password changed'                                   { 'PasswordChanged'; break }
            'Disconnected from|Connection closed'                { 'Disconnect';      break }
            default { '' }
        }

        $user = ''
        if     ($message -match 'for invalid user\s+(\S+)')       { $user = $Matches[1] }
        elseif ($message -match 'for user\s+(\S+)')               { $user = $Matches[1] }
        elseif ($message -match '(?:^|\s)for\s+(\S+)\s+from')     { $user = $Matches[1] }
        elseif ($message -match 'of user\s+(\S+)')                { $user = $Matches[1] }
        elseif ($message -match '^\s*(\S+)\s*:\s*TTY=')           { $user = $Matches[1] }
        elseif ($message -match 'name=(\S+)')                     { $user = $Matches[1] }
        elseif ($message -match 'user=(\S+)')                     { $user = $Matches[1] }
        elseif ($message -match 'USER=(\S+)')                     { $user = $Matches[1] }

        $sourceIp = ''
        if ($message -match 'from\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,})') {
            $sourceIp = $Matches[1]
        }

        $command = ''
        if ($message -match 'COMMAND=(.+)$') { $command = $Matches[1].Trim() }

        $rows += [pscustomobject]@{
            Timestamp    = $timestamp
            TimestampUtc = $timestampUtc
            RawTime      = $rawTime
            YearInferred = $inferred
            Host         = $hostName
            Process      = $process
            PID          = $processId
            Event        = $event
            User         = Clean-User $user
            SourceIP     = $sourceIp
            Command      = $command
            Message      = $message
            SourceFile   = $file.Name
        }
    }
}

if (@($rows).Count -eq 0) { Write-Host "No parseable auth lines found"; exit 0 }

$sorted = $rows | Sort-Object Timestamp
$sorted | Export-Csv -LiteralPath (Join-Path $Out 'LinuxAuth_Events.csv') -NoTypeInformation -Encoding UTF8
Write-Host ("  LinuxAuth_Events.csv         {0} row(s) from {1} file(s)" -f @($sorted).Count, @($files).Count)

# A separate view of the events worth looking at first, so they are not buried in session noise.
$interesting = $sorted | Where-Object {
    $_.Event -in @('LoginSuccess','LoginFailed','InvalidUser','AuthFailure','AccountCreated','SudoCommand','PasswordChanged')
}
if (@($interesting).Count -gt 0) {
    $interesting | Export-Csv -LiteralPath (Join-Path $Out 'LinuxAuth_KeyEvents.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxAuth_KeyEvents.csv      {0} row(s)" -f @($interesting).Count)
}
