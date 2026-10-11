<#
.SYNOPSIS
    Parses the binary login databases: wtmp, btmp and lastlog.

.DESCRIPTION
    wtmp  - login and logout history, plus boot and runlevel records
    btmp  - failed login attempts
    lastlog - the most recent login per UID, indexed by UID rather than appended

    These are fixed-size C structs, so they are read directly rather than needing a Linux tool.

    STRUCT SIZES ARE ARCHITECTURE-DEPENDENT. This reads the 384-byte utmp of Linux x86_64 and the
    292-byte lastlog entry that goes with it. The record count is validated against the file size
    before anything is parsed, so a 32-bit or non-glibc layout is reported rather than silently
    producing garbage rows - which is the failure mode that matters here, because plausible-looking
    nonsense in a login table is worse than no table.
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

$UtmpSize    = 384
$LastlogSize = 292
$Epoch       = [datetime]'1970-01-01T00:00:00Z'

$UtmpTypes = @{
    0 = 'EMPTY'; 1 = 'RUN_LVL'; 2 = 'BOOT_TIME'; 3 = 'NEW_TIME'; 4 = 'OLD_TIME'
    5 = 'INIT_PROCESS'; 6 = 'LOGIN_PROCESS'; 7 = 'USER_PROCESS'; 8 = 'DEAD_PROCESS'; 9 = 'ACCOUNTING'
}

# Fixed-width char arrays are NUL-padded; everything after the first NUL is padding, not data.
function Read-FixedString([byte[]]$Bytes, [int]$Offset, [int]$Length) {
    $end = $Offset
    $limit = $Offset + $Length
    while ($end -lt $limit -and $Bytes[$end] -ne 0) { $end++ }
    if ($end -eq $Offset) { return '' }
    return [System.Text.Encoding]::ASCII.GetString($Bytes, $Offset, $end - $Offset)
}

function Parse-Utmp([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { Write-Host "  $Label is empty"; return @() }

    if ($bytes.Length % $UtmpSize -ne 0) {
        Write-Problem "$Label is $($bytes.Length) bytes, not a multiple of $UtmpSize - not a 64-bit Linux utmp, skipping rather than guessing"
        return @()
    }

    $rows = @()
    for ($offset = 0; $offset -lt $bytes.Length; $offset += $UtmpSize) {
        $type = [BitConverter]::ToInt16($bytes, $offset)
        if ($type -eq 0) { continue }   # EMPTY - never written to, not evidence of anything

        $seconds = [BitConverter]::ToInt32($bytes, $offset + 340)
        $when = ''
        if ($seconds -gt 0) { $when = $Epoch.AddSeconds($seconds).ToString('yyyy-MM-dd HH:mm:ss') }

        $rows += [pscustomobject]@{
            TimestampUtc = $when
            Type         = if ($UtmpTypes.ContainsKey([int]$type)) { $UtmpTypes[[int]$type] } else { "UNKNOWN($type)" }
            User         = Read-FixedString $bytes ($offset + 44) 32
            Terminal     = Read-FixedString $bytes ($offset + 8) 32
            Host         = Read-FixedString $bytes ($offset + 76) 256
            PID          = [BitConverter]::ToInt32($bytes, $offset + 4)
            Source       = $Label
        }
    }
    return $rows
}

$logDir = Join-Path $Root 'var/log'

# --- wtmp: successful logins, logouts, boots -----------------------------------------------------
$wtmp = Parse-Utmp (Join-Path $logDir 'wtmp') 'wtmp'
if (@($wtmp).Count -gt 0) {
    $wtmp | Sort-Object TimestampUtc |
        Export-Csv -LiteralPath (Join-Path $Out 'LinuxLogins_wtmp.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxLogins_wtmp.csv         {0} row(s)" -f @($wtmp).Count)
}

# --- btmp: failed logins -------------------------------------------------------------------------
# Usually root-only, so an unprivileged collection may simply not have it.
$btmp = Parse-Utmp (Join-Path $logDir 'btmp') 'btmp'
if (@($btmp).Count -gt 0) {
    $btmp | Sort-Object TimestampUtc |
        Export-Csv -LiteralPath (Join-Path $Out 'LinuxLogins_btmp.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxLogins_btmp.csv         {0} row(s)" -f @($btmp).Count)
}

# --- lastlog: most recent login per UID ----------------------------------------------------------
# Indexed by UID rather than appended, so the row number IS the UID and most rows are zeroed.
$lastlogPath = Join-Path $logDir 'lastlog'
if (Test-Path -LiteralPath $lastlogPath) {
    $bytes = [System.IO.File]::ReadAllBytes($lastlogPath)

    if ($bytes.Length % $LastlogSize -ne 0) {
        Write-Problem "lastlog is $($bytes.Length) bytes, not a multiple of $LastlogSize - skipping rather than guessing"
    } else {
        # Resolve UIDs to names where passwd came along too.
        $names = @{}
        $passwd = Join-Path $Root 'etc/passwd'
        if (Test-Path -LiteralPath $passwd) {
            foreach ($line in Get-Content -LiteralPath $passwd -ErrorAction SilentlyContinue) {
                $f = $line -split ':'
                if ($f.Count -ge 3 -and $f[2] -match '^\d+$') { $names[[int]$f[2]] = $f[0] }
            }
        }

        $rows = @()
        $uid = 0
        for ($offset = 0; $offset -lt $bytes.Length; $offset += $LastlogSize) {
            $seconds = [BitConverter]::ToInt32($bytes, $offset)
            if ($seconds -gt 0) {
                $rows += [pscustomobject]@{
                    TimestampUtc = $Epoch.AddSeconds($seconds).ToString('yyyy-MM-dd HH:mm:ss')
                    UID          = $uid
                    User         = if ($names.ContainsKey($uid)) { $names[$uid] } else { '' }
                    Terminal     = Read-FixedString $bytes ($offset + 4) 32
                    Host         = Read-FixedString $bytes ($offset + 36) 256
                }
            }
            $uid++
        }

        if (@($rows).Count -gt 0) {
            $rows | Sort-Object TimestampUtc |
                Export-Csv -LiteralPath (Join-Path $Out 'LinuxLogins_lastlog.csv') -NoTypeInformation -Encoding UTF8
            Write-Host ("  LinuxLogins_lastlog.csv      {0} account(s) with a recorded login" -f @($rows).Count)
        } else {
            Write-Host "  lastlog holds no recorded logins"
        }
    }
}
