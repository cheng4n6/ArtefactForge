<#
.SYNOPSIS
    Parses the per-profile artefacts: shell history, SSH keys and other tools' history.

.DESCRIPTION
    Runs once per user profile, so it is given one home directory rather than the filesystem root.
    The parameter is HomeDir, not Home: $Home is a read-only automatic variable in PowerShell and a
    parameter of that name cannot be bound.
    That matters on Linux, where root's home sits outside /home and a module that assumed a single
    parent would miss it entirely.

    Shell history files carry no timestamps by default. bash only records them when HISTTIMEFORMAT
    is set, in which case a '#<epoch>' line precedes each command - handled here when present, and
    the line number is kept either way so ordering survives.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HomeDir,
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force -Path $Out | Out-Null }

$Epoch = [datetime]'1970-01-01T00:00:00Z'

# --- shell history -------------------------------------------------------------------------------
$history = @()
foreach ($name in @('.bash_history', '.zsh_history', '.sh_history', '.ash_history', '.python_history')) {
    $path = Join-Path $HomeDir $name
    if (-not (Test-Path -LiteralPath $path)) { continue }

    $n = 0
    $pending = ''
    try { $lines = Get-Content -LiteralPath $path -ErrorAction Stop } catch { continue }

    foreach ($line in $lines) {
        $n++

        # bash writes '#1698600000' before a command when HISTTIMEFORMAT is set.
        if ($line -match '^#(\d{9,})\s*$') { $pending = $Epoch.AddSeconds([int64]$Matches[1]).ToString('yyyy-MM-dd HH:mm:ss'); continue }

        # zsh extended history: ': 1698600000:0;command'
        $command = $line
        $when = $pending
        if ($line -match '^:\s*(\d{9,}):\d+;(.*)$') {
            $when = $Epoch.AddSeconds([int64]$Matches[1]).ToString('yyyy-MM-dd HH:mm:ss')
            $command = $Matches[2]
        }

        $pending = ''
        if ([string]::IsNullOrWhiteSpace($command)) { continue }

        $history += [pscustomobject]@{
            User         = $User
            SourceFile   = $name
            Line         = $n
            TimestampUtc = $when
            Command      = $command.Trim()
            # Cheap flags for the commands worth reading first.
            Suspicious   = if ($command -match 'curl|wget|nc |netcat|base64|chmod \+x|/dev/tcp|python -c|perl -e|ssh-keygen|history -c|shred|rm -rf') { 'review' } else { '' }
        }
    }
}

if (@($history).Count -gt 0) {
    $history | Export-Csv -LiteralPath (Join-Path $Out "${User}_LinuxUserFiles_ShellHistory.csv") -NoTypeInformation -Encoding UTF8
    Write-Host ("  {0} shell history: {1} command(s), {2} flagged" -f `
                $User, @($history).Count, @($history | Where-Object { $_.Suspicious }).Count)
}

# --- ssh ------------------------------------------------------------------------------------------
$ssh = @()
$sshDir = Join-Path $HomeDir '.ssh'
if (Test-Path -LiteralPath $sshDir) {
    foreach ($name in @('authorized_keys', 'authorized_keys2')) {
        $path = Join-Path $sshDir $name
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $n = 0
        foreach ($line in (Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
            $n++
            $trimmed = $line.Trim()
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }

            # An authorized key is a standing grant of access - the comment field is the only clue
            # to who owns it, and it is attacker-controlled, so it is reported verbatim.
            $parts = $trimmed -split '\s+'
            $ssh += [pscustomobject]@{
                User     = $User
                Kind     = 'AuthorizedKey'
                File     = $name
                Line     = $n
                KeyType  = if ($parts.Count -ge 1) { $parts[0] } else { '' }
                Comment  = if ($parts.Count -ge 3) { ($parts[2..($parts.Count-1)] -join ' ') } else { '' }
                Options  = if ($trimmed -match '^(command=|no-pty|from=)') { 'yes' } else { '' }
            }
        }
    }

    $known = Join-Path $sshDir 'known_hosts'
    if (Test-Path -LiteralPath $known) {
        $n = 0
        foreach ($line in (Get-Content -LiteralPath $known -ErrorAction SilentlyContinue)) {
            $n++
            $trimmed = $line.Trim()
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
            $parts = $trimmed -split '\s+'
            $ssh += [pscustomobject]@{
                User     = $User
                Kind     = 'KnownHost'
                File     = 'known_hosts'
                Line     = $n
                KeyType  = if ($parts.Count -ge 2) { $parts[1] } else { '' }
                # Hashed entries start with '|1|' and cannot be resolved back to a hostname.
                Comment  = if ($parts[0].StartsWith('|1|')) { '(hashed)' } else { $parts[0] }
                Options  = ''
            }
        }
    }
}

if (@($ssh).Count -gt 0) {
    $ssh | Export-Csv -LiteralPath (Join-Path $Out "${User}_LinuxUserFiles_Ssh.csv") -NoTypeInformation -Encoding UTF8
    Write-Host ("  {0} ssh: {1} entr(ies)" -f $User, @($ssh).Count)
}

# --- other history ----------------------------------------------------------------------------------
# What other tools remember: vim (commands, searches, files edited), less (searches, shell escapes),
# database and REPL clients, wget's HSTS host list, the desktop's recently used files, and the
# marker Ubuntu writes the first time a user's sudo succeeds. Each row says which file it came from;
# TimeUtc is filled only where the file itself records a time.
$other = New-Object System.Collections.ArrayList
function Add-Other([string]$Source, [string]$Type, [int]$Line, [string]$Entry, [string]$TimeUtc) {
    [void]$other.Add([pscustomobject]@{
        User = $User; Source = $Source; Type = $Type; Line = $Line; Entry = $Entry; TimeUtc = $TimeUtc
    })
}
function From-Epoch([string]$Value) {
    $seconds = 0L
    if (-not [long]::TryParse($Value, [ref]$seconds) -or $seconds -le 0) { return '' }
    return $Epoch.AddSeconds($seconds).ToString('yyyy-MM-dd HH:mm:ss')
}

# vim: ':' lines are commands, '?' and '/' lines searches, '> path' lines files with marks. vim 8
# follows an entry with '|2,0,<epoch>,...' (history) or '|4,<mark>,<line>,<col>,<epoch>,...' (marks),
# which gives it a time.
$viminfo = Join-Path $HomeDir '.viminfo'
if (Test-Path -LiteralPath $viminfo) {
    $lines = @(Get-Content -LiteralPath $viminfo -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $next = if ($i + 1 -lt $lines.Count) { $lines[$i + 1] } else { '' }
        $time = ''
        if ($next -match '^\|2,\d+,(\d+),') { $time = From-Epoch $Matches[1] }
        if ($line.StartsWith(':')) { Add-Other '.viminfo' 'vim command' ($i + 1) $line.Substring(1) $time }
        elseif ($line -match '^\?[/?]?(.*)$' -and $line.Length -gt 1) { Add-Other '.viminfo' 'vim search' ($i + 1) $Matches[1] $time }
        elseif ($line.StartsWith('> ')) { Add-Other '.viminfo' 'vim file edited' ($i + 1) $line.Substring(2) '' }
        elseif ($line -match '^\|4,\d+,\d+,\d+,(\d+),"(.*)"$') { Add-Other '.viminfo' 'vim file mark' ($i + 1) $Matches[2] (From-Epoch $Matches[1]) }
    }
}

# less: '.search' and '.shell' sections; each entry starts with a double quote.
$lesshst = Join-Path $HomeDir '.lesshst'
if (Test-Path -LiteralPath $lesshst) {
    $section = ''
    $n = 0
    foreach ($line in (Get-Content -LiteralPath $lesshst -ErrorAction SilentlyContinue)) {
        $n++
        if ($line -eq '.search') { $section = 'less search'; continue }
        if ($line -eq '.shell') { $section = 'less shell command'; continue }
        if ($section -and $line.StartsWith('"')) { Add-Other '.lesshst' $section $n $line.Substring(1) '' }
    }
}

# Database and REPL clients. mysql's libedit history escapes spaces as \040.
foreach ($pair in @(@('.mysql_history', 'mysql'), @('.psql_history', 'psql'), @('.sqlite_history', 'sqlite'),
                    @('.node_repl_history', 'node'), @('.rediscli_history', 'redis-cli'), @('.irb_history', 'ruby irb'))) {
    $path = Join-Path $HomeDir $pair[0]
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $n = 0
    foreach ($line in (Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $n++
        if ($line -eq '' -or $line -eq '_HiStOrY_V2_') { continue }
        $text = [regex]::Replace($line, '\\([0-7]{3})', { param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 8) })
        Add-Other $pair[0] ($pair[1] + ' command') $n $text ''
    }
}

# wget remembers every host that sent it an HSTS header: host, port, subdomains, created, max-age.
$hsts = Join-Path $HomeDir '.wget-hsts'
if (Test-Path -LiteralPath $hsts) {
    $n = 0
    foreach ($line in (Get-Content -LiteralPath $hsts -ErrorAction SilentlyContinue)) {
        $n++
        if ($line.StartsWith('#') -or $line.Trim() -eq '') { continue }
        $f = $line -split '\s+'
        if ($f.Count -ge 4) { Add-Other '.wget-hsts' 'wget HTTPS host' $n $f[0] (From-Epoch $f[3]) }
    }
}

# Desktop sessions: files opened, with when.
$recent = Join-Path $HomeDir '.local/share/recently-used.xbel'
if (Test-Path -LiteralPath $recent) {
    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($recent)
        $n = 0
        foreach ($bookmark in $xml.SelectNodes('//bookmark')) {
            $n++
            $when = $bookmark.GetAttribute('visited')
            if (-not $when) { $when = $bookmark.GetAttribute('modified') }
            $utc = ''
            $parsed = [datetime]::MinValue
            if ($when -and [datetime]::TryParse($when, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) {
                $utc = $parsed.ToString('yyyy-MM-dd HH:mm:ss')
            }
            Add-Other 'recently-used.xbel' 'recent file (desktop)' $n ([Uri]::UnescapeDataString($bookmark.GetAttribute('href'))) $utc
        }
    } catch {
        [Console]::Error.WriteLine("${User}: recently-used.xbel could not be read: $($_.Exception.Message)")
    }
}

# Ubuntu creates this the first time the user's sudo succeeds; its time is that moment.
$sudoMarker = Join-Path $HomeDir '.sudo_as_admin_successful'
if (Test-Path -LiteralPath $sudoMarker) {
    $stamp = (Get-Item -LiteralPath $sudoMarker -Force).LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
    Add-Other '.sudo_as_admin_successful' 'sudo first used (marker file time)' 0 '' $stamp
}

if ($other.Count -gt 0) {
    $other | Export-Csv -LiteralPath (Join-Path $Out "${User}_LinuxUserFiles_OtherHistory.csv") -NoTypeInformation -Encoding UTF8
    Write-Host ("  {0} other history: {1} entr(ies)" -f $User, $other.Count)
}

if (@($history).Count -eq 0 -and @($ssh).Count -eq 0 -and $other.Count -eq 0) { Write-Host "  $User - nothing to parse" }
