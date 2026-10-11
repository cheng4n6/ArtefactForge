<#
.SYNOPSIS
    Builds the system summary for a Linux collection: identity, OS, time, network and accounts.

.DESCRIPTION
    Produces two renderings of one parse:

      SystemInfo.csv - Category / Item / Value / Source, for filtering and for the case roll-up
      SystemInfo.txt - the same facts laid out to be read at a glance

    Every row carries the file it came from. A summary that cannot be traced back to a source is
    an assertion rather than evidence, and the source is what someone checks when a value looks
    wrong.

    Absent values are recorded as rows with an empty value rather than omitted, so the difference
    between "not collected" and "not set" stays visible.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Out,
    [string]$Collection = ''
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force -Path $Out | Out-Null }

$facts = New-Object System.Collections.ArrayList
function Add-Fact([string]$Category, [string]$Item, $Value, [string]$Source) {
    [void]$facts.Add([pscustomobject]@{
        Category = $Category; Item = $Item; Value = "$Value".Trim(); Source = $Source
    })
}
# Three states, not two. Key files under /etc are symlinks to targets outside it - Ubuntu's
# os-release points at ../usr/lib/os-release - so an export of /etc alone leaves a link that
# Test-Path reports as existing and Get-Content cannot read. Silently treating that as "absent"
# is how a summary ends up with no Operating System section and nobody notices.
$script:unreadable = New-Object System.Collections.ArrayList

# A collection unpacked from a tar or zip (UAC) lists its symbolic links in _symlinks.csv instead of
# creating them. Linux paths are case-sensitive, so the lookup is ordinal.
$script:links = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
$linkList = Join-Path $Root '_symlinks.csv'
if (Test-Path -LiteralPath $linkList) {
    foreach ($link in (Import-Csv -LiteralPath $linkList)) { $script:links[$link.Path] = "$($link.Target)" }
}

# Follows listed links to a path relative to the root, or $null when a link leaves the collection
# or loops. An absolute target is relative to the collected system's root, not this machine's.
function Resolve-ListedLink([string]$Relative) {
    $current = $Relative
    for ($hop = 0; $hop -lt 8 -and $script:links.ContainsKey($current); $hop++) {
        $target = $script:links[$current]
        if (-not $target) { return $null }
        $parts = New-Object System.Collections.ArrayList
        if (-not $target.StartsWith('/')) {
            $dir = @($current -split '/' | Where-Object { $_ })
            if ($dir.Count -gt 1) { [void]$parts.AddRange(@($dir[0..($dir.Count - 2)])) }
        }
        foreach ($part in ($target -split '/')) {
            if ($part -eq '' -or $part -eq '.') { continue }
            if ($part -eq '..') {
                if ($parts.Count -eq 0) { return $null }
                $parts.RemoveAt($parts.Count - 1)
                continue
            }
            [void]$parts.Add($part)
        }
        $current = $parts -join '/'
    }
    if ($script:links.ContainsKey($current)) { return $null }
    return $current
}

function Resolve-Source([string]$Relative) {
    $path = Join-Path $Root $Relative
    if (-not (Test-Path -LiteralPath $path) -and $script:links.ContainsKey($Relative)) {
        # Readable only if the link's target was collected too, exactly as for a link on disk.
        $resolved = Resolve-ListedLink $Relative
        if ($resolved -and (Test-Path -LiteralPath (Join-Path $Root $resolved) -PathType Leaf)) {
            return @{ State = 'ok'; Path = (Join-Path $Root $resolved) }
        }
        [void]$script:unreadable.Add("$Relative -> $($script:links[$Relative])")
        return @{ State = 'dangling'; Target = $script:links[$Relative] }
    }
    if (-not (Test-Path -LiteralPath $path)) { return @{ State = 'missing' } }

    try {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            $target = ''
            try { $target = (Get-Item -LiteralPath $path -Force).Target } catch { }
            if ($target -is [array]) { $target = $target[0] }

            # Reading proves whether the target came along; the link itself never does.
            try { [void](Get-Content -LiteralPath $path -TotalCount 1 -ErrorAction Stop) }
            catch {
                [void]$script:unreadable.Add("$Relative -> $(if ($target) { $target } else { 'unresolvable' })")
                return @{ State = 'dangling'; Target = "$target" }
            }
        }
    } catch { return @{ State = 'missing' } }

    return @{ State = 'ok'; Path = $path }
}

function Read-First([string]$Relative) {
    $source = Resolve-Source $Relative
    if ($source.State -ne 'ok') { return $null }
    try { return (Get-Content -LiteralPath $source.Path -TotalCount 1 -ErrorAction Stop) } catch { return $null }
}

function Read-All([string]$Relative) {
    $source = Resolve-Source $Relative
    if ($source.State -ne 'ok') { return @() }
    try { return Get-Content -LiteralPath $source.Path -ErrorAction Stop } catch { return @() }
}

# --- identity -------------------------------------------------------------------------------------
Add-Fact 'Identity' 'Hostname'  (Read-First 'etc/hostname')   'etc/hostname'
# machine-id survives a rename and is identical on cloned VMs - which is how you spot a clone.
Add-Fact 'Identity' 'MachineID' (Read-First 'etc/machine-id') 'etc/machine-id'

$hostsPath = Join-Path $Root 'etc/hosts'
if (Test-Path -LiteralPath $hostsPath) {
    $entries = @()
    foreach ($line in (Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue)) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        # Loopback lines are boilerplate; anything else was added, deliberately or otherwise.
        if ($t -match '^(127\.|::1|fe00::|ff0)') { continue }
        $entries += $t
    }
    Add-Fact 'Identity' 'HostsEntries' ($entries -join ' | ') 'etc/hosts'
}

# --- operating system -----------------------------------------------------------------------------
# /etc/os-release is a symlink into /usr/lib on Debian and Ubuntu, so fall back to the real
# location and then to the older lsb-release before giving up.
$osFound = $false
foreach ($candidate in @('etc/os-release', 'usr/lib/os-release', 'etc/lsb-release')) {
    $lines = Read-All $candidate
    if (@($lines).Count -eq 0) { continue }

    foreach ($line in $lines) {
        if ($line -notmatch '^([A-Z_]+)="?([^"]*)"?$') { continue }
        if ($Matches[1] -in @('PRETTY_NAME','ID','VERSION_ID','VERSION_CODENAME','BUILD_ID',
                              'DISTRIB_ID','DISTRIB_RELEASE','DISTRIB_DESCRIPTION')) {
            Add-Fact 'OperatingSystem' $Matches[1] $Matches[2] $candidate
            $osFound = $true
        }
    }
    if ($osFound) { break }
}
if (-not $osFound) { Add-Fact 'OperatingSystem' 'PRETTY_NAME' '' 'etc/os-release (not readable)' }

# Kernel version is not in a config file offline; the installed kernel images name it.
$bootDir = Join-Path $Root 'boot'
if (Test-Path -LiteralPath $bootDir) {
    $kernels = Get-ChildItem -LiteralPath $bootDir -Filter 'vmlinuz-*' -ErrorAction SilentlyContinue |
               ForEach-Object { $_.Name -replace '^vmlinuz-', '' }
    if ($kernels) { Add-Fact 'OperatingSystem' 'InstalledKernels' ($kernels -join ', ') 'boot/' }
}

# --- time -----------------------------------------------------------------------------------------
# The single most consequential value here. Everything ArtefactForge writes is UTC, so this is what
# reconciles the output with anything a person reports in local time.
$tz = Read-First 'etc/timezone'
if ($tz) {
    Add-Fact 'Time' 'Timezone' $tz 'etc/timezone'
} else {
    # RHEL has no /etc/timezone; the zone is the target of the /etc/localtime symlink.
    $localtime = Join-Path $Root 'etc/localtime'
    if ($script:links.ContainsKey('etc/localtime') -and -not (Test-Path -LiteralPath $localtime)) {
        $target = $script:links['etc/localtime']
        if ($target) { Add-Fact 'Time' 'Timezone' ($target -replace '.*zoneinfo/', '') 'etc/localtime' }
        else { Add-Fact 'Time' 'Timezone' '' 'etc/localtime (symlink target not recorded)' }
    } elseif (Test-Path -LiteralPath $localtime) {
        $target = ''
        try { $target = (Get-Item -LiteralPath $localtime -Force).Target } catch { }
        if ($target -is [array]) { $target = $target[0] }
        if ($target) { Add-Fact 'Time' 'Timezone' (("$target" -replace '.*zoneinfo/', '')) 'etc/localtime' }
        else { Add-Fact 'Time' 'Timezone' '' 'etc/localtime (symlink not resolvable)' }
    }
}

# Ubuntu records the install in the installer log directory.
foreach ($candidate in @('var/log/installer/media-info', 'root/anaconda-ks.cfg')) {
    $path = Join-Path $Root $candidate
    if (Test-Path -LiteralPath $path) {
        Add-Fact 'Time' 'InstallEvidence' (Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') $candidate
        break
    }
}

# --- network --------------------------------------------------------------------------------------
$dns = @()
if ($true) {
    foreach ($line in (Read-All 'etc/resolv.conf')) {
        if ($line -match '^\s*nameserver\s+(\S+)') { $dns += $Matches[1] }
        if ($line -match '^\s*(search|domain)\s+(.+)$') { Add-Fact 'Network' 'SearchDomain' $Matches[2] 'etc/resolv.conf' }
    }
    Add-Fact 'Network' 'DnsServers' ($dns -join ', ') 'etc/resolv.conf'
}

# Addresses live in whichever configuration system the distribution uses.
foreach ($spec in @(
    @{ Path = 'etc/netplan';                     Filter = '*.yaml'; Label = 'netplan' },
    @{ Path = 'etc/NetworkManager/system-connections'; Filter = '*';  Label = 'NetworkManager' })) {

    $dir = Join-Path $Root $spec.Path
    if (-not (Test-Path -LiteralPath $dir)) { continue }

    foreach ($file in (Get-ChildItem -LiteralPath $dir -Filter $spec.Filter -File -ErrorAction SilentlyContinue)) {
        $addresses = @()
        foreach ($line in (Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue)) {
            if ($line -match '(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})') { $addresses += $Matches[1] }
            elseif ($line -match '^\s*address\d*=(\S+)')          { $addresses += $Matches[1] }
            if ($line -match '^\s*dhcp4:\s*(true|yes)')           { Add-Fact 'Network' 'DHCP' 'enabled' "$($spec.Path)/$($file.Name)" }
        }
        if ($addresses.Count -gt 0) {
            Add-Fact 'Network' 'IPAddresses' (($addresses | Select-Object -Unique) -join ', ') "$($spec.Path)/$($file.Name)"
        }
        Add-Fact 'Network' 'ConfigFile' $file.Name $spec.Label
    }
}

$interfaces = Join-Path $Root 'etc/network/interfaces'
if (Test-Path -LiteralPath $interfaces) {
    foreach ($line in (Get-Content -LiteralPath $interfaces -ErrorAction SilentlyContinue)) {
        if ($line -match '^\s*address\s+(\S+)') { Add-Fact 'Network' 'IPAddresses' $Matches[1] 'etc/network/interfaces' }
    }
}

# --- domain membership ------------------------------------------------------------------------------
foreach ($spec in @(
    @{ File = 'etc/sssd/sssd.conf'; Pattern = '^\s*(domains|ad_domain|ldap_uri)\s*=\s*(.+)$' },
    @{ File = 'etc/krb5.conf';      Pattern = '^\s*default_realm\s*=\s*(.+)$' })) {

    $path = Join-Path $Root $spec.File
    if (-not (Test-Path -LiteralPath $path)) { continue }
    foreach ($line in (Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
        if ($line -match $spec.Pattern) {
            Add-Fact 'Domain' ($Matches[1]) ($Matches[$Matches.Count - 1]) $spec.File
        }
    }
}

# --- accounts ---------------------------------------------------------------------------------------
$passwdPath = Join-Path $Root 'etc/passwd'
if (Test-Path -LiteralPath $passwdPath) {
    $all = @(); $interactive = @(); $uid0 = @()
    foreach ($line in (Get-Content -LiteralPath $passwdPath -ErrorAction SilentlyContinue)) {
        $f = $line -split ':'
        if ($f.Count -lt 7) { continue }
        $all += $f[0]
        if ([int]$f[2] -eq 0) { $uid0 += $f[0] }
        if ($f[6] -notmatch 'nologin|/false$') { $interactive += "$($f[0]) (uid $($f[2]))" }
    }
    Add-Fact 'Accounts' 'TotalAccounts'      $all.Count               'etc/passwd'
    Add-Fact 'Accounts' 'InteractiveAccounts' ($interactive -join ', ') 'etc/passwd'
    Add-Fact 'Accounts' 'UID0Accounts'       ($uid0 -join ', ')       'etc/passwd'
}

$groupPath = Join-Path $Root 'etc/group'
if (Test-Path -LiteralPath $groupPath) {
    foreach ($line in (Get-Content -LiteralPath $groupPath -ErrorAction SilentlyContinue)) {
        $f = $line -split ':'
        if ($f.Count -ge 4 -and $f[0] -in @('sudo','wheel','admin','docker','lxd') -and $f[3]) {
            Add-Fact 'Accounts' "Group:$($f[0])" $f[3] 'etc/group'
        }
    }
}

# --- last boot ---------------------------------------------------------------------------------------
# BOOT_TIME records in wtmp; the struct layout is the same one the logins parser validates.
$wtmp = Join-Path $Root 'var/log/wtmp'
if (Test-Path -LiteralPath $wtmp) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($wtmp)
        if ($bytes.Length -gt 0 -and $bytes.Length % 384 -eq 0) {
            $epoch = [datetime]'1970-01-01T00:00:00Z'
            $boots = @()
            for ($offset = 0; $offset -lt $bytes.Length; $offset += 384) {
                if ([BitConverter]::ToInt16($bytes, $offset) -ne 2) { continue }   # BOOT_TIME
                $seconds = [BitConverter]::ToInt32($bytes, $offset + 340)
                if ($seconds -gt 0) { $boots += $epoch.AddSeconds($seconds) }
            }
            if ($boots.Count -gt 0) {
                Add-Fact 'Time' 'LastBootUtc'  ($boots | Sort-Object | Select-Object -Last 1).ToString('yyyy-MM-dd HH:mm:ss') 'var/log/wtmp'
                Add-Fact 'Time' 'FirstBootUtc' ($boots | Sort-Object | Select-Object -First 1).ToString('yyyy-MM-dd HH:mm:ss') 'var/log/wtmp'
                Add-Fact 'Time' 'BootCount'    $boots.Count 'var/log/wtmp'
            }
        }
    } catch { }
}

# --- collection completeness -------------------------------------------------------------------------
# Anything here is a file that WAS collected as a link but whose target was not, which usually means
# the export covered /etc but not /usr. It is a gap in the collection, not in the system.
if ($script:unreadable.Count -gt 0) {
    foreach ($entry in $script:unreadable) {
        Add-Fact 'CollectionGaps' 'UnreadableSymlink' $entry 'link target not collected'
    }
}

# --- write ------------------------------------------------------------------------------------------
$facts | Export-Csv -LiteralPath (Join-Path $Out 'SystemInfo.csv') -NoTypeInformation -Encoding UTF8

$report = New-Object System.Text.StringBuilder
[void]$report.AppendLine("System summary" + $(if ($Collection) { " - $Collection" } else { '' }))
[void]$report.AppendLine(('=' * 70))
[void]$report.AppendLine("Source: $Root")
[void]$report.AppendLine("Built:  $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC")
[void]$report.AppendLine()

foreach ($group in ($facts | Group-Object Category)) {
    [void]$report.AppendLine($group.Name)
    [void]$report.AppendLine(('-' * 70))
    foreach ($fact in $group.Group) {
        $value = if ($fact.Value) { $fact.Value } else { '(not present)' }
        [void]$report.AppendLine(("  {0,-22} {1}" -f $fact.Item, $value))
    }
    [void]$report.AppendLine()
}

[System.IO.File]::WriteAllText((Join-Path $Out 'SystemInfo.txt'), $report.ToString())
Write-Host ("  SystemInfo.csv / .txt        {0} fact(s)" -f $facts.Count)
