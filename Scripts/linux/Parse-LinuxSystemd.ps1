<#
.SYNOPSIS
    Parses systemd units and their enablement state.

.DESCRIPTION
    Two different things live under /etc/systemd/system, and the difference is the whole point:

      - A real FILE is a unit defined locally, overriding or adding to what the packages provide.
        That is a classic persistence location - a unit nobody installed is worth explaining.
      - A SYMLINK inside a *.wants directory is an enablement record, pointing at a unit that
        lives elsewhere. It says the unit runs at boot.

    Enablement is read from the link TARGET STRING, never by following the link. In a partial
    collection the target lives under /usr/lib or /lib and will not have been captured, so
    following it would silently drop every enabled unit.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force -Path $Out | Out-Null }

$unitDirs = @('etc/systemd/system', 'usr/lib/systemd/system', 'lib/systemd/system') |
            ForEach-Object { Join-Path $Root $_ } |
            Where-Object { Test-Path -LiteralPath $_ }

if (@($unitDirs).Count -eq 0) { Write-Host "No systemd unit directories under $Root"; exit 0 }

$units = @()
$enabled = @()

foreach ($dir in $unitDirs) {
    $relativeBase = ($dir.Substring($Root.Length).TrimStart('\', '/')) -replace '\\', '/'

    Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -in '.service', '.timer', '.socket', '.mount', '.path' } |
      ForEach-Object {
        $item = $_
        $relative = $item.FullName.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'

        # ReparsePoint is how a Linux symlink lands on NTFS.
        $isLink = $item.Attributes -band [System.IO.FileAttributes]::ReparsePoint
        if ($isLink) {
            # Windows PowerShell cannot resolve a WSL-created symlink: those use a Linux-specific
            # reparse tag, and .Target comes back empty. The enablement fact does not depend on it -
            # the unit name and the *.wants directory carry that - so an empty target is recorded
            # honestly rather than guessed at from convention.
            $target = ''
            try { $target = (Get-Item -LiteralPath $item.FullName -Force).Target } catch { }
            if ($target -is [array]) { $target = $target[0] }
            if (-not $target) { $target = '' }

            # A link inside a *.wants or *.requires directory is an enablement record.
            $wantedBy = ''
            if ($relative -match '/([^/]+)\.(wants|requires)/') { $wantedBy = $Matches[1] }

            $enabled += [pscustomobject]@{
                Unit       = $item.Name
                WantedBy   = $wantedBy
                LinkPath   = $relative
                LinkTarget = "$target"
                TargetReadable = if ($target) { 'yes' } else { 'no - link target not resolvable from Windows' }
            }
            return
        }

        # A locally defined unit under /etc is not shipped by a package - worth explaining.
        $isLocal = $relativeBase -like 'etc/*'

        $execStart = ''; $execStartPre = ''; $user = ''; $description = ''; $wantedBy = ''; $restart = ''
        try {
            foreach ($line in Get-Content -LiteralPath $item.FullName -ErrorAction Stop) {
                switch -Regex ($line) {
                    '^\s*ExecStart\s*='    { if (-not $execStart)    { $execStart    = ($line -split '=', 2)[1].Trim() } }
                    '^\s*ExecStartPre\s*=' { if (-not $execStartPre) { $execStartPre = ($line -split '=', 2)[1].Trim() } }
                    '^\s*User\s*='         { if (-not $user)         { $user         = ($line -split '=', 2)[1].Trim() } }
                    '^\s*Description\s*='  { if (-not $description)  { $description  = ($line -split '=', 2)[1].Trim() } }
                    '^\s*WantedBy\s*='     { if (-not $wantedBy)     { $wantedBy     = ($line -split '=', 2)[1].Trim() } }
                    '^\s*Restart\s*='      { if (-not $restart)      { $restart      = ($line -split '=', 2)[1].Trim() } }
                }
            }
        } catch { }

        $units += [pscustomobject]@{
            Unit         = $item.Name
            LocallyDefined = if ($isLocal) { 'YES' } else { '' }
            Path         = $relative
            Description  = $description
            ExecStart    = $execStart
            ExecStartPre = $execStartPre
            RunAsUser    = $user
            Restart      = $restart
            WantedBy     = $wantedBy
            ModifiedUtc  = $item.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            SizeBytes    = $item.Length
        }
      }
}

# A collection unpacked from a tar or zip (UAC) has its symbolic links listed in _symlinks.csv
# rather than created, because Windows cannot make them without a privilege. Each link listed in a
# unit directory is recorded exactly as one found on disk, target string included.
$linkList = Join-Path $Root '_symlinks.csv'
if (Test-Path -LiteralPath $linkList) {
    $bases = @('etc/systemd/system/', 'usr/lib/systemd/system/', 'lib/systemd/system/')
    foreach ($link in (Import-Csv -LiteralPath $linkList)) {
        $relative = $link.Path
        $inUnitDir = @($bases | Where-Object { $relative.StartsWith($_, [StringComparison]::Ordinal) }).Count -gt 0
        if (-not $inUnitDir) { continue }

        $name = ($relative -split '/')[-1]
        if ([IO.Path]::GetExtension($name) -notin '.service', '.timer', '.socket', '.mount', '.path') { continue }

        $wantedBy = ''
        if ($relative -match '/([^/]+)\.(wants|requires)/') { $wantedBy = $Matches[1] }

        $enabled += [pscustomobject]@{
            Unit       = $name
            WantedBy   = $wantedBy
            LinkPath   = $relative
            LinkTarget = $link.Target
            TargetReadable = if ($link.Target) { 'yes' } else { 'no - link target not recorded in the archive' }
        }
    }
}

if (@($units).Count -gt 0) {
    $units | Sort-Object Unit |
        Export-Csv -LiteralPath (Join-Path $Out 'LinuxSystemd_Units.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxSystemd_Units.csv       {0} unit(s), {1} locally defined" -f `
                @($units).Count, @($units | Where-Object { $_.LocallyDefined }).Count)
}

if (@($enabled).Count -gt 0) {
    $enabled | Sort-Object Unit |
        Export-Csv -LiteralPath (Join-Path $Out 'LinuxSystemd_Enabled.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxSystemd_Enabled.csv     {0} enablement link(s)" -f @($enabled).Count)
}

if (@($units).Count -eq 0 -and @($enabled).Count -eq 0) { Write-Host "No systemd units found" }
