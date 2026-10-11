<#
.SYNOPSIS
    Parses Linux account files into CSV: passwd, group, shadow and the sudo configuration.

.DESCRIPTION
    Four questions this answers on a suspected compromise: who can log in, who is UID 0, who can
    escalate, and which accounts have a usable password.

    Reads what is present and skips what is not. A partial export holding only /etc/passwd still
    produces the passwd output rather than failing.

    Nothing here needs the files to be readable as a Linux system would - they are plain text, and
    the only trap is that a copied tree may hold CRLF line endings if it passed through a Windows
    tool, which Split handles either way.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force -Path $Out | Out-Null }

function Read-Lines([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try { Get-Content -LiteralPath $Path -ErrorAction Stop } catch { return @() }
}

function Save-Csv($Rows, [string]$Name) {
    if ($null -eq $Rows -or @($Rows).Count -eq 0) { return }
    $Rows | Export-Csv -LiteralPath (Join-Path $Out $Name) -NoTypeInformation -Encoding UTF8
    Write-Host ("  {0,-28} {1} row(s)" -f $Name, @($Rows).Count)
}

# --- passwd ------------------------------------------------------------------------------------
$passwd = @()
foreach ($line in Read-Lines (Join-Path $Root 'etc/passwd')) {
    if ($line -match '^\s*(#|$)') { continue }
    $f = $line -split ':'
    if ($f.Count -lt 7) { continue }

    $uid = [int]($f[2])
    $shell = $f[6]
    $passwd += [pscustomobject]@{
        Username    = $f[0]
        UID         = $uid
        GID         = $f[3]
        Description = $f[4]
        HomeDir     = $f[5]
        Shell       = $shell
        # A UID 0 account that is not root is the single loudest finding in this file.
        IsRootEquiv = if ($uid -eq 0 -and $f[0] -ne 'root') { 'YES' } else { '' }
        IsSystem    = if ($uid -lt 1000) { 'yes' } else { '' }
        # nologin and false are the usual way a service account is denied interactive access.
        CanLogin    = if ($shell -match 'nologin|/false$') { '' } else { 'yes' }
        PasswdField = $f[1]
    }
}
Save-Csv $passwd 'LinuxUsers_passwd.csv'

# --- group -------------------------------------------------------------------------------------
$groups = @()
foreach ($line in Read-Lines (Join-Path $Root 'etc/group')) {
    if ($line -match '^\s*(#|$)') { continue }
    $f = $line -split ':'
    if ($f.Count -lt 4) { continue }

    $groups += [pscustomobject]@{
        Group       = $f[0]
        GID         = $f[2]
        Members     = $f[3]
        MemberCount = @($f[3] -split ',' | Where-Object { $_ }).Count
        # Membership of these is effectively root on most distributions.
        IsPrivileged = if ($f[0] -in @('sudo','wheel','admin','root','adm','docker','lxd')) { 'yes' } else { '' }
    }
}
Save-Csv $groups 'LinuxUsers_group.csv'

# --- shadow ------------------------------------------------------------------------------------
# Hash values are deliberately NOT written out. What matters for triage is whether an account has
# a usable password, how it is hashed, and when it last changed - not the hash itself, which only
# creates a cracking target inside the case output.
$shadow = @()
foreach ($line in Read-Lines (Join-Path $Root 'etc/shadow')) {
    if ($line -match '^\s*(#|$)') { continue }
    $f = $line -split ':'
    if ($f.Count -lt 2) { continue }

    $hash = $f[1]
    $algorithm = switch -Regex ($hash) {
        '^\$y\$'    { 'yescrypt'; break }
        '^\$6\$'    { 'sha512';   break }
        '^\$5\$'    { 'sha256';   break }
        '^\$2[aby]\$' { 'bcrypt'; break }
        '^\$1\$'    { 'md5';      break }
        '^[!*]+$'   { 'none';     break }
        '^$'        { 'EMPTY';    break }
        default     { 'other' }
    }

    $lastChange = ''
    if ($f.Count -gt 2 -and $f[2] -match '^\d+$' -and [int]$f[2] -gt 0) {
        $lastChange = ([datetime]'1970-01-01').AddDays([int]$f[2]).ToString('yyyy-MM-dd')
    }

    $shadow += [pscustomobject]@{
        Username       = $f[0]
        HashAlgorithm  = $algorithm
        # A leading ! or * means the password is locked; an empty field means no password at all.
        Locked         = if ($hash -match '^!') { 'yes' } else { '' }
        NoPasswordSet  = if ($hash -eq '') { 'YES' } else { '' }
        LastChangeUtc  = $lastChange
        MinDays        = if ($f.Count -gt 3) { $f[3] } else { '' }
        MaxDays        = if ($f.Count -gt 4) { $f[4] } else { '' }
        ExpireDays     = if ($f.Count -gt 7) { $f[7] } else { '' }
    }
}
Save-Csv $shadow 'LinuxUsers_shadow.csv'

# --- sudoers -----------------------------------------------------------------------------------
$sudoFiles = @()
$mainSudoers = Join-Path $Root 'etc/sudoers'
if (Test-Path -LiteralPath $mainSudoers) { $sudoFiles += Get-Item -LiteralPath $mainSudoers }

$sudoersDir = Join-Path $Root 'etc/sudoers.d'
if (Test-Path -LiteralPath $sudoersDir) {
    $sudoFiles += Get-ChildItem -LiteralPath $sudoersDir -File -ErrorAction SilentlyContinue
}

$sudo = @()
foreach ($file in $sudoFiles) {
    $n = 0
    foreach ($line in Read-Lines $file.FullName) {
        $n++
        if ($line -match '^\s*(#|$)') { continue }

        $sudo += [pscustomobject]@{
            SourceFile = $file.Name
            Line       = $n
            Entry      = $line.Trim()
            # NOPASSWD and ALL=(ALL) are what turn a sudo entry into a privilege escalation path.
            NoPassword = if ($line -match 'NOPASSWD') { 'YES' } else { '' }
            GrantsAll  = if ($line -match 'ALL\s*=\s*\(\s*ALL') { 'yes' } else { '' }
        }
    }
}
Save-Csv $sudo 'LinuxUsers_sudoers.csv'

if (@($passwd).Count -eq 0 -and @($groups).Count -eq 0 -and @($shadow).Count -eq 0 -and @($sudo).Count -eq 0) {
    Write-Host "No account files found under $Root"
}
