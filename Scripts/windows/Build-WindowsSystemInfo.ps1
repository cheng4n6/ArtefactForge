<#
.SYNOPSIS
    Turns the SystemInfo.reb batch output into the system summary.

.DESCRIPTION
    Reads what RECmd extracted and writes the same two renderings the Linux summary produces:

      SystemInfo.csv - Category / Item / Value / Source, for filtering and the case roll-up
      SystemInfo.txt - the same facts laid out to be read

    Item names match the Linux summary where they mean the same thing - Hostname, Timezone,
    Domain, IPAddresses, DnsServers, MachineID - so both platforms land in one SystemInventory.csv.

    THREE THINGS RECmd BATCH MODE CANNOT GIVE US, handled rather than ignored:

    1. Plugin-backed keys are written to a SEPARATE CSV in a timestamped subfolder, and appear in
       the main file as ValueType '(plugin)' with no data. TimeZoneInformation is one, which is why
       the timezone would otherwise come out empty - the value that matters most here.

    2. Binary values read '(Binary data)' with no raw bytes, so ShutdownTime and the NetworkList
       connect dates cannot be decoded. The key's LastWriteTimestamp is used instead and labelled
       Approx, because that key is written at the moment of the event. It is a proxy, and saying so
       is the difference between evidence and a guess.

    3. ControlSet* matches every control set in the hive, not just the live one. Select\Current
       names the one that was in use, and only its values are reported.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RecmdOutput,
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

# --- load ------------------------------------------------------------------------------------------
$batchCsv = Get-ChildItem -LiteralPath $RecmdOutput -Filter '*.csv' -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
if (-not $batchCsv) { Write-Host "No RECmd output found in $RecmdOutput"; exit 0 }

$rows = @(Import-Csv -LiteralPath $batchCsv.FullName)

# Plugin output lands in a timestamped subfolder rather than the main CSV.
$pluginRows = @()
foreach ($file in (Get-ChildItem -LiteralPath $RecmdOutput -Filter '*.csv' -File -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -ne $batchCsv.FullName })) {
    try { $pluginRows += Import-Csv -LiteralPath $file.FullName } catch { }
}

# --- current control set ---------------------------------------------------------------------------
$current = ($rows | Where-Object { $_.Description -eq 'CurrentControlSet' } | Select-Object -First 1).ValueData
$currentSet = if ($current -match '^\d+$') { 'ControlSet{0:D3}' -f [int]$current } else { 'ControlSet001' }
Add-Fact 'Identity' 'CurrentControlSet' $currentSet 'SYSTEM\Select\Current'

function Pick([string]$Description) {
    $matching = @($rows | Where-Object { $_.Description -eq $Description -and "$($_.ValueData)".Trim() })
    if ($matching.Count -eq 0) { return $null }
    # Prefer the control set that was actually in use.
    $live = $matching | Where-Object { $_.KeyPath -like "*$currentSet*" } | Select-Object -First 1
    if ($live) { return $live }
    return $matching[0]
}
function Value([string]$Description) { $r = Pick $Description; if ($r) { "$($r.ValueData)".Trim() } else { '' } }

# --- identity ---------------------------------------------------------------------------------------
Add-Fact 'Identity' 'Hostname' (Value 'ComputerName') 'SYSTEM\ControlSet\Control\ComputerName'

# Domain is empty on a workgroup machine; NV Domain is the one set by policy.
$domain = Value 'Domain'
if (-not $domain) { $domain = Value 'NVDomain' }
Add-Fact 'Identity' 'Domain' $domain 'SYSTEM\ControlSet\Services\Tcpip\Parameters'

$role = switch (Value 'ProductType') {
    'WinNT'    { 'Workstation' }
    'ServerNT' { 'Server' }
    'LanmanNT' { 'Domain controller' }
    default    { Value 'ProductType' }
}
Add-Fact 'Identity' 'ComputerRole' $role 'SYSTEM\ControlSet\Control\ProductOptions'

# The machine SID is the common prefix of the local account SIDs under ProfileList.
$profileRows = @($rows | Where-Object { $_.Description -eq 'UserProfile' })
$machineSid = ''
foreach ($p in $profileRows) {
    if ($p.KeyPath -match '(S-1-5-21-\d+-\d+-\d+)-\d+$') { $machineSid = $Matches[1]; break }
}
Add-Fact 'Identity' 'MachineID' $machineSid 'SOFTWARE\...\ProfileList (SID prefix)'

# --- operating system ---------------------------------------------------------------------------------
Add-Fact 'OperatingSystem' 'ProductName' (Value 'ProductName') 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$display = Value 'DisplayVersion'
if (-not $display) { $display = Value 'ReleaseId' }
Add-Fact 'OperatingSystem' 'DisplayVersion' $display 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$build = Value 'CurrentBuild'
$ubr = Value 'UBR'
Add-Fact 'OperatingSystem' 'Build' $(if ($ubr) { "$build.$ubr" } else { $build }) 'CurrentBuild + UBR'
Add-Fact 'OperatingSystem' 'EditionID' (Value 'EditionID') 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Add-Fact 'OperatingSystem' 'InstallationType' (Value 'InstallationType') 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$install = Value 'InstallDate'
if ($install -match '^\d+$') {
    Add-Fact 'OperatingSystem' 'InstallDateUtc' `
        (([datetime]'1970-01-01T00:00:00Z').AddSeconds([int64]$install).ToString('yyyy-MM-dd HH:mm:ss')) `
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate'
}
Add-Fact 'OperatingSystem' 'RegisteredOwner' (Value 'RegisteredOwner') 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Add-Fact 'OperatingSystem' 'RegisteredOrganization' (Value 'RegisteredOrganization') 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

# --- time -----------------------------------------------------------------------------------------------
# From the plugin CSV, not the main batch output.
function PluginValue([string]$Name) {
    $r = $pluginRows | Where-Object { $_.ValueName -eq $Name -and "$($_.ValueData)".Trim() -ne '' } | Select-Object -First 1
    if ($r) { "$($r.ValueData)".Trim() } else { '' }
}

$tz = PluginValue 'TimeZoneKeyName'
Add-Fact 'Time' 'Timezone' $tz 'SYSTEM\ControlSet\Control\TimeZoneInformation (plugin)'
Add-Fact 'Time' 'TimezoneBiasMinutes' (PluginValue 'Bias') 'TimeZoneInformation (plugin)'
Add-Fact 'Time' 'TimezoneActiveBiasMinutes' (PluginValue 'ActiveTimeBias') 'TimeZoneInformation (plugin)'

# ShutdownTime is binary and RECmd batch mode does not emit the bytes. The key is written at
# shutdown, so its last-write time is the event - labelled Approx because it is a proxy.
$shutdown = Pick 'ShutdownTime'
if ($shutdown -and $shutdown.LastWriteTimestamp) {
    Add-Fact 'Time' 'LastShutdownApprox' ($shutdown.LastWriteTimestamp -replace '\.\d+$', '') `
        'SYSTEM\ControlSet\Control\Windows key last write (binary value not decodable in batch mode)'
}

# --- hardware --------------------------------------------------------------------------------------------
foreach ($pair in @(
    @{ Item = 'Manufacturer'; Desc = 'SystemManufacturer' },
    @{ Item = 'Model';        Desc = 'SystemProductName' },
    @{ Item = 'BIOSVersion';  Desc = 'BIOSVersion' },
    @{ Item = 'BIOSDate';     Desc = 'BIOSReleaseDate' })) {
    Add-Fact 'Hardware' $pair.Item (Value $pair.Desc) 'SYSTEM\ControlSet\Control\SystemInformation'
}

# --- network ----------------------------------------------------------------------------------------------
$interfaceRows = @($rows | Where-Object { $_.Description -eq 'NetworkInterface' -and $_.KeyPath -like "*$currentSet*" })
$byInterface = @{}
foreach ($r in $interfaceRows) {
    if (-not $byInterface.ContainsKey($r.KeyPath)) { $byInterface[$r.KeyPath] = @{} }
    if ("$($r.ValueData)".Trim()) { $byInterface[$r.KeyPath][$r.ValueName] = "$($r.ValueData)".Trim() }
}

$addresses = @(); $dns = @(); $gateways = @()
foreach ($key in $byInterface.Keys) {
    $v = $byInterface[$key]
    foreach ($n in @('DhcpIPAddress','IPAddress')) {
        if ($v.ContainsKey($n) -and $v[$n] -notmatch '^0\.0\.0\.0' -and $v[$n]) { $addresses += $v[$n] }
    }
    foreach ($n in @('DhcpNameServer','NameServer')) { if ($v.ContainsKey($n) -and $v[$n]) { $dns += ($v[$n] -split '[ ,]+') } }
    foreach ($n in @('DhcpDefaultGateway','DefaultGateway')) { if ($v.ContainsKey($n) -and $v[$n]) { $gateways += ($v[$n] -split '[ ,]+') } }
}
Add-Fact 'Network' 'IPAddresses' (($addresses | Select-Object -Unique) -join ', ') 'SYSTEM\ControlSet\Services\Tcpip\Parameters\Interfaces'
Add-Fact 'Network' 'DnsServers'  (($dns       | Where-Object { $_ } | Select-Object -Unique) -join ', ') 'Tcpip\Parameters\Interfaces'
Add-Fact 'Network' 'Gateways'    (($gateways  | Where-Object { $_ } | Select-Object -Unique) -join ', ') 'Tcpip\Parameters\Interfaces'
Add-Fact 'Network' 'InterfaceCount' $byInterface.Count 'Tcpip\Parameters\Interfaces'

# --- network history ----------------------------------------------------------------------------------------
# Where this machine has been. The connect dates are binary and not decodable from batch output,
# so the profile key's last write stands in for the last connection.
$profileGroups = @{}
foreach ($r in ($rows | Where-Object { $_.Description -eq 'NetworkProfile' })) {
    if (-not $profileGroups.ContainsKey($r.KeyPath)) { $profileGroups[$r.KeyPath] = @{ Values = @{}; LastWrite = $r.LastWriteTimestamp } }
    if ("$($r.ValueData)".Trim()) { $profileGroups[$r.KeyPath].Values[$r.ValueName] = "$($r.ValueData)".Trim() }
}
$networks = @()
foreach ($key in $profileGroups.Keys) {
    $v = $profileGroups[$key].Values
    $name = if ($v.ContainsKey('ProfileName')) { $v['ProfileName'] } else { '' }
    if (-not $name) { continue }
    $when = "$($profileGroups[$key].LastWrite)" -replace '\.\d+$', ''
    $networks += "$name (last seen approx $when)"
}
Add-Fact 'NetworkHistory' 'NetworksJoined' $networks.Count 'SOFTWARE\...\NetworkList\Profiles'
foreach ($n in ($networks | Sort-Object)) {
    Add-Fact 'NetworkHistory' 'Network' $n 'NetworkList\Profiles (key last write; binary dates not decodable)'
}

# --- accounts ---------------------------------------------------------------------------------------------------
$users = @()
foreach ($p in $profileRows) {
    $path = "$($p.ValueData)".Trim()
    if (-not $path) { continue }
    # Service SIDs are S-1-5-18/19/20; only real accounts carry the S-1-5-21 machine prefix.
    if ($p.KeyPath -notmatch 'S-1-5-21-') { continue }
    $users += (Split-Path $path -Leaf)
}
Add-Fact 'Accounts' 'LocalProfiles' (($users | Sort-Object -Unique) -join ', ') 'SOFTWARE\...\ProfileList'
Add-Fact 'Accounts' 'TotalAccounts' @($users | Sort-Object -Unique).Count 'SOFTWARE\...\ProfileList'
Add-Fact 'Accounts' 'LastLoggedOnUser' (Value 'LastLoggedOnUser') 'SOFTWARE\...\Authentication\LogonUI'

$auto = Value 'AutoAdminLogon'
if ($auto -eq '1') {
    Add-Fact 'Accounts' 'AutoAdminLogon' "ENABLED for $(Value 'DefaultUserName')" 'SOFTWARE\...\Winlogon - a plaintext password may sit alongside'
} else {
    Add-Fact 'Accounts' 'AutoAdminLogon' 'disabled' 'SOFTWARE\...\Winlogon'
}

# --- write ---------------------------------------------------------------------------------------------------------
$facts | Export-Csv -LiteralPath (Join-Path $Out 'SystemInfo.csv') -NoTypeInformation -Encoding UTF8

$report = New-Object System.Text.StringBuilder
[void]$report.AppendLine("System summary" + $(if ($Collection) { " - $Collection" } else { '' }))
[void]$report.AppendLine(('=' * 70))
[void]$report.AppendLine("Built:  $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC")
[void]$report.AppendLine()

foreach ($group in ($facts | Group-Object Category)) {
    [void]$report.AppendLine($group.Name)
    [void]$report.AppendLine(('-' * 70))
    foreach ($fact in $group.Group) {
        $value = if ($fact.Value) { $fact.Value } else { '(not present)' }
        [void]$report.AppendLine(("  {0,-26} {1}" -f $fact.Item, $value))
    }
    [void]$report.AppendLine()
}

[System.IO.File]::WriteAllText((Join-Path $Out 'SystemInfo.txt'), $report.ToString())
Write-Host ("  SystemInfo.csv / .txt        {0} fact(s)" -f $facts.Count)
