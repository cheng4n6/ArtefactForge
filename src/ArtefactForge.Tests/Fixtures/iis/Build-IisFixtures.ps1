<#
.SYNOPSIS
    Builds a synthetic IIS collection for the WindowsIisLogs tests: W3C logs, HTTP.sys errors
    and an applicationHost.config. No evidence: made-up host names, users and documentation
    addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

.DESCRIPTION
    The same parameters always give the same files (a seeded random), so the checked-in
    fixture under collection\ can be rebuilt and compared:

        .\Build-IisFixtures.ps1 -Out .\collection

    Larger sets for timing the module: -Days 7 -RequestsPerDay 15000 (about 100,000 lines).

    What the logs hold, per day:
      W3SVC1 (Default Web Site)   browsing; on day 1 a scanner burst, an upload of a script under
                                  aspnet_client and POSTs to it; part way through each day the
                                  logged fields change (a new #Fields block in the same file,
                                  adding s-sitename, cs-host, bytes and X-Forwarded-For)
      W3SVC2 (Exchange Back End)  ActiveSync (Cmd=Sync on every request) and one ProxyShell-shaped
                                  autodiscover request on day 1
      FTPSVC3 (FTP site)          FTP W3C log lines
      HTTPERR                     requests HTTP.sys rejected
    The format follows Microsoft's W3C extended log documentation and IIS 10's defaults.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$Days = 1,
    [int]$RequestsPerDay = 120
)

$ErrorActionPreference = 'Stop'
$random = New-Object System.Random 42
$utf8 = New-Object System.Text.UTF8Encoding $false
$start = New-Object DateTime 2026, 3, 16, 0, 0, 0, ([DateTimeKind]::Utc)

function Write-Lines([string]$Path, [string[]]$Lines) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($Path, (($Lines -join "`r`n") + "`r`n"), $utf8)
}

function Pick([object[]]$Items) { return $Items[$random.Next($Items.Length)] }

function Stamp([DateTime]$Time) { return $Time.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }

$header = @('#Software: Microsoft Internet Information Services 10.0', '#Version: 1.0')
$defaultFields = 'date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken'
$wideFields = 'date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken X-Forwarded-For'

$browsers = @('Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/131.0+Safari/537.36',
              'Mozilla/5.0+(Macintosh;+Intel+Mac+OS+X+14_6)+AppleWebKit/605.1.15+(KHTML,+like+Gecko)+Version/18.1+Safari/605.1.15')
$pages = @('/', '/index.html', '/about.aspx', '/products/list.aspx', '/images/logo.png', '/css/site.css', '/js/app.js', '/contact.aspx')
$clients = @('198.51.100.10', '198.51.100.11', '198.51.100.12', '2001:db8::25')

for ($day = 0; $day -lt $Days; $day++) {
    $date = $start.AddDays($day)
    $name = 'u_ex' + $date.ToString('yyMMdd', [Globalization.CultureInfo]::InvariantCulture) + '.log'
    $step = [int](86400 / [Math]::Max(1, $RequestsPerDay))

    # --- Default Web Site ------------------------------------------------------------------------
    $lines = @()
    $lines += $header
    $lines += '#Date: ' + (Stamp $date)
    $lines += '#Fields: ' + $defaultFields
    $wide = $false
    for ($i = 0; $i -lt $RequestsPerDay; $i++) {
        $t = $date.AddSeconds($i * $step + $random.Next($step))
        if (-not $wide -and $i -ge [int]($RequestsPerDay / 2)) {
            # The fields were changed in IIS Manager: a new block in the same file.
            $lines += $header
            $lines += '#Date: ' + (Stamp $t)
            $lines += '#Fields: ' + $wideFields
            $wide = $true
        }
        $page = Pick $pages
        $status = if ($random.Next(20) -eq 0) { '404' } else { '200' }
        $client = Pick $clients
        $agent = Pick $browsers
        $taken = $random.Next(1, 400)
        if ($wide) {
            $lines += '{0} W3SVC1 WEB01 192.0.2.10 GET {1} - 443 - 192.0.2.250 HTTP/1.1 {2} - www.example.test {3} 0 0 {4} {5} {6} {7}' -f `
                (Stamp $t), $page, $agent, $status, $random.Next(200, 90000), $random.Next(300, 900), $taken, $client
        } else {
            $lines += '{0} 192.0.2.10 GET {1} - 443 - {2} {3} - {4} 0 0 {5}' -f (Stamp $t), $page, $client, $agent, $status, $taken
        }

        if ($day -eq 0 -and $i -eq 20) {
            # A scanner burst from one address.
            foreach ($probe in @('/../../windows/win.ini', '/admin.aspx', '/search.aspx?q=1%27%20UNION%20SELECT%20name%20FROM%20sys.tables', '/.env', '/web.config')) {
                $t = $t.AddSeconds(1)
                $lines += '{0} 192.0.2.10 GET {1} {2} 443 - 203.0.113.66 sqlmap/1.8.3#stable+(https://sqlmap.org) - 404 0 2 3' -f `
                    (Stamp $t), ($probe -split '\?')[0], $(if ($probe.Contains('?')) { ($probe -split '\?', 2)[1] } else { '-' })
            }
        }
        if ($day -eq 0 -and $i -eq 40) {
            # An upload, then the dropped script is used.
            $t = $t.AddSeconds(5)
            $lines += '{0} 192.0.2.10 POST /upload.aspx - 443 - 203.0.113.66 Mozilla/5.0+(compatible) - 200 0 0 120' -f (Stamp $t)
            foreach ($q in @('c=d2hvYW1p', 'c=aXBjb25maWc=', 'c=bmV0K3VzZXI=')) {
                $t = $t.AddSeconds(30)
                $lines += '{0} 192.0.2.10 POST /aspnet_client/system_web/errorpage.aspx {1} 443 - 203.0.113.66 Mozilla/5.0+(compatible) - 200 0 0 45' -f (Stamp $t), $q
            }
        }
    }
    Write-Lines (Join-Path $Out "inetpub\logs\LogFiles\W3SVC1\$name") $lines

    # --- Exchange Back End -----------------------------------------------------------------------
    $lines = @()
    $lines += $header
    $lines += '#Date: ' + (Stamp $date)
    $lines += '#Fields: ' + $defaultFields
    for ($i = 0; $i -lt [int]($RequestsPerDay / 4); $i++) {
        $t = $date.AddSeconds($i * $step * 4 + $random.Next($step))
        $lines += '{0} 192.0.2.11 POST /Microsoft-Server-ActiveSync/Proxy/default.eas Cmd=Sync&User=CORP%5Calice&DeviceId=ABC{1}&DeviceType=iPhone 444 CORP\alice 192.0.2.11 Apple-iPhone15C2/2104.120 - 200 0 0 {2}' -f `
            (Stamp $t), $random.Next(100, 999), $random.Next(50, 900)
    }
    if ($day -eq 0) {
        $t = $date.AddHours(3)
        $lines += '{0} 192.0.2.11 POST /autodiscover/autodiscover.json @evil.example/powershell/?X-Rps-CAT=VgEAVAdXaW5kb3dz 444 - 203.0.113.77 python-requests/2.31.0 - 200 0 0 210' -f (Stamp $t)
    }
    Write-Lines (Join-Path $Out "inetpub\logs\LogFiles\W3SVC2\$name") $lines

    # --- FTP site ------------------------------------------------------------------------------------
    $lines = @('#Software: Microsoft Internet Information Services 10.0', '#Version: 1.0', ('#Date: ' + (Stamp $date)),
               '#Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status sc-win32-status sc-substatus x-session x-fullpath')
    $t = $date.AddHours(9)
    $lines += '{0} 198.51.100.40 - 192.0.2.10 21 ControlChannelOpened - - 0 0 6a1b2c3d -' -f (Stamp $t)
    $lines += '{0} 198.51.100.40 bob 192.0.2.10 21 USER bob 331 0 0 6a1b2c3d -' -f (Stamp $t.AddSeconds(1))
    $lines += '{0} 198.51.100.40 bob 192.0.2.10 21 RETR finance.xlsx 226 0 0 6a1b2c3d /finance.xlsx' -f (Stamp $t.AddSeconds(9))
    Write-Lines (Join-Path $Out "inetpub\logs\LogFiles\FTPSVC3\$name") $lines
}

# --- HTTP.sys errors -------------------------------------------------------------------------------
$lines = @('#Software: Microsoft HTTP API 2.0', '#Version: 1.0', ('#Date: ' + (Stamp $start)),
           '#Fields: date time c-ip c-port s-ip s-port cs-version cs-method cs-uri sc-status s-siteid s-reason s-queuename')
$lines += '{0} 203.0.113.66 51234 192.0.2.10 443 HTTP/1.1 GET /%c0%af 400 - BadRequest -' -f (Stamp $start.AddMinutes(30))
$lines += '{0} 203.0.113.66 51240 192.0.2.10 80 - - - - - Timer_ConnectionIdle -' -f (Stamp $start.AddMinutes(31))
Write-Lines (Join-Path $Out 'Windows\System32\LogFiles\HTTPERR\httperr1.log') $lines

# --- applicationHost.config ------------------------------------------------------------------------
$config = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <sites>
      <site name="Default Web Site" id="1">
        <application path="/" applicationPool="DefaultAppPool">
          <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" />
          <virtualDirectory path="/downloads" physicalPath="D:\Downloads" />
        </application>
        <bindings>
          <binding protocol="https" bindingInformation="*:443:" />
        </bindings>
      </site>
      <site name="Exchange Back End" id="2">
        <application path="/" applicationPool="MSExchangeServicesAppPool">
          <virtualDirectory path="/" physicalPath="C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\Exchweb" />
        </application>
        <application path="/owa" applicationPool="MSExchangeOWAAppPool">
          <virtualDirectory path="/" physicalPath="C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\Owa" />
        </application>
        <bindings>
          <binding protocol="https" bindingInformation="*:444:" />
        </bindings>
      </site>
      <site name="Files" id="3">
        <application path="/">
          <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\ftproot" />
        </application>
        <bindings>
          <binding protocol="ftp" bindingInformation="*:21:" />
        </bindings>
      </site>
      <siteDefaults>
        <logFile logFormat="W3C" directory="%SystemDrive%\inetpub\logs\LogFiles" />
      </siteDefaults>
    </sites>
    <log>
      <centralW3CLogFile enabled="true" directory="%SystemDrive%\inetpub\logs\LogFiles" />
    </log>
  </system.applicationHost>
</configuration>
'@
Write-Lines (Join-Path $Out 'Windows\System32\inetsrv\config\applicationHost.config') ($config.TrimEnd() -split "`r?`n")
