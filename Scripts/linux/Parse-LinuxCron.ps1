<#
.SYNOPSIS
    Parses cron configuration from every location a scheduled job can hide.

.DESCRIPTION
    Covers the system crontab, /etc/cron.d, the hourly/daily/weekly/monthly directories, per-user
    crontabs under /var/spool/cron, and pending at-jobs (/var/spool/cron/atjobs on Debian,
    /var/spool/at on RHEL).

    The formats differ in one important way: /etc/crontab and /etc/cron.d entries carry a user
    field between the schedule and the command, per-user crontabs do not. Parsing both with the
    same rule would misread the command as running under the wrong account.

    AT-JOBS: a job file exists only until it runs, so these are jobs still pending at collection.
    Its name encodes the queue, the job number and the scheduled time (hex minutes since the Unix
    epoch, UTC); its body is a shell script that at wrote, recording the submitting uid and the
    login name mailed on completion, the environment at submission, and finally the command.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force -Path $Out | Out-Null }

$entries = @()

function Add-CrontabFile([System.IO.FileInfo]$File, [bool]$HasUserField, [string]$OwnerFallback) {
    $n = 0
    try { $lines = Get-Content -LiteralPath $File.FullName -ErrorAction Stop } catch { return }

    foreach ($line in $lines) {
        $n++
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }

        # Environment assignments are not jobs but do matter - PATH and MAILTO get abused.
        if ($trimmed -match '^\s*[A-Za-z_][A-Za-z0-9_]*\s*=') {
            $script:entries += [pscustomobject]@{
                SourceFile = $File.Name; Line = $n; Kind = 'Environment'
                Schedule = ''; RunAsUser = ''; Command = $trimmed
                ModifiedUtc = $File.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            }
            continue
        }

        $schedule = ''; $rest = ''
        if ($trimmed -match '^(@\w+)\s+(.*)$') {
            $schedule = $Matches[1]; $rest = $Matches[2]
        } elseif ($trimmed -match '^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.*)$') {
            $schedule = $Matches[1]; $rest = $Matches[2]
        } else {
            continue
        }

        $user = $OwnerFallback
        $command = $rest
        if ($HasUserField -and $rest -match '^(\S+)\s+(.*)$') {
            $user = $Matches[1]; $command = $Matches[2]
        }

        $script:entries += [pscustomobject]@{
            SourceFile  = $File.Name
            Line        = $n
            Kind        = 'Job'
            Schedule    = $schedule
            RunAsUser   = $user
            Command     = $command
            ModifiedUtc = $File.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }
}

# /etc/crontab and /etc/cron.d carry a user field; per-user crontabs do not.
$systemCrontab = Join-Path $Root 'etc/crontab'
if (Test-Path -LiteralPath $systemCrontab) { Add-CrontabFile (Get-Item -LiteralPath $systemCrontab) $true '' }

$cronD = Join-Path $Root 'etc/cron.d'
if (Test-Path -LiteralPath $cronD) {
    Get-ChildItem -LiteralPath $cronD -File -ErrorAction SilentlyContinue |
        ForEach-Object { Add-CrontabFile $_ $true '' }
}

foreach ($spool in @('var/spool/cron/crontabs', 'var/spool/cron')) {
    $dir = Join-Path $Root $spool
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
        ForEach-Object { Add-CrontabFile $_ $false $_.Name }   # the filename IS the owning user
}

if (@($entries).Count -gt 0) {
    $entries | Export-Csv -LiteralPath (Join-Path $Out 'LinuxCron_Entries.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxCron_Entries.csv        {0} entr(ies)" -f @($entries).Count)
}

# The periodic directories hold scripts rather than crontab lines, so they are listed, not parsed.
$scripts = @()
foreach ($period in @('hourly', 'daily', 'weekly', 'monthly')) {
    $dir = Join-Path $Root "etc/cron.$period"
    if (-not (Test-Path -LiteralPath $dir)) { continue }

    Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
        $first = ''
        try { $first = (Get-Content -LiteralPath $_.FullName -TotalCount 1 -ErrorAction Stop) } catch { }
        $scripts += [pscustomobject]@{
            Period      = $period
            Script      = $_.Name
            SizeBytes   = $_.Length
            ModifiedUtc = $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            FirstLine   = "$first".Trim()
        }
    }
}

if (@($scripts).Count -gt 0) {
    $scripts | Sort-Object Period, Script |
        Export-Csv -LiteralPath (Join-Path $Out 'LinuxCron_PeriodicScripts.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxCron_PeriodicScripts.csv {0} script(s)" -f @($scripts).Count)
}

# ------------------------------------------------------------------------------------- at-jobs
# Name: a0000f01b3c4d5 = queue 'a', job 0x0000f, run at 0x01b3c4d5 minutes after the epoch (UTC).
# '.SEQ' is the job counter and 'spool/' holds output of jobs that are running; neither is a job.
$atJobs = @()
foreach ($spool in @('var/spool/cron/atjobs', 'var/spool/at')) {
    $dir = Join-Path $Root $spool
    if (-not (Test-Path -LiteralPath $dir)) { continue }

    Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne '.SEQ' } | ForEach-Object {
        $file = $_
        $queue = ''; $jobNumber = ''; $scheduledUtc = ''
        if ($file.Name -match '^([a-zA-Z=])([0-9a-f]{5})([0-9a-f]{8})$') {
            $queue     = $Matches[1]
            $jobNumber = [Convert]::ToInt32($Matches[2], 16)
            $minutes   = [Convert]::ToInt64($Matches[3], 16)
            $scheduledUtc = ([DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddMinutes($minutes).ToString('yyyy-MM-dd HH:mm:ss')
        }

        try { $lines = @(Get-Content -LiteralPath $file.FullName -ErrorAction Stop) } catch { return }

        $uid = ''; $mailUser = ''; $workDir = ''; $command = @()
        $inBody = $false; $delimiter = $null
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if (-not $inBody) {
                if     ($line -match '^# atrun uid=(\d+)')      { $uid = $Matches[1] }
                elseif ($line -match '^# mail\s+(\S+)')         { $mailUser = $Matches[1] }
                elseif ($line -match '^cd\s+(.+?)\s*\|\|\s*\{') {
                    $workDir = $Matches[1].Trim().Trim("'").Trim('"') -replace '\\(.)', '$1'
                    # Skip the '{ echo ...; exit 1 }' block that follows; the command starts after it.
                    while ($i -lt $lines.Count -and $lines[$i].Trim() -ne '}') { $i++ }
                    $inBody = $true
                }
                continue
            }

            # at 3.2 and later wrap the command in a heredoc fed to the user's shell.
            if ($null -eq $delimiter -and $command.Count -eq 0 -and
                $line -match "^\`$\{SHELL:-/bin/sh\}\s*<<\s*'([^']+)'") { $delimiter = $Matches[1]; continue }
            if ($null -ne $delimiter -and $line -eq $delimiter) { break }
            $command += $line
        }

        $text = (($command | Where-Object { $_.Trim() -ne '' }) -join "`n").Trim()
        if (-not $inBody) {
            # Not laid out the way at writes jobs. Report it rather than guess, and keep the body.
            [Console]::Error.WriteLine("$($file.Name): not in at's job format - recorded whole")
            $text = ($lines -join "`n").Trim()
        }

        $atJobs += [pscustomobject]@{
            SourceFile       = "$spool/$($file.Name)"
            Queue            = $queue
            JobNumber        = $jobNumber
            ScheduledUtc     = $scheduledUtc
            SubmittedByUid   = $uid
            MailUser         = $mailUser
            WorkingDirectory = $workDir
            Command          = $text
            ModifiedUtc      = $file.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }
}

if (@($atJobs).Count -gt 0) {
    $atJobs | Sort-Object ScheduledUtc |
        Export-Csv -LiteralPath (Join-Path $Out 'LinuxCron_AtJobs.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ("  LinuxCron_AtJobs.csv         {0} pending job(s)" -f @($atJobs).Count)
}

if (@($entries).Count -eq 0 -and @($scripts).Count -eq 0 -and @($atJobs).Count -eq 0) { Write-Host "No cron configuration found" }
