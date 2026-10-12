<#
.SYNOPSIS
    Builds a self-contained deployment folder containing only what is needed to run.

.DESCRIPTION
    Produces a clean package with the two executables at its root:

        ArtefactForge\
            ArtefactForge.exe        the interface
            ArtefactForgeCli.exe     headless
            BUILD.txt                what this package is and when it was built
            README.md
            Modules\  Layouts\  Profiles\  Scripts\  Tools\

    Nothing else - no source, no docs beyond the README, no git history, no build artefacts.
    Copy the folder anywhere and run it.

    Tools\ ships whole, including the EZ Tools GUI applications that ArtefactForge never invokes.
    That is deliberate: one folder carries both the processing and the analysis side, so the
    results can be opened on the same machine that parsed them. It costs roughly 690 MB of the
    total. A lean variant is a future option, not a missing feature.

    Both executables are published as single files, so the root holds the two exes rather than
    two exes plus a scatter of DLLs and .json runtime files.

    Framework-dependent by default: the EZ Tools already require the .NET 9 runtime, so any box
    that can run them can run this. -SelfContained bundles the runtime for a machine with no .NET,
    costing roughly 180 MB.

.PARAMETER Destination
    Where to build the package. Defaults to .\Dist\ArtefactForge.

.PARAMETER SelfContained
    Bundle the .NET runtime so the package runs on a machine with no .NET installed.

.PARAMETER NoTools
    Skip copying Tools\ (~690 MB of it is EZ Tools GUI apps). Builds to a separate folder and
    archive name, so the lightweight package sits alongside the full one rather than replacing it.
    Nothing will run until Tools\ is supplied - BUILD.txt says so.

.PARAMETER Archive
    Also produce one grabbable file per release:
      full package     Dist\ArtefactForge_v<version>.7z         carried to a job, never published
      -NoTools         Dist\release\artefactforge-<version>-no-tools.zip   the GitHub Release asset

    The published package is a zip, not a 7z: Windows opens it natively, and the in-place updater
    extracts it without 7-Zip.

.PARAMETER SignKey
    With -NoTools -Archive: the release signing key (see 'ArtefactForgeCli release keygen'). Writes
    Dist\release\artefactforge-latest.json and its .sig beside the zip - the three assets that make
    up a GitHub Release. Prompts for the key's password, or reads AF_SIGNING_PASSWORD.
    Without it no latest.json is written, so an unsigned release cannot be published by mistake.

.EXAMPLE
    .\package.ps1 -Archive              full package, for carrying to a job
    .\package.ps1 -NoTools -Archive     lightweight package, not yet publishable as an update
    .\package.ps1 -NoTools -Archive -SignKey <path to the release signing key>
                                        a release: zip, latest.json and signature in Dist\release\
    .\package.ps1 -SelfContained -Destination E:\ArtefactForge
#>
[CmdletBinding()]
param(
    [string]$Destination,
    [switch]$SelfContained,
    [switch]$NoTools,
    [switch]$Archive,
    [string]$SignKey
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

if ($SignKey -and -not ($NoTools -and $Archive)) { throw "-SignKey signs a published release: use it with -NoTools -Archive" }
if ($SignKey -and -not (Test-Path $SignKey)) { throw "Signing key not found: $SignKey" }

# The two variants must not overwrite each other: the full package is what gets carried to a job,
# the no-tools one is small enough to publish.
$variant = if ($NoTools) { '-no-tools' } else { '' }
if (-not $Destination) { $Destination = Join-Path $root ("Dist\ArtefactForge" + $variant) }

# Rebuild from scratch: a stale file left behind from a previous package is a support call
# waiting to happen.
if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$Destination = (Resolve-Path $Destination).Path

# Single source of truth for the version, so the folder, BUILD.txt and archive cannot disagree.
$props = Get-Content (Join-Path $root 'Directory.Build.props') -Raw
$version = if ($props -match '<Version>([^<]+)</Version>') { $Matches[1] } else { '0.0.0' }

$mode = if ($SelfContained) { 'self-contained' } else { 'framework-dependent' }
Write-Host "Packaging ArtefactForge $version to $Destination ($mode)"

$publishArgs = @(
    '-c', 'Release',
    '-r', 'win-x64',
    '-o', $Destination,
    '--self-contained', $(if ($SelfContained) { 'true' } else { 'false' }),
    '-p:PublishSingleFile=true',
    '-p:DebugType=none',
    '-p:GenerateDocumentationFile=false'
)

# Checked up front so a missing SDK or an unreachable package source is reported as that, rather
# than as "publish failed" with dotnet's own output hidden.
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet not found. Install the .NET 9 SDK: winget install Microsoft.DotNet.SDK.9"
}
Write-Host "  restoring packages"
$restore = & dotnet restore (Join-Path $root 'ArtefactForge.sln') -r win-x64 2>&1
if ($LASTEXITCODE -ne 0) {
    $restore | Write-Host
    if ($restore -match 'NU1100|NU1301') {
        throw ("restore could not download packages from NuGet. Check this machine can reach " +
               "https://api.nuget.org (a proxy or firewall may block it) and that " +
               "'dotnet nuget list source' shows nuget.org as Enabled.")
    }
    if ($restore -match 'global\.json|compatible \.NET SDK|NETSDK1045') {
        throw "a .NET 9 SDK matching global.json is needed: winget install Microsoft.DotNet.SDK.9"
    }
    throw "restore failed - see the output above"
}

foreach ($project in @('src\ArtefactForge.Gui', 'src\ArtefactForge.Cli')) {
    Write-Host "  building $project"
    $output = & dotnet publish (Join-Path $root $project) @publishArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Write-Host
        throw "publish failed for $project - see the output above"
    }
}

# Single-file publish still emits these next to the exe; they are not needed to run.
Get-ChildItem $Destination -File | Where-Object { $_.Extension -in '.pdb', '.xml' } | Remove-Item -Force

# Everything listed here ships to whoever downloads the archive. Scripts\ must hold only what a
# module invokes at run time - a development harness with a hardcoded path once reached a release
# this way. Dev tooling lives in dev\, which is deliberately absent from this list.
Write-Host "  copying module definitions and layouts"
foreach ($folder in @('Modules', 'Layouts', 'Profiles', 'Scripts')) {
    $source = Join-Path $root $folder
    if (Test-Path $source) { Copy-Item $source -Destination $Destination -Recurse -Force }
}
Copy-Item (Join-Path $root 'README.md') -Destination $Destination -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root 'Apps.yaml') -Destination $Destination -Force -ErrorAction SilentlyContinue

if ($NoTools) {
    Write-Warning "Tools\ not copied - the package will not run until it is supplied"
} else {
    $toolsSource = Join-Path $root 'Tools'
    if (Test-Path $toolsSource) {
        Write-Host "  copying tools (this is the slow part)"
        Copy-Item $toolsSource -Destination $Destination -Recurse -Force
    } else {
        Write-Warning "Tools\ not found in the repo - the package will not run until it is supplied"
    }
}

# Stamp the build so output can be traced back to the package that produced it.
$commit = try { (& git -C $root rev-parse --short HEAD 2>$null) } catch { $null }
if (-not $commit) { $commit = 'unknown' }
$tag = try { (& git -C $root describe --tags --always 2>$null) } catch { $null }
if (-not $tag) { $tag = 'untagged' }
$moduleCount = (Get-ChildItem (Join-Path $Destination 'Modules') -Recurse -Filter '*.forge' -ErrorAction SilentlyContinue).Count

@"
ArtefactForge $version
Packaged   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Commit     $commit
Tag        $tag
Build      $mode, single-file, win-x64
Modules    $moduleCount
Tools      $(if (Test-Path (Join-Path $Destination 'Tools')) { 'see Tools\VERSIONS.txt' } else { 'NOT INCLUDED - see below' })

Run ArtefactForge.exe for the interface, or ArtefactForgeCli.exe for headless use.
Modules, Layouts, Profiles and Tools are resolved relative to this folder, so the
whole folder can be copied anywhere as a unit.
$(if ($NoTools -or -not (Test-Path (Join-Path $Destination 'Tools'))) {
@"

TOOLS ARE NOT INCLUDED in this build. Nothing will run until you populate Tools\:

    Tools\eztools\     Eric Zimmerman tools
    Tools\hayabusa\    hayabusa.exe plus its rules and config folders
    Tools\chainsaw\    chainsaw.exe plus mappings, rules and sigma

Run 'ArtefactForgeCli tools' to check what is found and what is still missing.
See README.md for where to download each.
"@ })
"@ | Out-File (Join-Path $Destination 'BUILD.txt') -Encoding utf8

# files.txt: every file this package installs, with its SHA-256. The in-place updater uses it to
# tell the package's own files, which it may replace, from anything the analyst added or edited.
# Tools\ is left out on purpose - an update never touches the tools.
$manifestLines = Get-ChildItem $Destination -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($Destination.Length).TrimStart('\')
    if ($relative -like 'Tools\*' -or $relative -eq 'files.txt') { return }
    '{0} {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $relative
} | Sort-Object { $_.Substring(65) }
$manifestText = @("# ArtefactForge $version - the files this package installed, for the updater. Do not edit.") + $manifestLines
[System.IO.File]::WriteAllLines((Join-Path $Destination 'files.txt'), [string[]]$manifestText, (New-Object System.Text.UTF8Encoding($false)))

$size = (Get-ChildItem $Destination -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
Write-Host ""
Write-Host ("Done. {0:N0} MB" -f $size)
Get-ChildItem $Destination | ForEach-Object {
    $label = if ($_.PSIsContainer) { $_.Name + '\' } else { $_.Name }
    "  $label"
}

if ($Archive -and -not $NoTools) {
    $sevenZip = 'C:\Program Files\7-Zip\7z.exe'
    if (-not (Test-Path $sevenZip)) { throw "7-Zip not found at $sevenZip" }

    $archivePath = Join-Path (Split-Path $Destination -Parent) ("ArtefactForge_v{0}.7z" -f $version)
    if (Test-Path $archivePath) { Remove-Item $archivePath -Force }

    Write-Host ""
    Write-Host "Compressing to $archivePath"
    # Archive the folder itself, not its contents, so extracting yields ArtefactForge\ intact.
    & $sevenZip a -t7z -mx5 -bso0 -bsp0 $archivePath $Destination | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7-Zip failed with exit code $LASTEXITCODE" }

    $archiveSize = (Get-Item $archivePath).Length / 1MB
    Write-Host ("Archive: {0:N0} MB ({1:N0}% of the folder)" -f $archiveSize, ($archiveSize / $size * 100))
}

if ($Archive -and $NoTools) {
    # Every asset of a GitHub Release, in one folder. The updater reads them by these names.
    $site = Join-Path (Split-Path $Destination -Parent) 'release'
    if (Test-Path $site) { Remove-Item $site -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $site | Out-Null

    $zipName = "artefactforge-$version-no-tools.zip"
    $zipPath = Join-Path $site $zipName
    Write-Host ""
    Write-Host "Compressing to $zipPath"

    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        # Entries sit under ArtefactForge/ whatever the build folder is called, so extracting by
        # hand gives an ArtefactForge folder, and the updater strips that one level.
        foreach ($file in Get-ChildItem $Destination -Recurse -File) {
            $entry = 'ArtefactForge/' + $file.FullName.Substring($Destination.Length).TrimStart('\').Replace('\', '/')
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entry,
                [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally { $zip.Dispose() }

    $zipItem = Get-Item $zipPath
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    Write-Host ("Archive: {0:N0} KB  SHA256 {1}" -f ($zipItem.Length / 1KB), $zipHash)

    if (-not $SignKey) {
        Write-Warning "No -SignKey: no artefactforge-latest.json written, so this is not publishable as an update."
    } else {
        # The release notes are this version's section of the changelog, as written.
        $notes = ''
        $changelog = Join-Path $root 'CHANGELOG.md'
        if (Test-Path $changelog) {
            $text = Get-Content $changelog -Raw -Encoding UTF8
            $pattern = '(?ms)^## ' + [regex]::Escape($version) + '\b[^\n]*\n(.*?)(?=^## |\z)'
            # Sections end with a '---' rule, which is layout, not notes.
            if ($text -match $pattern) { $notes = ($Matches[1].Trim() -replace '\s*-{3,}\s*$', '').Trim() }
        }
        if (-not $notes) { Write-Warning "CHANGELOG.md has no '## $version' section - the release will have no notes." }

        $release = [ordered]@{
            product   = 'ArtefactForge'
            version   = $version
            published = (Get-Date -Format 'yyyy-MM-dd')
            file      = $zipName
            size      = $zipItem.Length
            sha256    = $zipHash
            notes     = $notes
        }
        $jsonPath = Join-Path $site 'artefactforge-latest.json'
        [System.IO.File]::WriteAllText($jsonPath, ($release | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))

        # Signed by the CLI just built, which also refuses a key this build does not trust.
        & (Join-Path $Destination 'ArtefactForgeCli.exe') release sign $jsonPath --key $SignKey
        if ($LASTEXITCODE -ne 0) {
            Remove-Item $jsonPath -Force
            throw "Signing failed - no artefactforge-latest.json left behind"
        }

        Write-Host ""
        Write-Host "Release ready in $site - attach all three to one GitHub Release, then publish it:"
        Get-ChildItem $site | ForEach-Object { "  " + $_.Name }
    }
}
