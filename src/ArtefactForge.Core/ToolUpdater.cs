using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using ArtefactForge.Core.Update;

namespace ArtefactForge.Core;

/// <summary>
/// A third-party tool ArtefactForge can update in place: where its releases are, which download is
/// the Windows x64 one, and how that download maps onto <c>Tools\&lt;Name&gt;\</c>.
/// </summary>
public sealed record ToolPackage(
    string Name,
    string Repository,
    Regex AssetPattern,
    Regex ExecutablePattern,
    string Executable,
    IReadOnlyList<string> ReplacedFolders)
{
    /// <summary>A note shown before the update, when part of the folder is deliberately left alone.</summary>
    public string? KeptNote { get; init; }
}

public sealed record ToolUpdateOutcome(string Package, string? FromVersion, string ToVersion, string ExecutableSha256);

/// <summary>
/// Replaces a tool under Tools\ with its latest GitHub release, only when the analyst asks.
///
/// Order of trust: the download's size and SHA-256 are checked against what GitHub publishes for
/// it before the zip is opened, and nothing outside Tools\_update\ is written until the new folder
/// is complete. The swap is two renames; if the second fails, or VERSIONS.txt cannot be written,
/// the old folder goes back, because a tool that does not match VERSIONS.txt breaks the version and
/// SHA-256 provenance the run manifest records.
/// </summary>
public sealed class ToolUpdater(string toolsDirectory)
{
    public const string WorkFolder = "_update";
    public const string VersionsFile = "VERSIONS.txt";

    public static readonly IReadOnlyList<ToolPackage> Packages =
    [
        // The release zip holds hayabusa-<version>-win-x64.exe beside its rules and config. Modules
        // call hayabusa\hayabusa.exe, so the exe is renamed, and rules and config are replaced
        // with the ones the release was built against.
        new("hayabusa", "Yamato-Security/hayabusa",
            new Regex(@"^hayabusa-[0-9.]+-win-x64\.zip$", RegexOptions.IgnoreCase),
            new Regex(@"^hayabusa-[0-9.]+-win-x64\.exe$", RegexOptions.IgnoreCase),
            "hayabusa.exe", ["config", "rules"]),

        // The Windows zip holds only chainsaw\chainsaw.exe, LICENCE and README.md. Its rules,
        // sigma rules and mappings come from a separate download and are left as they are.
        new("chainsaw", "WithSecureOpenSource/chainsaw",
            new Regex(@"^chainsaw_x86_64-pc-windows-msvc\.zip$", RegexOptions.IgnoreCase),
            new Regex(@"^chainsaw\.exe$", RegexOptions.IgnoreCase),
            "chainsaw.exe", [])
        {
            KeptNote = @"Chainsaw's rules, sigma and mappings folders are not in this download and stay as they are."
        }
    ];

    public string ToolsDirectory { get; } = Path.GetFullPath(toolsDirectory);

    public static ToolPackage? Find(string package) =>
        Packages.FirstOrDefault(p => string.Equals(p.Name, package, StringComparison.OrdinalIgnoreCase));

    /// <summary>Null when this release can be installed over <paramref name="installed"/>; otherwise why not.</summary>
    public static string? WhyNotInstallable(ReleaseInfo release, string? installed)
    {
        if (Find(release.Package) is null) return $"{release.Package} cannot be updated from here.";
        if (!release.Ok) return "Check for updates first.";
        if (ReleaseCheck.IsNewer(release.LatestVersion, installed) == false)
            return $"{release.Package} {installed} is already the latest release.";
        if (release.Asset is null)
            return $"The {release.LatestVersion} release has no Windows x64 download. Use the release page.";
        if (release.Asset.Sha256 is null)
            return $"GitHub publishes no SHA-256 for {release.Asset.Name}, so it cannot be verified. " +
                   "Use the release page and check it by hand.";
        if (!ReleaseCheck.IsGitHubHttps(release.Asset.Url, out _))
            return $"{release.Asset.Name} is not served from github.com over https, so it was not used.";
        return null;
    }

    /// <summary>Downloads, verifies and installs the release's Windows download.</summary>
    public async Task<ToolUpdateOutcome> UpdateAsync(ReleaseInfo release, string? installed,
        IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        var reason = WhyNotInstallable(release, installed);
        if (reason is not null) throw new UpdateException(reason);

        var asset = release.Asset!;
        var work = PrepareWork(release);
        try
        {
            var zipPath = Path.Combine(work, asset.Name);
            using (var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) })
            {
                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("ArtefactForge", BuildInfo.Version));
                // The default handler follows GitHub's redirect to its download host and refuses
                // any redirect from https to http.
                using var response = await client.GetAsync(asset.Url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                response.EnsureSuccessStatusCode();
                await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
                await using var output = File.Create(zipPath);
                await GitHubReleaseSource.Copy(input, output, progress, cancellationToken);
            }

            return Install(zipPath, release, installed, work);
        }
        finally
        {
            TryDelete(work);
        }
    }

    /// <summary>
    /// Installs an already-downloaded release zip. Public so the install can be tested without a
    /// network; <see cref="UpdateAsync"/> is the way in for the application.
    /// </summary>
    public ToolUpdateOutcome Install(string zipPath, ReleaseInfo release, string? installed, string? work = null)
    {
        var reason = WhyNotInstallable(release, installed);
        if (reason is not null) throw new UpdateException(reason);

        var spec = Find(release.Package)!;
        var asset = release.Asset!;
        var ownsWork = work is null;
        work ??= PrepareWork(release);

        try
        {
            var size = new FileInfo(zipPath).Length;
            if (asset.Size > 0 && size != asset.Size)
                throw new UpdateException(
                    $"The download is {size:N0} bytes, not the {asset.Size:N0} GitHub states - incomplete or altered. Nothing was changed.");

            if (!string.Equals(SelfUpdater.Sha256(zipPath), asset.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new UpdateException(
                    $"The SHA-256 of {asset.Name} does not match the one GitHub publishes. It was not used and nothing was changed.");

            var extracted = SelfUpdater.Extract(zipPath, Path.Combine(work, "extracted"));

            var executables = Directory.EnumerateFiles(extracted)
                .Where(f => spec.ExecutablePattern.IsMatch(Path.GetFileName(f)))
                .ToList();
            if (executables.Count != 1)
                throw new UpdateException(
                    $"{asset.Name} does not contain exactly one {spec.Executable} (found {executables.Count}). Nothing was changed.");

            var live = Path.Combine(ToolsDirectory, spec.Name);
            var staged = Path.Combine(work, "new");
            BuildFolder(live, extracted, executables[0], spec, staged);

            var exeHash = SelfUpdater.Sha256(Path.Combine(staged, spec.Executable));
            Swap(live, staged, Path.Combine(work, "previous"), () => WriteVersions(spec, release, executables[0], exeHash));

            return new ToolUpdateOutcome(spec.Name, installed, release.LatestVersion!, exeHash);
        }
        finally
        {
            if (ownsWork) TryDelete(work);
        }
    }

    private string PrepareWork(ReleaseInfo release)
    {
        var work = Path.Combine(ToolsDirectory, WorkFolder, $"{release.Package}-{release.LatestVersion}");
        if (Directory.Exists(work)) Directory.Delete(work, recursive: true);
        Directory.CreateDirectory(work);
        return work;
    }

    /// <summary>
    /// The new folder is the old one, less the folders the release replaces, with the release laid
    /// over it. Anything else already there (Hayabusa's logs, Chainsaw's rules) is kept.
    /// </summary>
    private static void BuildFolder(string live, string extracted, string executable, ToolPackage spec, string staged)
    {
        Directory.CreateDirectory(staged);

        if (Directory.Exists(live))
        {
            foreach (var entry in new DirectoryInfo(live).EnumerateFileSystemInfos())
            {
                if (entry is DirectoryInfo dir)
                {
                    if (spec.ReplacedFolders.Contains(dir.Name, StringComparer.OrdinalIgnoreCase)) continue;
                    CopyDirectory(dir.FullName, Path.Combine(staged, dir.Name));
                }
                else
                {
                    File.Copy(entry.FullName, Path.Combine(staged, entry.Name));
                }
            }
        }

        foreach (var entry in new DirectoryInfo(extracted).EnumerateFileSystemInfos())
        {
            if (entry is DirectoryInfo dir)
            {
                var target = Path.Combine(staged, dir.Name);
                // A folder the release ships but the spec does not list as replaced is merged, so
                // nothing the analyst added to it is lost.
                CopyDirectory(dir.FullName, target);
            }
            else
            {
                var name = string.Equals(entry.FullName, executable, StringComparison.OrdinalIgnoreCase)
                    ? spec.Executable
                    : entry.Name;
                File.Copy(entry.FullName, Path.Combine(staged, name), overwrite: true);
            }
        }
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var dir in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, dir)));
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
            File.Copy(file, Path.Combine(destination, Path.GetRelativePath(source, file)), overwrite: true);
    }

    private static void Swap(string live, string staged, string previous, Action recordVersions)
    {
        var hadLive = Directory.Exists(live);
        if (hadLive)
        {
            try
            {
                Directory.Move(live, previous);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new UpdateException(
                    $"{live} could not be replaced ({ex.Message}). Close anything using the tool, such as a " +
                    "run or a console window in that folder, and try again. Nothing was changed.", ex);
            }
        }

        var movedIn = false;
        try
        {
            Directory.Move(staged, live);
            movedIn = true;
            recordVersions();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try
            {
                if (movedIn) Directory.Delete(live, recursive: true);
                if (hadLive) Directory.Move(previous, live);
            }
            catch (Exception restore) when (restore is IOException or UnauthorizedAccessException)
            {
                throw new UpdateException(
                    $"The update failed ({ex.Message}) and the previous version could not be put back " +
                    $"({restore.Message}). It is in {previous}; move it back to {live} by hand.", ex);
            }
            throw new UpdateException($"The update failed ({ex.Message}). The previous version was put back.", ex);
        }
    }

    private void WriteVersions(ToolPackage spec, ReleaseInfo release, string sourceExecutable, string exeHash)
    {
        var path = Path.Combine(ToolsDirectory, VersionsFile);
        var bytes = File.Exists(path) ? File.ReadAllBytes(path) : [];
        var hasBom = bytes is [0xEF, 0xBB, 0xBF, ..];
        var text = new UTF8Encoding(false).GetString(bytes, hasBom ? 3 : 0, bytes.Length - (hasBom ? 3 : 0));

        var updated = WithEntry(text, spec.Executable, release.LatestVersion!, Path.GetFileName(sourceExecutable),
                                exeHash, release.Asset!.Name, release.Asset.Sha256!, DateTime.Now);

        var temp = path + ".new";
        File.WriteAllText(temp, updated, new UTF8Encoding(hasBom || bytes.Length == 0));
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>
    /// VERSIONS.txt with one tool's entry replaced, or added at the end. An entry is the line that
    /// starts with the executable's name and the indented lines under it.
    /// </summary>
    public static string WithEntry(string text, string executable, string version, string sourceExecutable,
        string exeSha256, string assetName, string assetSha256, DateTime when)
    {
        // The file is hand-edited and mixes LF and CRLF, so split on either and write CRLF back.
        var newline = text.Contains("\r\n") || text.Length == 0 ? "\r\n" : "\n";
        var lines = text.Length == 0 ? [] : text.Replace("\r\n", "\n").Split('\n').ToList();
        var indent = new string(' ', 15);

        string[] entry =
        [
            $"{executable.PadRight(15)}{("v" + version).PadRight(8)}({sourceExecutable})",
            $"{indent}SHA256 {exeSha256.ToUpperInvariant()}",
            $"{indent}Updated {when:yyyy-MM-dd} by ArtefactForge from {assetName}",
            $"{indent}(SHA256 {assetSha256.ToUpperInvariant()})"
        ];

        var start = lines.FindIndex(l => l.Length > 0 && !char.IsWhiteSpace(l[0])
                                         && l.Split(' ', '\t')[0].Equals(executable, StringComparison.OrdinalIgnoreCase));
        if (start < 0)
        {
            while (lines.Count > 0 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);
            if (lines.Count > 0) lines.Add("");
            lines.AddRange(entry);
            lines.Add("");
            return string.Join(newline, lines);
        }

        var end = start + 1;
        while (end < lines.Count && lines[end].Length > 0 && char.IsWhiteSpace(lines[end][0])) end++;

        lines.RemoveRange(start, end - start);
        lines.InsertRange(start, entry);
        return string.Join(newline, lines);
    }

    private static void TryDelete(string directory)
    {
        try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
        catch { /* leftover download space only; the next update clears it */ }

        // Leave no empty _update\ behind: package.ps1 copies Tools\ whole.
        try
        {
            var parent = Path.GetDirectoryName(directory);
            if (parent is not null && Directory.Exists(parent) && !Directory.EnumerateFileSystemEntries(parent).Any())
                Directory.Delete(parent);
        }
        catch { /* as above */ }
    }
}
