using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace ArtefactForge.Core.Update;

public enum UpdateCheckStatus { Available, UpToDate, NotPossible, Failed }

public sealed record UpdateCheck(UpdateCheckStatus Status, ReleaseManifest? Release, string Message);

/// <summary>A downloaded, verified and extracted release, ready to plan and apply.</summary>
public sealed record StagedUpdate(ReleaseManifest Release, string PackageRoot, PackageManifest Manifest, string SourceDescription);

public enum ChangeKind
{
    /// <summary>New in this release.</summary>
    Add,
    /// <summary>The package's own file, replaced with the new version.</summary>
    Replace,
    /// <summary>Same content already - nothing to do.</summary>
    Unchanged,
    /// <summary>The analyst edited a module, layout, profile or Apps.yaml: theirs stays, ours goes beside it as .new.</summary>
    KeepUserCopy,
    /// <summary>Dropped from the package and untouched locally - removed (a copy is kept in the backup).</summary>
    Remove,
    /// <summary>Dropped from the package but edited locally - left where it is.</summary>
    LeaveEdited
}

public sealed record PlannedChange(string RelativePath, ChangeKind Kind);

public sealed record UpdatePlan(IReadOnlyList<PlannedChange> Changes)
{
    public int Count(ChangeKind kind) => Changes.Count(c => c.Kind == kind);

    public IEnumerable<string> Paths(ChangeKind kind) => Changes.Where(c => c.Kind == kind).Select(c => c.RelativePath);

    public string Summary() =>
        $"{Count(ChangeKind.Replace)} replaced, {Count(ChangeKind.Add)} added, {Count(ChangeKind.Remove)} removed, " +
        $"{Count(ChangeKind.Unchanged)} unchanged, {Count(ChangeKind.KeepUserCopy)} kept as you edited them";
}

public sealed record UpdateOutcome(string FromVersion, string ToVersion, UpdatePlan Plan, string BackupDirectory);

/// <summary>
/// Updates a packaged ArtefactForge folder in place from a signed release.
///
/// Order of trust: the manifest's signature is checked before the manifest is read; the zip's size
/// and SHA-256 (from the signed manifest) before it is opened; each extracted file's hash (from the
/// package's own files.txt, inside the verified zip) before anything is copied. Nothing outside
/// _update\ is written until all of that has passed.
///
/// Applying: every file about to be replaced or removed is copied to _previous\&lt;old version&gt;\
/// first. Windows will not overwrite a running exe but will rename one, so a file that cannot be
/// overwritten is renamed to *.af-old and the new one copied in beside it; the leftovers are
/// deleted on the next start. Any failure part-way restores everything from the backup.
/// </summary>
public sealed class SelfUpdater
{
    public const string UpdateFolder = "_update";
    public const string PreviousFolder = "_previous";
    public const string LogFileName = "updates.log";
    private const string OldSuffix = ".af-old";
    private const string NewSuffix = ".new";
    private const string CleanupListName = "pending-cleanup.txt";

    private static readonly string[] UserEditableFolders = ["Modules", "Layouts", "Profiles"];
    private static readonly string[] RequiredFiles = ["ArtefactForge.exe", "ArtefactForgeCli.exe"];

    private readonly IReadOnlyList<string> _trustedKeys;

    public string InstallDirectory { get; }
    public string InstalledVersion { get; }

    public SelfUpdater(string installDirectory, string installedVersion, IReadOnlyList<string>? trustedKeys = null)
    {
        InstallDirectory = Path.GetFullPath(installDirectory);
        InstalledVersion = installedVersion;
        _trustedKeys = trustedKeys ?? TrustedKeys.All;
    }

    /// <summary>The folder holding the running executable, at the running version.</summary>
    public static SelfUpdater ForRunningApplication() =>
        new(Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory, BuildInfo.Version);

    // ------------------------------------------------------------------ preconditions

    /// <summary>Null when this folder can be updated; otherwise a reason to show as it is.</summary>
    public string? WhyNotUpdatable()
    {
        if (_trustedKeys.Count == 0)
            return "This build has no release signing key, so updates are turned off.";

        if (Directory.Exists(Path.Combine(InstallDirectory, "src")) || Directory.Exists(Path.Combine(InstallDirectory, ".git")))
            return "This is a source checkout, not an installed package - update it with git.";

        if (!File.Exists(Path.Combine(InstallDirectory, "BUILD.txt")))
            return "This is not a packaged build (there is no BUILD.txt), so there is nothing to update in place.";

        try
        {
            var probe = Path.Combine(InstallDirectory, ".af-write-test-" + Guid.NewGuid().ToString("N")[..8]);
            File.WriteAllText(probe, "");
            File.Delete(probe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"The application folder cannot be written to ({InstallDirectory}) - read-only media, or it needs elevation.";
        }

        return null;
    }

    // ------------------------------------------------------------------------ check

    public async Task<UpdateCheck> CheckAsync(IReleaseSource source, CancellationToken cancellationToken = default)
    {
        var reason = WhyNotUpdatable();
        if (reason is not null) return new UpdateCheck(UpdateCheckStatus.NotPossible, null, reason);

        try
        {
            var release = await ReadVerifiedManifestAsync(source, cancellationToken);
            return ReleaseCheck.IsNewer(release.Version, InstalledVersion) switch
            {
                true => new UpdateCheck(UpdateCheckStatus.Available, release,
                    $"ArtefactForge {release.Version} is available (this is {InstalledVersion})."),
                false => new UpdateCheck(UpdateCheckStatus.UpToDate, release,
                    $"ArtefactForge {InstalledVersion} is up to date (latest published: {release.Version})."),
                null => new UpdateCheck(UpdateCheckStatus.Failed, release,
                    $"Cannot compare the published version '{release.Version}' with this one ({InstalledVersion}).")
            };
        }
        catch (UpdateException ex) { return new UpdateCheck(UpdateCheckStatus.Failed, null, ex.Message); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // No network on an isolated workstation is normal - say so plainly rather than throw.
            return new UpdateCheck(UpdateCheckStatus.Failed, null, $"Could not reach {source.Description}: {ex.Message}");
        }
    }

    private async Task<ReleaseManifest> ReadVerifiedManifestAsync(IReleaseSource source, CancellationToken cancellationToken)
    {
        var manifest = await source.ReadManifestAsync(cancellationToken);
        var signature = Encoding.ASCII.GetString(await source.ReadSignatureAsync(cancellationToken));

        // Before parsing: an unsigned manifest is not read at all, not even for its version number.
        if (!ReleaseSigning.Verify(manifest, signature, _trustedKeys))
            throw new UpdateException(
                $"The release published at {source.Description} failed its signature check, so it was not used. " +
                "Nothing was downloaded. If this persists, download the release from GitHub by hand and report it.");

        return ReleaseManifest.Parse(manifest);
    }

    // --------------------------------------------------------------------- download

    public async Task<StagedUpdate> DownloadAsync(IReleaseSource source, ReleaseManifest release,
        IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        if (ReleaseCheck.IsNewer(release.Version, InstalledVersion) != true)
            throw new UpdateException($"{release.Version} is not newer than {InstalledVersion}; refusing to install it.");

        var work = Path.Combine(InstallDirectory, UpdateFolder, release.Version);
        if (Directory.Exists(work)) Directory.Delete(work, recursive: true);
        Directory.CreateDirectory(work);

        var zipPath = Path.Combine(work, release.File);
        await source.DownloadPackageAsync(release.File, zipPath, progress, cancellationToken);

        var size = new FileInfo(zipPath).Length;
        if (size != release.Size)
            throw Discard(work, $"The download is {size:N0} bytes, not the {release.Size:N0} the release states - incomplete or altered.");

        if (!string.Equals(Sha256(zipPath), release.Sha256, StringComparison.OrdinalIgnoreCase))
            throw Discard(work, "The download's SHA-256 does not match the signed release - it was not used.");

        var packageRoot = Extract(zipPath, Path.Combine(work, "package"));

        var manifest = PackageManifest.Load(packageRoot)
                       ?? throw Discard(work, $"The release has no {PackageManifest.FileName}.");

        foreach (var required in RequiredFiles)
            if (!manifest.Files.ContainsKey(required))
                throw Discard(work, $"The release does not contain {required}.");

        foreach (var (relative, hash) in manifest.Files)
        {
            var path = PackageManifest.Local(packageRoot, relative);
            if (!File.Exists(path) || !string.Equals(Sha256(path), hash, StringComparison.OrdinalIgnoreCase))
                throw Discard(work, $"{relative} in the release does not match its {PackageManifest.FileName} entry.");
        }

        return new StagedUpdate(release, packageRoot, manifest, source.Description);
    }

    private static UpdateException Discard(string work, string message)
    {
        try { Directory.Delete(work, recursive: true); } catch { /* best effort; the next attempt starts clean */ }
        return new UpdateException(message);
    }

    /// <summary>Extracts with no entry allowed outside <paramref name="destination"/>. Returns the package root.</summary>
    public static string Extract(string zipPath, string destination)
    {
        Directory.CreateDirectory(destination);
        var root = Path.GetFullPath(destination) + Path.DirectorySeparatorChar;

        using var zip = ZipFile.OpenRead(zipPath);
        foreach (var entry in zip.Entries)
        {
            var target = Path.GetFullPath(Path.Combine(root, entry.FullName.Replace('\\', '/')));
            if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new UpdateException($"The release zip has an entry outside its folder: '{entry.FullName}'.");

            if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\')) { Directory.CreateDirectory(target); continue; }
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target, overwrite: false);
        }

        // The zip holds ArtefactForge\ itself, so extracting by hand gives one tidy folder.
        var entries = Directory.GetFileSystemEntries(destination);
        return entries.Length == 1 && Directory.Exists(entries[0]) ? entries[0] : destination;
    }

    // ------------------------------------------------------------------------- plan

    public UpdatePlan Plan(StagedUpdate staged)
    {
        var installed = PackageManifest.Load(InstallDirectory) ?? PackageManifest.Empty;
        var changes = new List<PlannedChange>();

        foreach (var (relative, newHash) in staged.Manifest.Files.OrderBy(f => f.Key, StringComparer.OrdinalIgnoreCase))
        {
            var local = PackageManifest.Local(InstallDirectory, relative);
            if (!File.Exists(local)) { changes.Add(new(relative, ChangeKind.Add)); continue; }

            var localHash = Sha256(local);
            if (string.Equals(localHash, newHash, StringComparison.OrdinalIgnoreCase))
                changes.Add(new(relative, ChangeKind.Unchanged));
            else if (installed.Files.TryGetValue(relative, out var shipped) && string.Equals(localHash, shipped, StringComparison.OrdinalIgnoreCase))
                changes.Add(new(relative, ChangeKind.Replace));
            else
                // Edited since it was installed (or there is no record of what was installed). The
                // analyst's configuration is theirs; program files are ours and get replaced - the
                // backup keeps the old copy either way.
                changes.Add(new(relative, IsUserEditable(relative) ? ChangeKind.KeepUserCopy : ChangeKind.Replace));
        }

        foreach (var (relative, shipped) in installed.Files.OrderBy(f => f.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (staged.Manifest.Files.ContainsKey(relative)) continue;
            var local = PackageManifest.Local(InstallDirectory, relative);
            if (!File.Exists(local)) continue;

            changes.Add(new(relative, string.Equals(Sha256(local), shipped, StringComparison.OrdinalIgnoreCase)
                ? ChangeKind.Remove
                : ChangeKind.LeaveEdited));
        }

        return new UpdatePlan(changes);
    }

    internal static bool IsUserEditable(string relative)
    {
        if (relative.Equals("Apps.yaml", StringComparison.OrdinalIgnoreCase)) return true;
        var first = relative.Split('\\')[0];
        return UserEditableFolders.Contains(first, StringComparer.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------------------ apply

    private enum StepKind { Added, Replaced, Removed }

    private sealed record Step(StepKind Kind, string Target, string? Backup, string? RenamedTo);

    public UpdateOutcome Apply(StagedUpdate staged, UpdatePlan plan)
    {
        var backup = UniqueDirectory(Path.Combine(InstallDirectory, PreviousFolder, InstalledVersion));
        var journal = new List<Step>();
        var leftovers = new List<string>();

        try
        {
            foreach (var change in plan.Changes)
            {
                var source = PackageManifest.Local(staged.PackageRoot, change.RelativePath);
                var target = PackageManifest.Local(InstallDirectory, change.RelativePath);

                switch (change.Kind)
                {
                    case ChangeKind.Add:
                        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                        File.Copy(source, target, overwrite: false);
                        journal.Add(new Step(StepKind.Added, target, null, null));
                        break;

                    case ChangeKind.Replace:
                        journal.Add(Replace(source, target, BackUp(target, change.RelativePath, backup), leftovers));
                        break;

                    case ChangeKind.Remove:
                        journal.Add(Remove(target, BackUp(target, change.RelativePath, backup), leftovers));
                        break;

                    case ChangeKind.KeepUserCopy:
                        var beside = target + NewSuffix;
                        if (File.Exists(beside))
                            journal.Add(Replace(source, beside, BackUp(beside, change.RelativePath + NewSuffix, backup), leftovers));
                        else
                        {
                            File.Copy(source, beside);
                            journal.Add(new Step(StepKind.Added, beside, null, null));
                        }
                        break;
                }
            }

            // The new files.txt goes in last: until it does, the folder still describes itself as
            // the old version, which is the truth if anything above failed.
            var manifestTarget = Path.Combine(InstallDirectory, PackageManifest.FileName);
            var manifestSource = Path.Combine(staged.PackageRoot, PackageManifest.FileName);
            if (File.Exists(manifestTarget))
                journal.Add(Replace(manifestSource, manifestTarget, BackUp(manifestTarget, PackageManifest.FileName, backup), leftovers));
            else
            {
                File.Copy(manifestSource, manifestTarget);
                journal.Add(new Step(StepKind.Added, manifestTarget, null, null));
            }
        }
        catch (Exception ex)
        {
            var restored = RollBack(journal);
            throw new UpdateException(
                $"The update failed and was rolled back{(restored ? "" : " - but not every file could be restored; the originals are in " + backup)}: {ex.Message}", ex);
        }

        KeepToolsNote(staged);
        Record(staged, plan, backup);
        if (leftovers.Count > 0)
            File.AppendAllLines(Path.Combine(InstallDirectory, PreviousFolder, CleanupListName), leftovers);

        PruneOldBackups(backup);
        try { Directory.Delete(Path.Combine(InstallDirectory, UpdateFolder), recursive: true); } catch { /* cleaned up next start */ }

        return new UpdateOutcome(InstalledVersion, staged.Release.Version, plan, backup);
    }

    private static string BackUp(string target, string relative, string backupRoot)
    {
        var copy = PackageManifest.Local(backupRoot, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
        File.Copy(target, copy, overwrite: true);
        return copy;
    }

    private static Step Replace(string source, string target, string backup, List<string> leftovers)
    {
        try
        {
            File.Copy(source, target, overwrite: true);
            return new Step(StepKind.Replaced, target, backup, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // In use - the running exe, or antivirus holding it. Windows allows a rename where it
            // refuses an overwrite, so move the old one aside and put the new one in its place.
            var aside = UniqueFile(target + OldSuffix);
            File.Move(target, aside);
            leftovers.Add(aside);
            File.Copy(source, target);
            return new Step(StepKind.Replaced, target, backup, aside);
        }
    }

    private static Step Remove(string target, string backup, List<string> leftovers)
    {
        try
        {
            File.Delete(target);
            return new Step(StepKind.Removed, target, backup, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            var aside = UniqueFile(target + OldSuffix);
            File.Move(target, aside);
            leftovers.Add(aside);
            return new Step(StepKind.Removed, target, backup, aside);
        }
    }

    /// <summary>Undoes the journal newest-first. Returns false if anything could not be put back.</summary>
    private static bool RollBack(List<Step> journal)
    {
        var complete = true;
        for (var i = journal.Count - 1; i >= 0; i--)
        {
            var step = journal[i];
            try
            {
                switch (step.Kind)
                {
                    case StepKind.Added:
                        File.Delete(step.Target);
                        break;

                    case StepKind.Replaced when step.RenamedTo is not null:
                        File.Delete(step.Target);
                        File.Move(step.RenamedTo, step.Target);
                        break;

                    case StepKind.Removed when step.RenamedTo is not null:
                        File.Move(step.RenamedTo, step.Target);
                        break;

                    default:
                        File.Copy(step.Backup!, step.Target, overwrite: true);
                        break;
                }
            }
            catch { complete = false; }
        }
        return complete;
    }

    /// <summary>
    /// Updates are built from the package without Tools\, whose BUILD.txt says tools are missing.
    /// In a folder that has its tools that would be untrue, so say what actually happened instead.
    /// </summary>
    private void KeepToolsNote(StagedUpdate staged)
    {
        var buildTxt = Path.Combine(InstallDirectory, "BUILD.txt");
        if (!Directory.Exists(Path.Combine(InstallDirectory, "Tools")) || !File.Exists(buildTxt)) return;

        try
        {
            var lines = File.ReadAllLines(buildTxt).ToList();
            var cut = lines.FindIndex(l => l.StartsWith("TOOLS ARE NOT INCLUDED", StringComparison.Ordinal));
            if (cut >= 0) lines.RemoveRange(cut, lines.Count - cut);
            while (lines.Count > 0 && lines[^1].Trim().Length == 0) lines.RemoveAt(lines.Count - 1);

            for (var i = 0; i < lines.Count; i++)
                if (lines[i].StartsWith("Tools ", StringComparison.Ordinal))
                    lines[i] = @"Tools      see Tools\VERSIONS.txt (kept from the earlier package)";

            lines.Add("");
            lines.Add($"Updated in place from {InstalledVersion} on {DateTime.Now:yyyy-MM-dd HH:mm:ss}; see {LogFileName}.");
            File.WriteAllLines(buildTxt, lines, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        }
        catch { /* informational only - never fail an applied update over it */ }
    }

    /// <summary>
    /// One line per update. Case manifests record the ArtefactForge version that produced them, so
    /// a version change part-way through a case has to be traceable to a time and a source.
    /// </summary>
    private void Record(StagedUpdate staged, UpdatePlan plan, string backup)
    {
        var line = $"{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss}Z  {InstalledVersion} -> {staged.Release.Version}  " +
                   $"from {staged.SourceDescription}  zip SHA256 {staged.Release.Sha256.ToUpperInvariant()}  " +
                   $"backup {Path.GetRelativePath(InstallDirectory, backup)}  {plan.Summary()}";
        try { File.AppendAllLines(Path.Combine(InstallDirectory, LogFileName), [line]); }
        catch { /* the update itself succeeded; a log failure is not a reason to report otherwise */ }
    }

    /// <summary>Keeps only the backup just made: one step of rollback, not an ever-growing folder.</summary>
    private void PruneOldBackups(string keep)
    {
        var previous = Path.Combine(InstallDirectory, PreviousFolder);
        foreach (var dir in Directory.EnumerateDirectories(previous))
            if (!string.Equals(Path.GetFullPath(dir), Path.GetFullPath(keep), StringComparison.OrdinalIgnoreCase))
                try { Directory.Delete(dir, recursive: true); } catch { /* harmless; tried again next update */ }
    }

    // ---------------------------------------------------------------------- restart

    /// <summary>
    /// Deletes the *.af-old files left by renaming in-use executables. Call on start-up; cheap when
    /// there is nothing to do. Anything still locked (the other exe still open) waits for next time.
    /// </summary>
    public static void CleanUpAfterUpdate(string installDirectory)
    {
        try
        {
            var list = Path.Combine(installDirectory, PreviousFolder, CleanupListName);
            if (File.Exists(list))
            {
                var remaining = new List<string>();
                foreach (var path in File.ReadAllLines(list).Where(l => l.Trim().Length > 0).Distinct())
                {
                    // Only ever delete what the updater itself set aside, inside this folder.
                    var full = Path.GetFullPath(path);
                    if (!full.EndsWith(OldSuffix, StringComparison.OrdinalIgnoreCase) && !full.Contains(OldSuffix + "-", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!full.StartsWith(Path.GetFullPath(installDirectory), StringComparison.OrdinalIgnoreCase)) continue;
                    try { if (File.Exists(full)) File.Delete(full); }
                    catch { remaining.Add(full); }
                }
                if (remaining.Count == 0) File.Delete(list);
                else File.WriteAllLines(list, remaining);
            }

            var staging = Path.Combine(installDirectory, UpdateFolder);
            if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        }
        catch { /* start-up must never fail over housekeeping */ }
    }

    // ---------------------------------------------------------------------- helpers

    public static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string UniqueDirectory(string path)
    {
        var candidate = path;
        for (var n = 2; Directory.Exists(candidate); n++) candidate = $"{path}-{n}";
        Directory.CreateDirectory(candidate);
        return candidate;
    }

    private static string UniqueFile(string path)
    {
        var candidate = path;
        for (var n = 2; File.Exists(candidate); n++) candidate = $"{path}-{n}";
        return candidate;
    }
}
