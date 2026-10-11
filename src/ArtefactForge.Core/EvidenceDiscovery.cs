using System.IO.Compression;

namespace ArtefactForge.Core;

/// <summary>What a selected evidence path turned out to hold.</summary>
public sealed class DiscoveryResult
{
    /// <summary>Collections to process: folders ready on disk, and zips still to be extracted.</summary>
    public List<ResolvedTarget> Targets { get; } = [];

    /// <summary>Folders and zips that were looked at and will not be processed, each with the reason.</summary>
    public List<UnmatchedInput> Unmatched { get; } = [];

    /// <summary>
    /// Batch only: the selection itself looks like a collection. A folder of collections does not,
    /// so batch is almost certainly the wrong choice - it would process the drive folder inside and
    /// name the collection after it, e.g. 'C' instead of the host.
    /// </summary>
    public bool SelectionIsCollection { get; set; }
}

public sealed record UnmatchedInput(string Path, string Reason);

/// <summary>
/// Turns what the analyst selected into collections. Shared by the CLI and the GUI so both accept
/// the same evidence and explain a rejection in the same words.
/// </summary>
public static class EvidenceDiscovery
{
    /// <summary>
    /// <paramref name="path"/> may be a folder (a collection, a mounted drive), a zip, or with
    /// <paramref name="batch"/> a folder whose subfolders and zips are each one collection.
    /// </summary>
    public static DiscoveryResult Discover(string path, bool batch, IReadOnlyList<LayoutProfile> layouts)
    {
        var result = new DiscoveryResult();

        if (File.Exists(path))
        {
            if (batch)
                result.Unmatched.Add(new UnmatchedInput(path, "batch needs a folder of collections, not a single file"));
            else
                AddArchive(result, path, layouts);
            return result;
        }

        if (!Directory.Exists(path))
        {
            result.Unmatched.Add(new UnmatchedInput(path, "no such file or folder"));
            return result;
        }

        if (!batch)
        {
            if (IsCollectorFolder(path))
            {
                AddArchive(result, path, layouts);
                return result;
            }

            result.Targets.AddRange(LayoutDetector.Detect(path, layouts));
            if (result.Targets.Count == 0)
                result.Unmatched.Add(new UnmatchedInput(path, "no evidence layout matched"));
            return result;
        }

        result.SelectionIsCollection = LayoutDetector.Detect(path, layouts).Count > 0;

        List<string> entries;
        try
        {
            entries = Directory.EnumerateDirectories(path)
                .Concat(Directory.EnumerateFiles(path).Where(CollectionSource.IsArchiveName))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            result.Unmatched.Add(new UnmatchedInput(path, "could not list its contents: " + ex.Message));
            return result;
        }

        // A zip often sits beside the folder it was extracted into, named the same. Both would be
        // the same collection under the same name, so the folder is passed over for the zip: the
        // zip is the copy as collected, and every entry in it is checked against its CRC.
        var zips = entries.Where(e => File.Exists(e))
                          .Select(z => (Zip: z, Inspected: InspectArchive(z, layouts)))
                          .ToDictionary(z => z.Zip, z => z.Inspected, StringComparer.OrdinalIgnoreCase);
        var zipStems = zips.Where(z => z.Value.Targets.Count > 0)
                           .ToDictionary(z => CollectionSource.Stem(z.Key), z => z.Key,
                                         StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (zips.TryGetValue(entry, out var inspected))
            {
                if (inspected.Targets.Count > 0) result.Targets.AddRange(inspected.Targets);
                else result.Unmatched.Add(new UnmatchedInput(entry, inspected.Reason ?? "no recognised collection inside"));
                continue;
            }

            if (zipStems.TryGetValue(Path.GetFileName(entry), out var zip))
            {
                result.Unmatched.Add(new UnmatchedInput(entry,
                    $"the extracted copy of {Path.GetFileName(zip)}, which is processed instead"));
                continue;
            }

            if (IsCollectorFolder(entry))
            {
                AddArchive(result, entry, layouts);
                continue;
            }

            var found = LayoutDetector.Detect(entry, layouts);
            if (found.Count == 0) result.Unmatched.Add(new UnmatchedInput(entry, "no evidence layout matched"));
            result.Targets.AddRange(found);
        }
        return result;
    }

    private static void AddArchive(DiscoveryResult result, string zipPath, IReadOnlyList<LayoutProfile> layouts)
    {
        var (targets, reason) = InspectArchive(zipPath, layouts);
        if (targets.Count > 0) result.Targets.AddRange(targets);
        else result.Unmatched.Add(new UnmatchedInput(zipPath, reason ?? "no recognised collection inside"));
    }

    /// <summary>
    /// Reads a zip's directory, not its contents, and says whether it holds a collection this build
    /// can process. Returns targets, or none and the reason in terms the analyst can act on. An
    /// unzipped Velociraptor collection is inspected the same way, from its file names.
    /// </summary>
    public static (IReadOnlyList<ResolvedTarget> Targets, string? Reason) InspectArchive(
        string zipPath, IReadOnlyList<LayoutProfile> layouts)
    {
        if (Directory.Exists(zipPath)) return InspectCollectorFolder(zipPath, layouts);

        if (!CollectionSource.IsArchiveName(zipPath))
            return ([], "only .zip, .tar and .tar.gz archives can be extracted; extract it first and select the folder");

        try
        {
            if (CollectionSource.IsTarFile(zipPath)) return InspectTar(zipPath, layouts);

            using var zip = ZipFile.OpenRead(zipPath);
            // Neither CyLR's --zippassword nor an encrypted Velociraptor collector can be read by
            // .NET's zip support. Checked up front so it is said plainly, not as a mid-run failure.
            if (zip.Entries.Any(e => e.IsEncrypted))
                return ([], "the zip is encrypted - extract it with the collection's password, then select the folder");

            var names = zip.Entries.Select(e => e.FullName).ToList();
            if (UacCollection.IsCollection(names))
                return DetectUac(zipPath, names, name => zip.GetEntry(name)?.Open(), layouts);
            if (!VelociraptorCollection.IsCollection(names))
            {
                var targets = LayoutDetector.DetectArchive(zipPath, names, layouts);
                return targets.Count > 0 ? (targets, null) : ([], "no recognised collection inside");
            }

            return DetectVelociraptor(zipPath, names, name => zip.GetEntry(name)?.Open(), layouts);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return ([], "could not be read as a zip: " + ex.Message);
        }
    }

    /// <summary>
    /// A tar has no directory to read, so its headers are read front to back and reading stops once
    /// the collection is recognised. UAC writes uac.log first, so its host is known at once; a
    /// collection that can hold several drive folders is read to the end so none is missed.
    /// </summary>
    private static (IReadOnlyList<ResolvedTarget>, string?) InspectTar(string tarPath, IReadOnlyList<LayoutProfile> layouts)
    {
        var names = new List<string>();
        byte[]? log = null;
        var nextCheck = 256;
        try
        {
            foreach (var (entry, data) in CollectionSource.ReadTarHeaders(tarPath))
            {
                names.Add(entry.FullName);
                if (log is null && entry.FullName == "uac.log" && data() is { } stream)
                {
                    using var copy = new MemoryStream();
                    stream.CopyTo(copy);
                    log = copy.ToArray();
                }

                if (names.Count < nextCheck) continue;
                nextCheck *= 2;
                var (early, _) = Recognise();
                if (early.Count > 0 && early.All(t => t.Layout.Detect.RootIsSelection)) return (early, null);
            }
        }
        catch (Exception ex) when (ex is EndOfStreamException or InvalidDataException or FormatException)
        {
            // Damaged: judged on what could be read. If it is a collection, the extraction reports
            // the damage on its row and in the log, and keeps everything before it.
            var (partial, reason) = Recognise();
            return partial.Count > 0 ? (partial, null) : ([], reason + "; " + CollectionSource.Damaged(ex));
        }
        return Recognise();

        (IReadOnlyList<ResolvedTarget>, string?) Recognise()
        {
            if (UacCollection.IsCollection(names))
                return DetectUac(tarPath, names, name => name == "uac.log" && log is not null ? new MemoryStream(log) : null, layouts);
            var targets = LayoutDetector.DetectArchive(tarPath, names, layouts);
            return targets.Count > 0 ? (targets, null) : ([], "no recognised collection inside");
        }
    }

    /// <summary>
    /// Detected on the names the files will have once converted - [root] as the filesystem root -
    /// and named after the host recorded in uac.log.
    /// </summary>
    private static (IReadOnlyList<ResolvedTarget>, string?) DetectUac(
        string source, IReadOnlyList<string> names, VelociraptorCollection.Opener open,
        IReadOnlyList<LayoutProfile> layouts)
    {
        var mapped = names.Select(UacCollection.MapEntry).OfType<string>().ToList();
        var host = UacCollection.Hostname(open, source);
        if (host is not null && !CollectionNaming.TryValidate(host, out host, out _)) host = null;
        if (host is null) host = CollectionSource.Stem(source);

        var found = LayoutDetector.DetectArchive(source, mapped, layouts, host);
        return found.Count > 0
            ? (found, null)
            : ([], "a UAC collection, but no Linux filesystem was found under [root]");
    }

    /// <summary>A collector's output that has been unpacked but still needs converting.</summary>
    private static bool IsCollectorFolder(string path) =>
        VelociraptorCollection.IsFolder(path) || UacCollection.IsFolder(path);

    private static (IReadOnlyList<ResolvedTarget>, string?) InspectCollectorFolder(
        string folder, IReadOnlyList<LayoutProfile> layouts)
    {
        try
        {
            using var source = CollectionSource.Open(folder);
            var names = source.Entries.Select(e => e.FullName).ToList();
            return UacCollection.IsFolder(folder)
                ? DetectUac(folder, names, source.OpenByName, layouts)
                : DetectVelociraptor(folder, names, source.OpenByName, layouts);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ([], "could not be read: " + ex.Message);
        }
    }

    /// <summary>
    /// Detected on the names the files will have once converted, and named after the host the
    /// collector ran on - the zip is named after the collection time as well.
    /// </summary>
    private static (IReadOnlyList<ResolvedTarget>, string?) DetectVelociraptor(
        string source, IReadOnlyList<string> names, VelociraptorCollection.Opener open,
        IReadOnlyList<LayoutProfile> layouts)
    {
        var mapped = names.Select(n => VelociraptorCollection.MapEntry(n, out _))
                          .OfType<string>()
                          .Select(n => n.Replace('\\', '/'))
                          .ToList();
        var host = VelociraptorCollection.Hostname(open);
        if (host is not null && !CollectionNaming.TryValidate(host, out host, out _)) host = null;

        var found = LayoutDetector.DetectArchive(source, mapped, layouts, host);
        return found.Count > 0
            ? (found, null)
            : ([], "a Velociraptor collection, but no Windows drive was found in its uploads");
    }
}
