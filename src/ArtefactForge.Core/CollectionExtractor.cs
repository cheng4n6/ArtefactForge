using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArtefactForge.Core;

/// <summary>What happened when one zip (or collector folder) was extracted, for the run manifest.</summary>
public sealed class ExtractionRecord
{
    /// <summary>The zip, or the collector's folder that was converted.</summary>
    public required string ArchivePath { get; init; }
    public required string ExtractedTo { get; init; }
    public long ArchiveBytes { get; set; }
    /// <summary>SHA-256 of the zip. Null for a folder, which has no single file to hash.</summary>
    public string? ArchiveSha256 { get; set; }
    public int Files { get; set; }
    public long Bytes { get; set; }
    /// <summary>True when a complete extraction of the same source from an earlier run was used again.</summary>
    public bool Reused { get; set; }
    public bool CleanedUp { get; set; }
    /// <summary>Why the extracted data could not be deleted, when cleanup was asked for and failed.</summary>
    public string? CleanupError { get; set; }
    public double DurationSeconds { get; set; }
    /// <summary>Entries that were not extracted cleanly, each with the reason.</summary>
    public List<string> Problems { get; } = [];
    /// <summary>Things the analyst should know that are not faults, such as files left out by design.</summary>
    public List<string> Notes { get; } = [];
    /// <summary>Set when extraction stopped altogether; nothing should be parsed from it.</summary>
    public string? Error { get; set; }
    public string? LogPath { get; set; }
}

/// <summary>
/// Unpacks a collection zip into a working folder for the modules to read. Every entry is checked
/// against the CRC-32 and length the zip recorded for it, because a short or corrupt file would
/// otherwise reach a parser and could come back as a smaller but complete-looking result.
///
/// A Velociraptor collection someone has already unzipped goes through the same conversion from
/// its folder. The folder is only read; the converted copy is what the modules see.
/// </summary>
public static class CollectionExtractor
{
    /// <summary>
    /// Written into the extraction folder. It marks the folder as ours, so a re-run may replace it,
    /// and records which source it came from, so a re-run of the same source can reuse it.
    /// </summary>
    public const string MarkerName = "_extraction.json";

    /// <summary>
    /// Written at the extraction root when the source held symbolic links, which are listed here
    /// rather than created: Path (relative to the root, '/'-separated, as extracted), Target (as
    /// recorded on the source system) and ArchiveEntry. Linux modules that read link targets, such
    /// as systemd enablement and /etc/localtime, read this file when the link itself is absent.
    /// </summary>
    public const string SymlinkList = "_symlinks.csv";

    /// <summary>Starts the problem recorded when a collector says its collection is incomplete.</summary>
    public const string IncompletePrefix = "collection incomplete: ";

    /// <summary>Headroom left on the volume beyond the uncompressed size, for the modules' own output.</summary>
    private const long SpaceMargin = 256L * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private sealed class Marker
    {
        public string Archive { get; set; } = "";
        /// <summary>Identifies the source's content; see <see cref="SignatureAsync"/>.</summary>
        public string Signature { get; set; } = "";
        public bool Completed { get; set; }
        public int Files { get; set; }
        public long Bytes { get; set; }
        public List<string> Problems { get; set; } = [];
        public List<string> Notes { get; set; } = [];
    }

    public static async Task<ExtractionRecord> ExtractAsync(
        string sourcePath, string destination, string? logPath,
        IProgress<(long Done, long Total)>? progress, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.Now;
        var isFolder = Directory.Exists(sourcePath);
        var root = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar);
        var record = new ExtractionRecord
        {
            ArchivePath = Path.GetFullPath(sourcePath).TrimEnd(Path.DirectorySeparatorChar),
            ExtractedTo = root,
            LogPath = logPath
        };

        // The zip's SHA-256 is read beside the extraction rather than before it: hashing first meant
        // a full extra read of a multi-GB zip, with nothing to show for it, before a file appeared.
        Task<string>? hashing = null;

        try
        {
            if (isFolder && (root + Path.DirectorySeparatorChar).StartsWith(
                    record.ArchivePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                // The copy would land inside the evidence it is read from.
                record.Error = $"the extraction folder '{root}' is inside the collection being converted - "
                               + "choose an extraction folder elsewhere";
                return record;
            }

            if (!isFolder)
            {
                record.ArchiveBytes = new FileInfo(sourcePath).Length;
                hashing = Task.Run(() => HashAsync(sourcePath, cancellationToken), cancellationToken);
            }
            // A folder's signature is cheap; a zip's needs the hash, so it is taken when needed.
            var signature = isFolder ? await SignatureAsync(sourcePath, null, cancellationToken) : null;
            async Task<string> Signature() =>
                signature ??= await SignatureAsync(sourcePath, record.ArchiveSha256 ??= await hashing!, cancellationToken);

            var markerPath = Path.Combine(root, MarkerName);
            if (Directory.Exists(root))
            {
                var marker = ReadMarker(markerPath);
                if (marker is null && Directory.EnumerateFileSystemEntries(root).Any())
                {
                    // Never delete a folder we did not make: it could be anything, evidence included.
                    record.Error = $"'{root}' already exists and was not created by ArtefactForge - "
                                   + "move it, or choose another extraction folder";
                    return record;
                }

                if (marker is { Completed: true } && marker.Signature == await Signature())
                {
                    record.Reused = true;
                    record.Files = marker.Files;
                    record.Bytes = marker.Bytes;
                    record.Problems.AddRange(marker.Problems);
                    record.Notes.AddRange(marker.Notes);
                    return record;
                }

                // Ours, but partial or from a different source. A half-written tree is never reused.
                Directory.Delete(root, recursive: true);
            }

            using var source = CollectionSource.Open(sourcePath);
            if (isFolder) record.ArchiveBytes = source.Entries.Sum(e => e.Length);

            var plan = PlanEntries(source, record);
            var total = source.Entries.Sum(e => e.Length);
            var needed = plan.Sum(p => p.Index is not null ? 0 : p.Sparse is not null && !p.Compact
                ? VelociraptorCollection.OriginalLength(p.Sparse) : p.Entry.Length);

            var free = DiskSpace.Available(root);
            if (free is null)
            {
                record.Notes.Add($"free space on {Path.GetPathRoot(root)} could not be read, so it was not checked "
                                 + $"before extracting {Size(needed)}");
            }
            else if (free < needed + SpaceMargin)
            {
                record.Error = $"not enough free space to extract: needs {Size(needed)}, "
                               + $"{Size(free.Value)} free on {Path.GetPathRoot(root)}";
                return record;
            }

            Directory.CreateDirectory(root);
            // Partial, so never reused: a zip's signature waits for its hash, written at the end.
            WriteMarker(markerPath, new Marker { Archive = record.ArchivePath, Signature = signature ?? "" });

            using var log = logPath is null ? null : OpenLog(logPath);
            log?.WriteLine("Entry,ExtractedTo,Bytes,Result");

            long done = 0;
            var buffer = new byte[1 << 20];
            // A collection of 100,000 files asks for the same few thousand folders over and over.
            var made = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            void MakeFolder(string path)
            {
                if (made.Add(path)) Directory.CreateDirectory(path);
            }
            var links = new List<(string Path, string Target, string Entry)>();
            // A tar or a UAC collection comes from Unix, where '\' is an ordinary character in a
            // name (systemd escapes '-' as \x2d), not a folder separator as in a Windows zip.
            var unixNames = source.IsTar || UacCollection.IsCollection(source.Entries.Select(e => e.FullName));
            foreach (var item in plan)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var entry = item.Entry;

                if (item.Index is not null)
                {
                    log?.WriteLine(Csv(entry.FullName, "", entry.Length.ToString(), "sparse index, applied to " + item.Index));
                    continue;
                }

                // The folder that becomes the root itself, such as UAC's [root].
                if (item.Mapped is null && item.SkipReason is null) continue;

                if (item.Mapped is null)
                {
                    // Left out by design - said in the log and the summary, but not a fault.
                    log?.WriteLine(Csv(entry.FullName, "", entry.Length.ToString(), "not extracted: " + item.SkipReason));
                    Note(record, "not extracted: " + item.SkipReason);
                    continue;
                }

                var (target, renamed, unsafeReason) = TargetPath(root, item.Mapped, unixNames);
                if (unsafeReason is not null)
                {
                    Problem(record, log, entry, "", "not extracted: " + unsafeReason);
                    continue;
                }

                if (entry.IsDirectory)
                {
                    MakeFolder(target);
                    continue;
                }

                switch (entry.Kind)
                {
                    case SourceEntryKind.SymbolicLink:
                        // Not created: Windows needs a privilege to make one, and an absolute Linux
                        // target would point outside the evidence. Listed instead, for the modules
                        // that read link targets. Its folder is made: it existed on the source, and
                        // a folder holding only links (a *.wants) would otherwise vanish.
                        MakeFolder(Path.GetDirectoryName(target)!);
                        links.Add((Relative(root, target), entry.LinkTarget ?? "", entry.FullName));
                        log?.WriteLine(Csv(entry.FullName, target, "0",
                            $"symbolic link to {entry.LinkTarget ?? "an unreadable target"} - listed in {SymlinkList}, not created"));
                        continue;

                    case SourceEntryKind.HardLink:
                        // The same content as an entry already written; tar stores it once.
                        var first = item.LinkMapped is null ? null : TargetPath(root, item.LinkMapped, unixNames).Path;
                        if (string.IsNullOrEmpty(first) || !File.Exists(first))
                        {
                            Problem(record, log, entry, target, $"not extracted: hard link to {entry.LinkTarget}, which was not extracted");
                            continue;
                        }
                        if (File.Exists(target))
                        {
                            Problem(record, log, entry, target, "not extracted: another entry already wrote this path");
                            continue;
                        }
                        MakeFolder(Path.GetDirectoryName(target)!);
                        File.Copy(first, target);
                        var copied = new FileInfo(target).Length;
                        record.Files++;
                        record.Bytes += copied;
                        log?.WriteLine(Csv(entry.FullName, target, copied.ToString(),
                            $"extracted, hard link to {entry.LinkTarget} - content copied"));
                        continue;

                    case SourceEntryKind.Special:
                        log?.WriteLine(Csv(entry.FullName, "", "0", "not extracted: device, pipe or socket - no content"));
                        Note(record, "not extracted: devices, pipes and sockets hold no content");
                        continue;

                    case SourceEntryKind.Unsupported:
                        Problem(record, log, entry, target, "not extracted: an archive entry type this build cannot reproduce, such as a GNU sparse file");
                        continue;
                }

                if (File.Exists(target))
                {
                    // Two entries landing on one file - a duplicate, names differing only in case,
                    // or one file read through two Velociraptor accessors. The first is kept (the
                    // raw NTFS read, for Velociraptor); the second is reported, not overwritten.
                    Problem(record, log, entry, target, "not extracted: another entry already wrote this path");
                    continue;
                }

                MakeFolder(Path.GetDirectoryName(target)!);
                Action<int> report = bytes => progress?.Report((done += bytes, total));
                var expand = item.Sparse is not null && !item.Compact;
                var result = expand
                    ? await CopySparseEntryAsync(entry, target, item.Sparse!, buffer, cancellationToken, report)
                    : await CopyEntryAsync(entry, target, buffer, cancellationToken, report);

                if (result is not null)
                {
                    TryDelete(target);
                    Problem(record, log, entry, target, "removed: " + result);
                    continue;
                }

                if (entry.LastWriteUtc is { } written) File.SetLastWriteTimeUtc(target, written);

                var length = expand ? VelociraptorCollection.OriginalLength(item.Sparse!) : entry.Length;
                record.Files++;
                record.Bytes += length;

                var outcome = renamed ? "extracted, renamed - name not valid on Windows" : "extracted";
                if (expand) outcome += $", sparse file expanded to {length:N0} bytes";
                if (item.Sparse is not null && item.Compact)
                {
                    outcome += ", sparse holes not expanded - stored data only";
                    Note(record, $"{item.Mapped.Replace('/', '\\')} written as its {Size(entry.Length)} of data; its "
                                 + $"{Size(VelociraptorCollection.OriginalLength(item.Sparse))} sparse size was not expanded");
                }
                log?.WriteLine(Csv(entry.FullName, target, length.ToString(), outcome));
            }

            if (links.Count > 0)
            {
                var listPath = Path.Combine(root, SymlinkList);
                if (File.Exists(listPath))
                {
                    // Never overwrite evidence: a collected file of the same name stays as it was.
                    record.Problems.Add($"{SymlinkList} - the collection has a file of this name at its root, so its "
                                        + $"{links.Count} symbolic link(s) are listed only in the extraction log");
                }
                else
                {
                    await File.WriteAllLinesAsync(listPath,
                        links.Select(l => Csv(l.Path, l.Target, l.Entry)).Prepend("Path,Target,ArchiveEntry"),
                        new UTF8Encoding(false), cancellationToken);
                    Note(record, $"{links.Count} symbolic link(s) listed in {SymlinkList} rather than created");
                }
            }

            WriteMarker(markerPath, new Marker
            {
                Archive = record.ArchivePath, Signature = await Signature(), Completed = true,
                Files = record.Files, Bytes = record.Bytes, Problems = record.Problems, Notes = record.Notes
            });
            return record;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            record.Error = ex.Message;
            return record;
        }
        finally
        {
            // Recorded for the manifest even when extraction failed part-way, as it was before.
            if (hashing is not null && record.ArchiveSha256 is null)
            {
                try { record.ArchiveSha256 = await hashing; }
                catch (OperationCanceledException) { /* the run was stopped */ }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    record.Error ??= "could not read the zip to hash it: " + ex.Message;
                }
            }
            record.DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds;
        }
    }

    /// <summary>
    /// Identifies a source's content, so an extraction is reused only for the same source. A zip is
    /// its size, date and SHA-256; a folder, which has no single hash, is its file count, total
    /// size and latest modification time.
    /// </summary>
    private static async Task<string> SignatureAsync(string path, string? sha256, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(path))
        {
            var zip = new FileInfo(path);
            return $"zip|{zip.Length}|{zip.LastWriteTimeUtc.Ticks}|{sha256 ?? await HashAsync(path, cancellationToken)}";
        }
        return "folder|" + QuickSignature(path);
    }

    /// <summary>
    /// A cheap identity for a source, without hashing: enough for the run state to tell that a
    /// zip or folder was replaced since its work last finished.
    /// </summary>
    public static string QuickSignature(string path)
    {
        if (!Directory.Exists(path))
        {
            var zip = new FileInfo(path);
            return $"{zip.Length}|{zip.LastWriteTimeUtc.Ticks}";
        }

        long count = 0, bytes = 0, latest = 0;
        foreach (var info in new DirectoryInfo(path).EnumerateFiles("*", SearchOption.AllDirectories))
        {
            count++;
            bytes += info.Length;
            latest = Math.Max(latest, info.LastWriteTimeUtc.Ticks);
        }
        return $"{count}|{bytes}|{latest}";
    }

    /// <summary>
    /// Where an entry goes, refusing anything that would land outside the extraction folder. Names
    /// Windows cannot hold are made safe and flagged, so the change is on record. With
    /// <paramref name="unixNames"/>, '\' is part of a name rather than a separator.
    /// </summary>
    internal static (string Path, bool Renamed, string? UnsafeReason) TargetPath(
        string root, string entryName, bool unixNames = false)
    {
        var name = unixNames ? entryName : entryName.Replace('\\', '/');
        if (name.StartsWith('/') || (name.Length > 1 && name[1] == ':'))
            return ("", false, "absolute path in the zip");

        var parts = name.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return ("", false, "empty entry name");
        if (parts.Any(p => p is "." or ".."))
            return ("", false, "path climbs out of the extraction folder");

        var invalid = Path.GetInvalidFileNameChars();
        var renamed = false;
        for (var i = 0; i < parts.Length; i++)
        {
            var safe = string.Concat(parts[i].Select(c => invalid.Contains(c) ? '_' : c));

            // Linux allows names Windows silently alters or refuses: a trailing dot or space is
            // stripped, and a device name such as 'aux' or 'nul.txt' opens the device, not a file.
            if (safe.EndsWith('.') || safe.EndsWith(' ')) safe = safe[..^1] + "_";
            if (IsDeviceName(safe)) safe = "_" + safe;

            if (safe != parts[i]) { parts[i] = safe; renamed = true; }
        }

        var full = Path.GetFullPath(Path.Combine([root, .. parts]));
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return ("", false, "path climbs out of the extraction folder");

        return (full, renamed, null);
    }

    private static bool IsDeviceName(string name)
    {
        var stem = name.Split('.')[0].TrimEnd(' ');
        if (stem.Length == 3)
            return stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
                   || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase);
        return stem.Length == 4 && char.IsAsciiDigit(stem[3]) && stem[3] != '0'
               && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>A path below the extraction root, '/'-separated as the source system wrote it.</summary>
    private static string Relative(string root, string full) => full[(root.Length + 1)..].Replace('\\', '/');

    /// <summary>Copies one entry, returning null when it matched its recorded length and CRC, else why not.</summary>
    private static async Task<string?> CopyEntryAsync(
        SourceEntry entry, string target, byte[] buffer, CancellationToken cancellationToken,
        Action<int> reportBytes)
    {
        var crc = new System.IO.Hashing.Crc32();
        long written = 0;
        try
        {
            await using var input = entry.Open();
            await using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write,
                                                    FileShare.None, 1 << 16, useAsync: true);
            int read;
            while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
            {
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                crc.Append(buffer.AsSpan(0, read));
                written += read;
                reportBytes(read);
            }
        }
        catch (OperationCanceledException)
        {
            TryDelete(target);
            throw;
        }
        catch (InvalidDataException ex)
        {
            return "compressed data is corrupt (" + ex.Message + ")";
        }

        if (written != entry.Length)
            return $"{written:N0} of {entry.Length:N0} bytes - entry truncated?";
        if (entry.Crc32 is { } expected && crc.GetCurrentHashAsUInt32() != expected)
            return "CRC-32 does not match the zip - entry corrupt";
        return null;
    }

    /// <summary>One source entry and what to do with it.</summary>
    private sealed record PlannedEntry(
        SourceEntry Entry, string? Mapped, string? SkipReason,
        IReadOnlyList<VelociraptorCollection.SparseRange>? Sparse, bool Compact, string? Index)
    {
        /// <summary>For a hard link, where the entry it repeats was written, mapped like any other.</summary>
        public string? LinkMapped { get; init; }
    }

    /// <summary>
    /// Decides where each entry goes. A plain zip extracts as it is. A Velociraptor collection is
    /// converted: paths mapped onto drive-letter folders, sparse indexes paired with their data,
    /// and the collector's own completeness check recorded.
    /// </summary>
    private static List<PlannedEntry> PlanEntries(CollectionSource source, ExtractionRecord record)
    {
        var entries = source.Entries;
        if (source.Damage is not null) record.Problems.Add(source.Damage);

        if (UacCollection.IsCollection(entries.Select(e => e.FullName)))
        {
            var uacErrors = UacCollection.LogErrors(source.OpenByName);
            if (uacErrors > 0)
                Note(record, $"the collector logged {uacErrors} error(s) - see {UacCollection.MetadataFolder}\\uac.log");
            return entries.Select(e => new PlannedEntry(e, UacCollection.MapEntry(e.FullName), null, null, false, null)
            {
                LinkMapped = e.Kind == SourceEntryKind.HardLink && e.LinkTarget is { } link ? UacCollection.MapEntry(link) : null
            }).ToList();
        }

        if (!VelociraptorCollection.IsCollection(entries.Select(e => e.FullName)))
            return entries.Select(e => new PlannedEntry(e, e.FullName, null, null, false, null) { LinkMapped = e.LinkTarget })
                          .ToList();

        var incomplete = VelociraptorCollection.IncompleteReason(source.OpenByName);
        if (incomplete is not null) record.Problems.Add(IncompletePrefix + incomplete);
        var errors = VelociraptorCollection.LogErrors(source.OpenByName);
        if (errors > 0)
            Note(record, $"the collector logged {errors} error(s) - see {VelociraptorCollection.MetadataFolder}\\log.json");

        var names = entries.Select(e => e.FullName).ToHashSet(StringComparer.Ordinal);
        var sparse = new Dictionary<string, IReadOnlyList<VelociraptorCollection.SparseRange>>(StringComparer.Ordinal);
        var indexOf = new Dictionary<SourceEntry, string>();
        foreach (var entry in entries.Where(e => e.FullName.EndsWith(".idx", StringComparison.Ordinal)))
        {
            var data = entry.FullName[..^4];
            if (!names.Contains(data) || !data.StartsWith("uploads/", StringComparison.OrdinalIgnoreCase)) continue;
            using var stream = entry.Open();
            var ranges = VelociraptorCollection.ReadIndex(stream);
            if (ranges is null) continue;
            sparse[data] = ranges;
            indexOf[entry] = data;
        }

        // Raw NTFS reads first, so where two accessors uploaded the same file the raw copy, which
        // gets past locks, is the one kept.
        return entries
            .OrderBy(e => e.FullName.StartsWith("uploads/ntfs/", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .Select(e =>
            {
                if (indexOf.TryGetValue(e, out var data)) return new PlannedEntry(e, null, null, null, false, data);
                var mapped = VelociraptorCollection.MapEntry(e.FullName, out var skip);
                sparse.TryGetValue(e.FullName, out var ranges);
                var compact = mapped is not null && VelociraptorCollection.KeepCompact(mapped);
                return new PlannedEntry(e, mapped?.Replace('\\', '/'), skip, ranges, compact, null);
            })
            .ToList();
    }

    /// <summary>
    /// Writes a sparse file back at its original size: each stored range at its original offset,
    /// zeros between. The CRC is over the stored bytes, as the zip recorded them.
    /// </summary>
    private static async Task<string?> CopySparseEntryAsync(
        SourceEntry entry, string target, IReadOnlyList<VelociraptorCollection.SparseRange> ranges,
        byte[] buffer, CancellationToken cancellationToken, Action<int> reportBytes)
    {
        var data = ranges.Where(r => r.FileLength > 0).OrderBy(r => r.FileOffset).ToList();
        if (data.Sum(r => r.FileLength) != entry.Length)
            return $"its sparse index describes {data.Sum(r => r.FileLength):N0} bytes of data but the source holds {entry.Length:N0}";

        var crc = new System.IO.Hashing.Crc32();
        long read = 0;
        try
        {
            await using var input = entry.Open();
            await using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write,
                                                    FileShare.None, 1 << 16, useAsync: true);
            output.SetLength(VelociraptorCollection.OriginalLength(ranges));

            foreach (var range in data)
            {
                output.Position = range.OriginalOffset;
                var remaining = range.FileLength;
                while (remaining > 0)
                {
                    var n = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), cancellationToken);
                    if (n == 0) return $"{read:N0} of {entry.Length:N0} bytes - entry truncated?";
                    await output.WriteAsync(buffer.AsMemory(0, n), cancellationToken);
                    crc.Append(buffer.AsSpan(0, n));
                    read += n;
                    remaining -= n;
                    reportBytes(n);
                }
            }
        }
        catch (OperationCanceledException)
        {
            TryDelete(target);
            throw;
        }
        catch (InvalidDataException ex)
        {
            return "compressed data is corrupt (" + ex.Message + ")";
        }

        return entry.Crc32 is { } expected && crc.GetCurrentHashAsUInt32() != expected
            ? "CRC-32 does not match the zip - entry corrupt"
            : null;
    }

    /// <summary>Records something the analyst should know that is not a fault, once per distinct message.</summary>
    private static void Note(ExtractionRecord record, string note)
    {
        // Skips by design arrive once per file; one line with a count says the same thing.
        var key = note.StartsWith("not extracted: ", StringComparison.Ordinal) ? note : null;
        if (key is null) { record.Notes.Add(note); return; }

        var existing = record.Notes.FindIndex(n => n.EndsWith(key, StringComparison.Ordinal));
        if (existing < 0) { record.Notes.Add("1 file " + key); return; }

        var count = int.Parse(record.Notes[existing].Split(' ')[0]) + 1;
        record.Notes[existing] = $"{count} files {key}";
    }

    /// <summary>True when the folder holds an extraction ArtefactForge made, complete or not.</summary>
    public static bool IsOurs(string extractedTo) => File.Exists(Path.Combine(extractedTo, MarkerName));

    /// <summary>The name an archive's extraction folder takes: its file name without the extension, both parts of ".tar.gz".</summary>
    public static string ArchiveStem(string path) => CollectionSource.Stem(path);

    /// <summary>
    /// Deletes an extracted collection. Returns null on success, else why it stayed. The folder
    /// the extractions share is left alone: other zips may be extracting into it.
    /// </summary>
    public static string? Delete(string extractedTo)
    {
        try
        {
            if (Directory.Exists(extractedTo)) Directory.Delete(extractedTo, recursive: true);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ex.Message;
        }
    }

    /// <summary>Removes the folder the extractions share once it is empty, and only then.</summary>
    public static void RemoveIfEmpty(string extractionRoot)
    {
        try
        {
            if (Directory.Exists(extractionRoot) && !Directory.EnumerateFileSystemEntries(extractionRoot).Any())
                Directory.Delete(extractionRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // An empty folder left behind is untidy, not harmful; each zip's cleanup is reported.
        }
    }

    private static void Problem(ExtractionRecord record, StreamWriter? log, SourceEntry entry, string target, string reason)
    {
        record.Problems.Add(entry.FullName + " - " + reason);
        log?.WriteLine(Csv(entry.FullName, target, entry.Length.ToString(), reason));
    }

    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, useAsync: true);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
    }

    private static Marker? ReadMarker(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<Marker>(File.ReadAllText(path)) : null; }
        catch (JsonException) { return new Marker(); }   // ours, but unreadable: treat as partial
    }

    private static void WriteMarker(string path, Marker marker) =>
        File.WriteAllText(path, JsonSerializer.Serialize(marker, JsonOptions));

    private static StreamWriter OpenLog(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        return new StreamWriter(path, append: false, new UTF8Encoding(false));
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* reported by the caller */ }
    }

    private static string Csv(params string[] fields) =>
        string.Join(",", fields.Select(f => f.Contains(',') || f.Contains('"') ? "\"" + f.Replace("\"", "\"\"") + "\"" : f));

    internal static string Size(long bytes) =>
        bytes >= 1L << 30 ? $"{bytes / (double)(1L << 30):F1} GB" : $"{bytes / (double)(1L << 20):F0} MB";
}
