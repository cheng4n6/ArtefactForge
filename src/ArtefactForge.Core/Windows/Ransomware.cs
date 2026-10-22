using System.Diagnostics;
using System.Security.Cryptography;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// Ransomware on Windows hosts, from MFTECmd's $MFT and USN journal output: the extension added
/// to encrypted files, the ransom note, and when encryption started and finished.
///
///   &lt;collection&gt;\Ransomware\RansomwareSummary.csv   the host's result (columns: RansomwareFinding)
///   &lt;collection&gt;\Ransomware\RansomwareEvidence.csv  the renames and files behind it
///   &lt;collection&gt;\Ransomware\Note\                   one copy of the note, when the collection holds it
///   &lt;case&gt;\Ransomware.csv                           one row per host, with where hosts differ
///   &lt;case&gt;\Ransomware-Overrides.csv                 the analyst's: confirms or overrides a host's
///                                                    extension or note. Read only, never written
///                                                    over or deleted.
///
/// A value in the overrides is also swept for on every other host, so a host whose own evidence
/// is too thin to call (a few renames before the collection) still shows it.
///
/// Derived files only: a host is rebuilt when its MFTECmd output is newer than its result, or
/// when what the overrides say about it changes (its own row, or a new value to sweep for).
/// </summary>
public static class Ransomware
{
    public const string Folder = "Ransomware";
    public const string SummaryFileName = "RansomwareSummary.csv";
    public const string EvidenceFileName = "RansomwareEvidence.csv";
    public const string NoteFolder = "Note";
    public const string FileName = "Ransomware.csv";
    public const string OverridesFileName = "Ransomware-Overrides.csv";
    public const string ModuleName = "Ransomware";

    public static readonly string[] OverrideColumns = ["Collection", "Extension", "NoteName", "Comment"];

    private const string NoInput =
        "no MFTECmd output (FileSystem\\MFTECmd_MFT.csv or FileSystem\\MFTECmd_USNJournal.csv) - run MFTECmd_MFT and MFTECmd_USNJournal";

    public static string PathFor(string caseDirectory) => Path.Combine(caseDirectory, FileName);

    public static string OverridesPathFor(string caseDirectory) => Path.Combine(caseDirectory, OverridesFileName);

    /// <summary>
    /// Builds every host that is missing or out of date, then the case's Ransomware.csv. Returns a
    /// result per host built. Overrides that cannot be read stop it: building without them would
    /// quietly drop what the analyst settled.
    /// </summary>
    public static List<WorkResult> Build(string caseDirectory, CancellationToken cancellationToken = default)
    {
        var results = new List<WorkResult>();
        if (!Directory.Exists(caseDirectory)) return results;

        List<RansomwareOverride> overrides;
        try { overrides = ReadOverrides(caseDirectory); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            results.Add(CaseResult(caseDirectory, WorkStatus.Failed,
                $"could not read {OverridesFileName}, so nothing was rebuilt: {ex.Message}"));
            return results;
        }

        foreach (var collectionDir in CollectionDirectories(caseDirectory))
        {
            if (cancellationToken.IsCancellationRequested) return results;
            try
            {
                var hints = HintsFor(overrides, Path.GetFileName(collectionDir), HostName(collectionDir));
                if (BuildCollection(collectionDir, hints, cancellationToken) is { } result) results.Add(result);
            }
            catch (OperationCanceledException)
            {
                return results;
            }
        }

        try { BuildCase(caseDirectory); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            results.Add(CaseResult(caseDirectory, WorkStatus.Failed, $"could not write the case {FileName}: {ex.Message}"));
        }
        return results;
    }

    /// <summary>
    /// One host. Null when it has no MFTECmd output, or nothing changed since it was built, so
    /// hosts with nothing new add nothing to the run's results.
    /// </summary>
    public static WorkResult? BuildCollection(string collectionDir, RansomwareHints hints, CancellationToken cancellationToken = default)
    {
        var name = Path.GetFileName(collectionDir);
        var outDir = Path.Combine(collectionDir, Folder);
        var summary = Path.Combine(outDir, SummaryFileName);

        var mft = Newest(collectionDir, "MFTECmd_MFT*.csv");
        var usn = Newest(collectionDir, "MFTECmd_USNJournal*.csv");
        if (mft is null && usn is null) return null;
        var parameters = hints.Key();
        if (UpToDate(summary, parameters, [mft, usn])) return null;

        var stopwatch = Stopwatch.StartNew();
        var started = DateTimeOffset.Now;
        WorkResult Result(WorkStatus status, string reason) => new()
        {
            Collection = name, Module = ModuleName, Category = Folder, Status = status, Reason = reason,
            Destination = outDir, Started = started, DurationSeconds = stopwatch.Elapsed.TotalSeconds
        };

        var host = HostName(collectionDir);
        try
        {
            var detection = RansomwareDetector.Detect(name, mft, usn, hints, cancellationToken);
            Directory.CreateDirectory(outDir);
            var finding = SaveNote(collectionDir, detection) with { Host = host };
            RansomwareEvidence.Write(Path.Combine(outDir, EvidenceFileName), detection.Evidence);
            RansomwareFinding.Write(summary, [finding], parameters);
            return Result(WorkStatus.Completed, finding.IsFound ? "ransomware: " + finding.Describe() : "no encrypted files or ransom note found");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            var reason = "could not check for ransomware: " + ex.Message;
            try
            {
                // Saved with no parameters, so the next run tries again.
                Directory.CreateDirectory(outDir);
                RansomwareFinding.Write(summary,
                    [new RansomwareFinding { Collection = name, Host = host, Status = RansomwareFinding.FailedStatus, Detail = reason }], "");
            }
            catch (Exception inner) when (inner is IOException or UnauthorizedAccessException)
            {
                reason += $"; the failure could not be saved either: {inner.Message}";
            }
            return Result(WorkStatus.Failed, reason);
        }
    }

    /// <summary>The case's Ransomware.csv from every host's summary. Not written for a case with no host checked.</summary>
    public static void BuildCase(string caseDirectory)
    {
        var rows = new List<RansomwareFinding>();
        foreach (var collectionDir in CollectionDirectories(caseDirectory))
        {
            var name = Path.GetFileName(collectionDir);
            var summary = Path.Combine(collectionDir, Folder, SummaryFileName);
            if (!File.Exists(summary))
            {
                rows.Add(new RansomwareFinding
                {
                    Collection = name, Host = HostName(collectionDir), Status = RansomwareFinding.NotChecked, Detail = NoInput
                });
                continue;
            }
            var read = RansomwareFinding.Read(summary);
            rows.Add(read.Count > 0
                ? read[0] with { Collection = name }
                : new RansomwareFinding { Collection = name, Status = RansomwareFinding.FailedStatus, Detail = $"{SummaryFileName} has no row" });
        }

        if (rows.All(r => r.Status == RansomwareFinding.NotChecked)) return;
        RansomwareFinding.Write(PathFor(caseDirectory), CompareHosts(rows));
    }

    /// <summary>The case's rows, or none when it has not been built.</summary>
    public static List<RansomwareFinding> Load(string caseDirectory)
    {
        var path = PathFor(caseDirectory);
        return File.Exists(path) ? RansomwareFinding.Read(path) : [];
    }

    /// <summary>Marks each host that differs from what most hosts with a finding show.</summary>
    internal static List<RansomwareFinding> CompareHosts(List<RansomwareFinding> rows)
    {
        var found = rows.Where(r => r.IsFound).ToList();
        if (found.Count == 0) return rows;

        string? Common(Func<RansomwareFinding, string> field)
        {
            var values = found.Select(field).Where(v => v.Length > 0)
                              .GroupBy(v => v, StringComparer.OrdinalIgnoreCase)
                              .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal)
                              .ToList();
            return values.Count == 0 ? null : values[0].Key;
        }
        int Hosts(Func<RansomwareFinding, string> field, string value) =>
            found.Count(r => field(r).Equals(value, StringComparison.OrdinalIgnoreCase));

        var extension = Common(r => r.Extension);
        var note = Common(r => r.NoteName);
        var hash = Common(r => r.NoteSha256);

        return rows.Select(r =>
        {
            var differences = new List<string>();
            if (r.Status == RansomwareFinding.NoneFound)
                differences.Add($"nothing found here, unlike {found.Count} other host{(found.Count == 1 ? "" : "s")}");
            if (r.IsFound)
            {
                void Compare(string what, string value, string? common, Func<RansomwareFinding, string> field)
                {
                    if (common is null || value.Equals(common, StringComparison.OrdinalIgnoreCase)) return;
                    var others = Hosts(field, common);
                    differences.Add(value.Length == 0
                        ? $"no {what} found, unlike {others} host{(others == 1 ? "" : "s")} ({common})"
                        : $"{what} {value} differs from {common} on {others} host{(others == 1 ? "" : "s")}");
                }
                Compare("extension", r.Extension, extension, f => f.Extension);
                Compare("note", r.NoteName, note, f => f.NoteName);
                // Only between saved copies: a host whose note could not be copied has no hash to compare.
                if (r.NoteSha256.Length > 0) Compare("note hash", r.NoteSha256, hash, f => f.NoteSha256);
            }
            return differences.Count == 0 ? r : r with { Differences = string.Join("; ", differences) };
        }).ToList();
    }

    // --- overrides ------------------------------------------------------------------------------

    /// <summary>One row of Ransomware-Overrides.csv. Null: not settled; empty: settled as none.</summary>
    public sealed record RansomwareOverride(string Collection, string? Extension, string? NoteName);

    /// <summary>
    /// The analyst's overrides. A blank cell settles nothing; "none" or "-" says there is none. A
    /// row with no collection, or "*", only adds its values to the sweep.
    /// </summary>
    public static List<RansomwareOverride> ReadOverrides(string caseDirectory)
    {
        var path = OverridesPathFor(caseDirectory);
        var rows = new List<RansomwareOverride>();
        if (!File.Exists(path)) return rows;

        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return rows;
        var index = header.Select((n, i) => (n, i))
            .GroupBy(p => p.n.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().i, StringComparer.OrdinalIgnoreCase);
        if (!index.ContainsKey("Collection") || (!index.ContainsKey("Extension") && !index.ContainsKey("NoteName")))
            throw new InvalidDataException(
                $"{OverridesFileName} needs the columns {string.Join(", ", OverrideColumns)} on its first line");

        while (reader.ReadRecord() is { } fields)
        {
            string Cell(string n) => index.TryGetValue(n, out var i) && i < fields.Count ? fields[i].Trim() : "";
            string? Value(string text) => text.Length == 0 ? null
                : text.Equals("none", StringComparison.OrdinalIgnoreCase) || text == "-" ? "" : text;

            var extension = Value(Cell("Extension"));
            var note = Value(Cell("NoteName"));
            if (extension is null && note is null) continue;
            rows.Add(new RansomwareOverride(Cell("Collection"),
                                            extension is null ? null : RansomwareDetector.NormaliseExtension(extension), note));
        }
        return rows;
    }

    /// <summary>What the overrides say about one host: its own row, and every value to sweep for.</summary>
    public static RansomwareHints HintsFor(IReadOnlyList<RansomwareOverride> overrides, string collection, string host)
    {
        bool Mine(RansomwareOverride o) =>
            o.Collection.Equals(collection, StringComparison.OrdinalIgnoreCase)
            || (host.Length > 0 && o.Collection.Equals(host, StringComparison.OrdinalIgnoreCase));

        // A later row for the same host wins, as the analyst reads the file top to bottom.
        var own = overrides.Where(Mine).ToList();
        return new RansomwareHints(
            own.LastOrDefault(o => o.Extension is not null)?.Extension,
            own.LastOrDefault(o => o.NoteName is not null)?.NoteName,
            overrides.Select(o => o.Extension).Where(e => e is { Length: > 0 }).Select(e => e!)
                     .ToHashSet(StringComparer.OrdinalIgnoreCase),
            overrides.Select(o => o.NoteName).Where(n => n is { Length: > 0 }).Select(n => n!)
                     .ToHashSet(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Creates Ransomware-Overrides.csv with only its header when the case has none, for the
    /// analyst to fill in. An existing file is left exactly as it is.
    /// </summary>
    public static string EnsureOverridesFile(string caseDirectory)
    {
        var path = OverridesPathFor(caseDirectory);
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            Linux.CsvFile.WriteRow(writer, OverrideColumns);
        }
        catch (IOException) when (File.Exists(path))
        {
            // Already there: the analyst's file, not touched.
        }
        return path;
    }

    // --- the note's copy --------------------------------------------------------------------------

    /// <summary>
    /// Saves one copy of the note in the host's Ransomware\Note folder, from the collection or from
    /// the MFT when the note is resident, and adds its hash. A note that is not .txt is saved with
    /// .txt added, so opening it from the case cannot run it (a .hta note is a program).
    /// </summary>
    private static RansomwareFinding SaveNote(string collectionDir, RansomwareDetection detection)
    {
        var finding = detection.Finding;
        var noteDir = Path.Combine(collectionDir, Folder, NoteFolder);
        if (Directory.Exists(noteDir)) Directory.Delete(noteDir, recursive: true);   // an earlier build's copy
        if (finding.NoteName.Length == 0 || finding.NoteSize is not { } size) return finding;

        foreach (var (path, resident) in detection.NoteSources)
        {
            byte[]? content = null;
            try
            {
                if (path.Length > 0 && File.Exists(path) && new FileInfo(path).Length == size)
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    content = new byte[size];
                    stream.ReadExactly(content);
                }
                else if (resident.Length > 0)
                {
                    var bytes = Convert.FromBase64String(resident);
                    if (bytes.Length == size) content = bytes;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
            {
                continue;   // another copy may read
            }
            if (content is null) continue;

            Directory.CreateDirectory(noteDir);
            var name = finding.NoteName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ? finding.NoteName : finding.NoteName + ".txt";
            var copy = Path.Combine(noteDir, name);
            File.WriteAllBytes(copy, content);
            var caseDir = Path.GetDirectoryName(collectionDir)!;
            return finding with
            {
                NoteSha256 = Convert.ToHexString(SHA256.HashData(content)),
                NoteCopy = Path.GetRelativePath(caseDir, copy)
            };
        }

        var first = detection.Evidence.FirstOrDefault(e => e.Kind == RansomwareEvidence.RansomNote);
        var pull = first is null ? "" : $": pull a copy from {Path.Combine(first.Path, first.Name)}";
        var line = $"the note is not in the collection{pull} (every copy is listed in {EvidenceFileName})";
        return finding with { Detail = finding.Detail.Length == 0 ? line : finding.Detail + "; " + line };
    }

    // --- helpers --------------------------------------------------------------------------------

    private static IEnumerable<string> CollectionDirectories(string caseDirectory) =>
        Directory.EnumerateDirectories(caseDirectory)
                 .Where(d => !Path.GetFileName(d).StartsWith('_'))   // _Logs, _Extracted
                 .Order(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The newest MFTECmd file of this kind: a module re-run writes beside the old file
    /// (MFTECmd_MFT_2.csv), and the newest is complete.
    /// </summary>
    private static string? Newest(string collectionDir, string pattern)
    {
        var dir = Path.Combine(collectionDir, "FileSystem");
        if (!Directory.Exists(dir)) return null;
        return Directory.EnumerateFiles(dir, pattern)
                        .OrderByDescending(File.GetLastWriteTimeUtc)
                        .FirstOrDefault();
    }

    private static bool UpToDate(string summary, string parameters, IEnumerable<string?> inputs)
    {
        if (!File.Exists(summary)) return false;
        var built = File.GetLastWriteTimeUtc(summary);
        if (inputs.OfType<string>().Any(i => File.GetLastWriteTimeUtc(i) > built)) return false;
        try
        {
            var read = RansomwareFinding.ReadWithParameters(summary);
            return read.Count == 1 && read[0].Parameters == parameters;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            return false;
        }
    }

    private static string HostName(string collectionDir)
    {
        var summary = Path.Combine(collectionDir, "SystemInfo", "SystemInfo.csv");
        try
        {
            return File.Exists(summary) && IpHistory.ReadFacts(summary).GetValueOrDefault("Hostname", "") is { Length: > 0 } name
                ? name
                : Path.GetFileName(collectionDir);
        }
        catch (IOException)
        {
            return Path.GetFileName(collectionDir);
        }
    }

    private static WorkResult CaseResult(string caseDirectory, WorkStatus status, string reason) => new()
    {
        Collection = Path.GetFileName(caseDirectory),
        Module = ModuleName,
        Category = Folder,
        Status = status,
        Reason = reason,
        Destination = caseDirectory,
        Started = DateTimeOffset.Now
    };
}
