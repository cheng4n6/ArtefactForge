using System.Text;
using System.Text.RegularExpressions;
using ArtefactForge.Lake.Contract;

namespace ArtefactForge.Lake;

/// <summary>A host folder and the files the lake found in it.</summary>
public sealed record DiscoveredHost
{
    public required string Name { get; init; }
    public required string Folder { get; init; }
    /// <summary>What the folder's outputs.json says about the host; null without one.</summary>
    public OutputsHost? Info { get; init; }
    public string? Producer { get; init; }
    /// <summary>True when the sources came from outputs.json rather than a walk of the folder.</summary>
    public bool FromManifest { get; init; }
    /// <summary>Why outputs.json could not be used, when it exists but is unreadable.</summary>
    public string? ManifestProblem { get; init; }
    public List<DiscoveredSource> Sources { get; } = [];
}

/// <summary>How a discovered file is to be treated.</summary>
public enum SourcePlan
{
    /// <summary>Loaded into its kind's raw table and mapped into the timeline.</summary>
    Mapped,
    /// <summary>Loaded into an unmapped.&lt;parser&gt; raw table only.</summary>
    Unmapped,
    /// <summary>A known kind by name or parser whose header does not fit: loaded raw only, and reported.</summary>
    HeaderMismatch,
    /// <summary>Not loaded: <see cref="DiscoveredSource.Reason"/> says why.</summary>
    Skip,
    /// <summary>Not loaded because something is wrong with it: listed but missing, unreadable.</summary>
    Fail
}

/// <summary>One file and the decision on how to load it.</summary>
public sealed record DiscoveredSource
{
    public required string Host { get; init; }
    /// <summary>Relative to the host folder, with '/' separators.</summary>
    public required string Path { get; init; }
    public required string FullPath { get; init; }
    public string? Parser { get; set; }
    public string ParserVersion { get; init; } = "unknown";
    /// <summary>The status outputs.json gave the file; null without one.</summary>
    public string? OutputStatus { get; init; }
    public SourcePlan Plan { get; set; }
    /// <summary>The kind it is loaded as: a mapped kind, or unmapped.&lt;parser&gt;.</summary>
    public string? Kind { get; set; }
    public KindDefinition? Definition { get; set; }
    public string? Reason { get; set; }
    public IReadOnlyList<string> Header { get; set; } = [];
    public long? Size { get; init; }
    public DateTime? ModifiedUtc { get; init; }
}

/// <summary>
/// Finds the hosts of a case and the parser output in each: from &lt;Host&gt;\outputs.json when a
/// host has one, otherwise by walking the folder and matching file names and headers (raw KAPE or
/// EZ Tools output).
/// </summary>
public static partial class SourceDiscovery
{
    private static readonly HashSet<string> LoadableStatuses =
        new([OutputStatus.Completed, OutputStatus.CheckLog], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The hosts under <paramref name="caseDirectory"/>: every subfolder whose name does not start
    /// with '_', as ArtefactForge counts them. With <paramref name="singleHost"/> the whole folder
    /// is one host of that name.
    /// </summary>
    public static IReadOnlyList<DiscoveredHost> Discover(string caseDirectory, string? singleHost = null)
    {
        if (singleHost is not null) return [DiscoverHost(singleHost, caseDirectory)];
        return Directory.EnumerateDirectories(caseDirectory)
            .Where(d => !System.IO.Path.GetFileName(d).StartsWith('_'))
            .Order(StringComparer.OrdinalIgnoreCase)
            .Select(d => DiscoverHost(System.IO.Path.GetFileName(d), d))
            .ToList();
    }

    public static DiscoveredHost DiscoverHost(string name, string folder)
    {
        var manifestPath = OutputsManifestFile.PathIn(folder);
        OutputsManifest? manifest = null;
        string? problem = null;
        try { manifest = OutputsManifestFile.Read(manifestPath); }
        catch (Exception ex) when (ex is InvalidDataException or UnsupportedFormatVersionException
                                       or IOException or UnauthorizedAccessException)
        {
            problem = ex.Message;
        }

        if (manifest is null)
        {
            // An unreadable outputs.json is reported and the folder is walked instead, so the
            // host is not lost; the problem stays on the host so the build is flagged for review.
            var walked = new DiscoveredHost { Name = name, Folder = folder, ManifestProblem = problem };
            foreach (var file in WalkCsvFiles(folder))
                walked.Sources.Add(FromFile(name, folder, file));
            return walked;
        }

        var host = new DiscoveredHost
        {
            Name = name,
            Folder = folder,
            Info = manifest.Host,
            Producer = string.Join(' ', new[] { manifest.Producer.Name, manifest.Producer.Build ?? manifest.Producer.Version }
                .Where(s => !string.IsNullOrEmpty(s))),
            FromManifest = true
        };
        foreach (var entry in manifest.Outputs)
            host.Sources.Add(FromManifestEntry(name, folder, entry));
        return host;
    }

    private static IEnumerable<string> WalkCsvFiles(string folder)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
        return Directory.EnumerateFiles(folder, "*.csv", options)
            .Where(f => OutputsManifestFile.IsListable(OutputsManifestFile.RelativePath(folder, f)))
            .Where(f => !IsInLakeFolder(folder, f))
            .Order(StringComparer.OrdinalIgnoreCase);
    }

    // With --host the case folder is the host, so its own _Lake folder must not be read back in.
    private static bool IsInLakeFolder(string folder, string file) =>
        OutputsManifestFile.RelativePath(folder, file)
            .StartsWith(LakeNames.LakeFolder + "/", StringComparison.OrdinalIgnoreCase);

    private static DiscoveredSource FromManifestEntry(string host, string folder, OutputEntry entry)
    {
        var path = OutputsManifestFile.NormalisePath(entry.Path);
        var full = System.IO.Path.Combine([folder, .. path.Split('/')]);
        var info = new FileInfo(full);
        var source = new DiscoveredSource
        {
            Host = host,
            Path = path,
            FullPath = full,
            Parser = entry.Parser,
            ParserVersion = string.IsNullOrWhiteSpace(entry.ParserVersion) ? "unknown" : entry.ParserVersion,
            OutputStatus = entry.Status,
            Size = info.Exists ? info.Length : null,
            ModifiedUtc = info.Exists ? info.LastWriteTimeUtc : null
        };

        if (!OutputsManifestFile.IsListable(path))
            return Decide(source, SourcePlan.Fail, $"outputs.json lists a path outside the host folder: {entry.Path}");
        if (!LoadableStatuses.Contains(entry.Status))
            return Decide(source, SourcePlan.Skip, $"outputs.json gives it status '{entry.Status}'; only completed and checklog are loaded");
        if (!string.Equals(System.IO.Path.GetExtension(path), ".csv", StringComparison.OrdinalIgnoreCase))
            return Decide(source, SourcePlan.Skip, "not a CSV file");
        if (!info.Exists)
            return Decide(source, SourcePlan.Fail, "listed in outputs.json but not found in the host folder");

        var name = StripName(entry.ToolFileName ?? System.IO.Path.GetFileName(path), entry.User);
        var candidates = KindRegistry.All
            .Where(k => string.Equals(k.Parser, entry.Parser, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return Classify(source, name, candidates, byParser: true);
    }

    private static DiscoveredSource FromFile(string host, string folder, string file)
    {
        var path = OutputsManifestFile.RelativePath(folder, file);
        var info = new FileInfo(file);
        var name = StripName(info.Name, UserFolder(path));
        var source = new DiscoveredSource
        {
            Host = host,
            Path = path,
            FullPath = file,
            Parser = ParserFromName(name),
            Size = info.Length,
            ModifiedUtc = info.LastWriteTimeUtc
        };
        return Classify(source, name, KindRegistry.All, byParser: false);
    }

    /// <summary>
    /// Picks the kind. A kind is proposed by its file name (and, with outputs.json, its parser) and
    /// only taken when the header fits. A name that proposes a kind whose header does not fit is a
    /// mismatch, reported and loaded raw; it is never mapped on a guess. Without a name match, a
    /// header that fits exactly one kind decides (EZ Tools output saved under another name).
    /// </summary>
    private static DiscoveredSource Classify(DiscoveredSource source, string name,
        IReadOnlyList<KindDefinition> candidates, bool byParser)
    {
        if (source.Size == 0) return Decide(source, SourcePlan.Skip, "empty file (0 bytes)");
        try { source.Header = ReadHeader(source.FullPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Decide(source, SourcePlan.Fail, $"could not read its header: {ex.Message}");
        }
        if (source.Header.Count == 0) return Decide(source, SourcePlan.Skip, "no header line");

        var named = candidates.Where(k => k.NameMatches(name)).ToList();
        var fitting = named.FirstOrDefault(k => k.HeaderFits(source.Header));
        if (fitting is not null) return Map(source, fitting, null);

        if (named.Count > 0)
        {
            var expected = named[0];
            var missing = expected.MissingColumns(source.Header);
            var detail = missing.Count > 0
                ? "missing " + string.Join(", ", missing)
                : $"{source.Header.Count} columns where {expected.RequiredColumns.Count} were expected";
            source.Parser ??= expected.Parser;
            return Unmapped(source, SourcePlan.HeaderMismatch,
                $"named like {expected.Kind} but its header does not fit ({detail}); loaded raw, not mapped");
        }

        // No name match. With outputs.json the parser narrows the field; without, every kind.
        var byHeader = candidates.Where(k => k.HeaderFits(source.Header)).ToList();
        if (byHeader.Count == 1)
            return Map(source, byHeader[0], byParser ? null : $"recognised as {byHeader[0].Kind} by its header");
        if (byHeader.Count > 1)
        {
            // The most specific signature wins (PECmd's output also has an ExecutableName column).
            var best = byHeader.OrderByDescending(k => k.RequiredColumns.Count).ToList();
            if (best[0].RequiredColumns.Count > best[1].RequiredColumns.Count)
                return Map(source, best[0], byParser ? null : $"recognised as {best[0].Kind} by its header");
        }
        return Unmapped(source, SourcePlan.Unmapped, null);
    }

    private static DiscoveredSource Map(DiscoveredSource source, KindDefinition kind, string? note)
    {
        source.Plan = SourcePlan.Mapped;
        source.Kind = kind.Kind;
        source.Definition = kind;
        source.Reason = note;
        source.Parser ??= kind.Parser;
        return source;
    }

    private static DiscoveredSource Unmapped(DiscoveredSource source, SourcePlan plan, string? reason)
    {
        source.Plan = plan;
        source.Kind = LakeNames.Unmapped(source.Parser ?? "unknown");
        source.Reason = reason;
        return source;
    }

    private static DiscoveredSource Decide(DiscoveredSource source, SourcePlan plan, string reason)
    {
        source.Plan = plan;
        source.Reason = reason;
        return source;
    }

    /// <summary>
    /// The file name as its tool would have written it: a leading tool timestamp
    /// ("20261118100301_") and a leading "&lt;user&gt;_" for a user's file are removed.
    /// </summary>
    public static string StripName(string fileName, string? user)
    {
        var name = ToolTimestamp().Replace(fileName, "");
        if (!string.IsNullOrEmpty(user)
            && name.StartsWith(user + "_", StringComparison.OrdinalIgnoreCase)
            && name.Length > user.Length + 1)
            name = name[(user.Length + 1)..];
        return ToolTimestamp().Replace(name, "");
    }

    /// <summary>
    /// The user a file belongs to, from where it sits: ArtefactForge puts a user's files in
    /// &lt;Category&gt;\&lt;User&gt;\&lt;User&gt;_&lt;Tool&gt;..., so only a file two folders down
    /// can be one. A file directly in a category folder named like its tool (Amcache\Amcache_...)
    /// keeps its name.
    /// </summary>
    private static string? UserFolder(string relativePath)
    {
        var parts = relativePath.Split('/');
        return parts.Length >= 3 ? parts[^2] : null;
    }

    /// <summary>The parser a file name suggests: its first word, "RECmd" in "RECmd_Batch_Kroll.csv".</summary>
    public static string ParserFromName(string strippedName)
    {
        var stem = System.IO.Path.GetFileNameWithoutExtension(strippedName);
        var first = stem.Split('_', 2)[0];
        return first.Length == 0 || first.All(char.IsDigit) ? "unknown" : first;
    }

    /// <summary>
    /// The column names on the first line of a CSV, with any byte order mark removed. Quoted names
    /// are unquoted; a quoted name may hold a comma.
    /// </summary>
    public static IReadOnlyList<string> ReadHeader(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var line = reader.ReadLine();
        if (string.IsNullOrWhiteSpace(line)) return [];

        var columns = new List<string>();
        var current = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { current.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else current.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { columns.Add(current.ToString()); current.Clear(); }
            else current.Append(c);
        }
        columns.Add(current.ToString());
        return columns;
    }

    [GeneratedRegex(@"^\d{8,20}_")]
    private static partial Regex ToolTimestamp();
}
