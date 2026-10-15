using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Core.Report;

/// <summary>One rule's hits on one host from one tool.</summary>
public sealed record RuleHits(string Title, string Level, string Tags, string Tool, int Hits, DateTime? First, DateTime? Last);

/// <summary>A host's Hayabusa and Chainsaw detections, counted by rule.</summary>
public sealed record HostDetections(IReadOnlyList<RuleHits> Rules, IReadOnlyList<string> Tools, IReadOnlyList<string> Problems)
{
    public static readonly HostDetections None = new([], [], []);

    /// <summary>
    /// One row per rule: a rule both tools report is the same events seen twice, so it counts the
    /// higher of the two rather than the sum.
    /// </summary>
    public IReadOnlyList<RuleHits> Merged() => DetectionSummary.MergeByRule(Rules);
}

/// <summary>
/// Counts a host's detections by rule from Hayabusa's timeline and Chainsaw's hunt CSVs in its
/// EventLogs folder. A timeline runs to hundreds of MB, and the report is rebuilt after every
/// IOC sweep and RDP trace, so each host's counts are kept in _Logs\CaseReport\Detections and
/// read again only when one of its files changes.
/// </summary>
public static class DetectionSummary
{
    public const string Critical = "Critical";
    public const string High = "High";
    public const string Medium = "Medium";
    public const string Low = "Low";
    public const string Informational = "Informational";

    private const string Hayabusa = "Hayabusa";
    private const string Chainsaw = "Chainsaw";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    private static readonly Regex Technique = new(@"\bT\d{4}(?:\.\d{3})?\b", RegexOptions.Compiled);
    private static readonly Regex RerunSuffix = new(@"_\d+$", RegexOptions.Compiled);

    private sealed record InputFile(string File, long Length, long ModifiedTicks);
    private sealed record Cached(List<InputFile> Inputs, HostDetections Detections);

    /// <summary>Hayabusa's levels (crit, med, info) and Sigma's, as one set of names.</summary>
    public static string NormaliseLevel(string level) => level.Trim().ToLowerInvariant() switch
    {
        "crit" or "critical" or "emergency" => Critical,
        "high" => High,
        "med" or "medium" => Medium,
        "low" => Low,
        "info" or "informational" => Informational,
        _ => ""
    };

    /// <summary>Sort order: critical first, a rule with no level after low.</summary>
    public static int Rank(string level) => level switch
    {
        Critical => 0, High => 1, Medium => 2, Low => 3, "" => 4, _ => 5
    };

    /// <summary>
    /// One row per rule from rows that see the same events: the higher count, not the sum, with
    /// the widest time span and every tag and tool. Used for a rule both tools report on a host,
    /// and for a host collected more than once, whose later collection reads the same logs again.
    /// </summary>
    public static IReadOnlyList<RuleHits> MergeByRule(IEnumerable<RuleHits> rows) =>
        rows.GroupBy(r => r.Title, StringComparer.OrdinalIgnoreCase)
            .Select(g => new RuleHits(
                g.First().Title,
                g.Select(r => r.Level).FirstOrDefault(l => l.Length > 0) ?? "",
                Join(g.Select(r => r.Tags)),
                Join(g.Select(r => r.Tool)),
                g.Max(r => r.Hits),
                g.Min(r => r.First),
                g.Max(r => r.Last)))
            .ToList();

    private static string Join(IEnumerable<string> lists) =>
        string.Join(", ", lists.SelectMany(l => l.Split(", ", StringSplitOptions.RemoveEmptyEntries))
                               .Distinct(StringComparer.OrdinalIgnoreCase));

    public static HostDetections ForHost(CaseReportContext context, ReportHost host)
    {
        var inputs = Inputs(host.Directory);
        if (inputs.Count == 0) return HostDetections.None;

        var stamp = inputs.Select(i => Stamp(host.Directory, i.Path)).ToList();
        var cachePath = Path.Combine(context.WorkDirectory, "Detections", SafeName(host.Collection) + ".json");
        if (ReadCache(cachePath) is { } cached && cached.Inputs.SequenceEqual(stamp)) return cached.Detections;

        var rules = new List<RuleHits>();
        var problems = new List<string>();
        foreach (var (tool, path) in inputs)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            try { rules.AddRange(Read(tool, path, context.CancellationToken)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problems.Add($"{Path.GetFileName(path)} could not be read: {ex.Message}");
            }
        }

        var detections = new HostDetections(rules, inputs.Select(i => i.Tool).Distinct().ToList(), problems);
        if (problems.Count == 0) WriteCache(cachePath, new Cached(stamp, detections));
        return detections;
    }

    /// <summary>
    /// The newest Hayabusa timeline, and the newest of each Chainsaw hunt file (a module re-run
    /// writes beside the old file, as sigma_2.csv). Chainsaw's files are named after its rule
    /// groups, so they are known by their header: a timestamp and a detections column.
    /// </summary>
    private static List<(string Tool, string Path)> Inputs(string hostDirectory)
    {
        var folder = Path.Combine(hostDirectory, "EventLogs");
        if (!Directory.Exists(folder)) return [];

        List<string> csvs;
        try { csvs = Directory.EnumerateFiles(folder, "*.csv", SearchOption.AllDirectories).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }

        var found = new List<(string, string)>();
        var timeline = csvs.Where(f => Path.GetFileName(f).StartsWith("Hayabusa_Timeline", StringComparison.OrdinalIgnoreCase))
                           .OrderByDescending(File.GetLastWriteTimeUtc)
                           .FirstOrDefault();
        if (timeline is not null) found.Add((Hayabusa, timeline));

        found.AddRange(csvs
            .Where(f => !Path.GetFileName(f).StartsWith("Hayabusa", StringComparison.OrdinalIgnoreCase)
                        && !Path.GetFileName(f).StartsWith("EvtxECmd", StringComparison.OrdinalIgnoreCase))
            .Where(IsChainsawHunt)
            .GroupBy(f => Path.Combine(Path.GetDirectoryName(f)!, RerunSuffix.Replace(Path.GetFileNameWithoutExtension(f), "")),
                     StringComparer.OrdinalIgnoreCase)
            .Select(g => (Chainsaw, g.OrderByDescending(File.GetLastWriteTimeUtc).First()))
            .OrderBy(f => f.Item2, StringComparer.OrdinalIgnoreCase));
        return found;
    }

    private static bool IsChainsawHunt(string path)
    {
        try
        {
            using var reader = new CsvRecordReader(path);
            var header = reader.ReadRecord();
            return header is not null
                   && header.Any(h => h.Trim().Equals("detections", StringComparison.OrdinalIgnoreCase))
                   && header.Any(h => h.Trim().Equals("timestamp", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    private sealed class Tally
    {
        public string Level = "";
        public readonly HashSet<string> Tags = new(StringComparer.OrdinalIgnoreCase);
        public int Hits;
        public DateTime? First;
        public DateTime? Last;
    }

    /// <summary>Counts one file's hits by rule. Hayabusa has a rule per row; a Chainsaw row can name several.</summary>
    internal static List<RuleHits> Read(string tool, string path, CancellationToken cancellationToken)
    {
        var tallies = new Dictionary<string, Tally>(StringComparer.OrdinalIgnoreCase);
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return [];
        var index = header.Select((name, i) => (name: name.Trim(), i))
                          .GroupBy(p => p.name, StringComparer.OrdinalIgnoreCase)
                          .ToDictionary(g => g.Key, g => g.First().i, StringComparer.OrdinalIgnoreCase);
        int Column(string name) => index.TryGetValue(name, out var i) ? i : -1;

        var hayabusa = tool == Hayabusa;
        var titleColumn = hayabusa ? Column("RuleTitle") : Column("detections");
        var timeColumn = hayabusa ? Column("Timestamp") : Column("timestamp");
        var levelColumn = Column("Level");
        var tagsColumn = Column("MitreTags");
        if (titleColumn < 0) return [];

        var rows = 0;
        while (reader.ReadRecord() is { } fields)
        {
            if (++rows % 10_000 == 0) cancellationToken.ThrowIfCancellationRequested();
            string Cell(int column) => column >= 0 && column < fields.Count ? fields[column] : "";

            IEnumerable<string> titles = hayabusa
                ? new[] { Cell(titleColumn).Trim() }
                : Cell(titleColumn).Split(['\n', ';'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                                   .Select(t => t.TrimStart('+', ' ').Trim());
            var time = ParseTime(Cell(timeColumn));
            var level = NormaliseLevel(Cell(levelColumn));
            var tags = Technique.Matches(Cell(tagsColumn)).Select(m => m.Value.ToUpperInvariant()).ToList();

            foreach (var title in titles)
            {
                if (title.Length == 0) continue;
                if (!tallies.TryGetValue(title, out var tally)) tallies[title] = tally = new Tally();
                tally.Hits++;
                if (tally.Level.Length == 0) tally.Level = level;
                foreach (var tag in tags) tally.Tags.Add(tag);
                if (time is { } t)
                {
                    if (tally.First is null || t < tally.First) tally.First = t;
                    if (tally.Last is null || t > tally.Last) tally.Last = t;
                }
            }
        }

        return tallies.Select(t => new RuleHits(t.Key, t.Value.Level, string.Join(", ", t.Value.Tags.Order(StringComparer.Ordinal)),
                                                tool, t.Value.Hits, t.Value.First, t.Value.Last))
                      .ToList();
    }

    /// <summary>
    /// Hayabusa's "2026-03-01 10:00:00.123 +00:00", ISO 8601 "2026-03-01T10:00:00Z" and
    /// Chainsaw's "2026-03-01T10:00:00.123456+00:00": the first 19 characters are the UTC time.
    /// </summary>
    public static DateTime? ParseTime(string text)
    {
        text = text.Trim();
        if (text.Length < 19) return null;
        return DateTime.TryParseExact(text[..19].Replace('T', ' '), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                                      DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)
            ? t : null;
    }

    private static InputFile Stamp(string hostDirectory, string path)
    {
        var info = new FileInfo(path);
        return new InputFile(Path.GetRelativePath(hostDirectory, path), info.Length, info.LastWriteTimeUtc.Ticks);
    }

    private static Cached? ReadCache(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<Cached>(File.ReadAllText(path), Json) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return null;   // read again from the files, and written fresh
        }
    }

    private static void WriteCache(string path, Cached cached)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(cached, Json));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Only a cache: the next rebuild reads the files again.
        }
    }

    private static string SafeName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        return new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
    }
}
