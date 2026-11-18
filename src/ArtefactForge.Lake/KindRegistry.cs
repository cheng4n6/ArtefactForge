using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArtefactForge.Lake;

/// <summary>
/// One kind of source the lake knows: which parser writes it, how its file is named, the columns
/// that identify it, and the SQL that maps its raw table into the timeline.
/// </summary>
public sealed record KindDefinition
{
    /// <summary>The kind's name, such as "pecmd.timeline". Its raw table is raw_pecmd_timeline.</summary>
    public required string Kind { get; init; }
    /// <summary>The parser as outputs.json names it, such as "PECmd".</summary>
    public required string Parser { get; init; }
    public string Description { get; init; } = "";
    /// <summary>
    /// Patterns for the file name, matched after a leading tool timestamp and user prefix are
    /// removed. A name match only proposes the kind; the header confirms it.
    /// </summary>
    public IReadOnlyList<string> FileNames { get; init; } = [];
    /// <summary>Columns every file of this kind has. A file missing one is a header mismatch.</summary>
    public IReadOnlyList<string> RequiredColumns { get; init; } = [];
    /// <summary>True when the file has exactly the required columns and no others.</summary>
    public bool ExactColumns { get; init; }
    /// <summary>
    /// True when the header alone does not identify the kind, because other files share it
    /// (RECmd's batch CSVs, Linux _Events and _KeyEvents): then only a file-name match maps it.
    /// </summary>
    public bool NameRequired { get; init; }
    /// <summary>
    /// Columns map.sql reads that only some versions or options of the tool write (Hayabusa's
    /// profiles, Chainsaw's groups). A raw table without one gets it, empty, before mapping.
    /// </summary>
    public IReadOnlyList<string> OptionalColumns { get; init; } = [];
    /// <summary>
    /// The column whose time puts a row in the timeline. A row with a value there that the
    /// mapping cannot read as a time is counted against its source, never dropped in silence.
    /// </summary>
    public string? TimeColumn { get; init; }
    /// <summary>
    /// What it means when <see cref="TimeColumn"/> is empty, for a kind whose rows can lack a UTC
    /// time (Linux logs with only the host's local time). Such rows stay raw and are counted
    /// against their source with this note; null when an empty time is not worth a look.
    /// </summary>
    public string? EmptyTimeNote { get; init; }
    /// <summary>
    /// The column holding the host's local time for rows with no <see cref="TimeColumn"/>. The
    /// mapping converts it with the host's zone (host_zones); the rows it converts are counted
    /// against their source, and only those it cannot convert are counted as without a time.
    /// </summary>
    public string? LocalTimeColumn { get; init; }
    /// <summary>How <see cref="TimeColumn"/> is read: "plain" (UTC as written) or "offset" (with a +hh:mm or Z).</summary>
    public string TimeParse { get; init; } = "plain";
    /// <summary>
    /// File names in the case folder itself (not a host's) that are this kind: case-wide files
    /// such as ArtefactForge's IocHits.csv. They are loaded with host "(case)".
    /// </summary>
    public IReadOnlyList<string> CaseFiles { get; init; } = [];
    public int MappingVersion { get; init; } = 1;
    /// <summary>The SELECT whose rows go into timeline; null for a kind kept raw only.</summary>
    public string? MapSql { get; init; }

    public string RawTable => LakeNames.RawTable(Kind);

    public bool NameMatches(string strippedFileName) =>
        FileNames.Any(p => Regex.IsMatch(strippedFileName, p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    /// <summary>The required columns <paramref name="header"/> lacks; empty when it fits.</summary>
    public IReadOnlyList<string> MissingColumns(IReadOnlyList<string> header)
    {
        var present = new HashSet<string>(header, StringComparer.OrdinalIgnoreCase);
        return RequiredColumns.Where(c => !present.Contains(c)).ToList();
    }

    /// <summary>The SQL macro (schema.sql) that reads <see cref="TimeColumn"/>.</summary>
    public string TimeFunction => TimeParse == "offset" ? "lake_ts_offset" : "lake_ts";

    public bool CaseFileMatches(string fileName) =>
        CaseFiles.Any(p => Regex.IsMatch(fileName, p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    public bool HeaderFits(IReadOnlyList<string> header) =>
        MissingColumns(header).Count == 0 && (!ExactColumns || header.Count == RequiredColumns.Count);
}

/// <summary>The kinds built into this library, read from its embedded Kinds\&lt;kind&gt; folders.</summary>
public static class KindRegistry
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly Lazy<IReadOnlyList<KindDefinition>> Loaded = new(Load);

    public static IReadOnlyList<KindDefinition> All => Loaded.Value;

    public static KindDefinition? Find(string kind) =>
        All.FirstOrDefault(k => string.Equals(k.Kind, kind, StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<KindDefinition> Load()
    {
        var assembly = typeof(KindRegistry).Assembly;
        var kinds = new List<KindDefinition>();
        foreach (var name in assembly.GetManifestResourceNames()
                     .Select(n => n.Replace('\\', '/'))
                     .Where(n => n.StartsWith("Kinds/", StringComparison.Ordinal)
                                 && n.EndsWith("/signature.json", StringComparison.Ordinal))
                     .Order(StringComparer.Ordinal))
        {
            var folder = name[..^"signature.json".Length];
            var definition = JsonSerializer.Deserialize<KindDefinition>(ReadResource(assembly, name), JsonOptions)
                ?? throw new InvalidDataException($"{name} is empty.");
            var map = TryReadResource(assembly, folder + "map.sql");
            kinds.Add(definition with { MapSql = map });
        }
        return kinds;
    }

    internal static string ReadResource(Assembly assembly, string name) =>
        TryReadResource(assembly, name)
        ?? throw new InvalidOperationException($"{name} is missing from {assembly.GetName().Name}.");

    private static string? TryReadResource(Assembly assembly, string name)
    {
        // RecursiveDir gives the logical name '\' separators on Windows; accept either.
        var actual = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => string.Equals(n.Replace('\\', '/'), name, StringComparison.Ordinal));
        if (actual is null) return null;
        using var stream = assembly.GetManifestResourceStream(actual)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

/// <summary>Names the lake gives files, tables and kinds.</summary>
public static partial class LakeNames
{
    public const string LakeFolder = "_Lake";
    public const string DatabaseFile = "case.duckdb";
    public const string LogFile = "lake.log";
    public const string BuildFile = "build.json";
    public const string TempFolder = "tmp";
    public const string UnmappedPrefix = "unmapped.";

    /// <summary>raw_ plus the kind with anything but letters and digits as '_': raw_pecmd_timeline.</summary>
    public static string RawTable(string kind) => "raw_" + Identifier(kind);

    /// <summary>
    /// The kind for a file no mapping covers: unmapped.&lt;parser&gt;_&lt;file stem&gt;, from the name the
    /// tool gave it (tool timestamp and user prefix already removed). The parser's name is not
    /// repeated when the stem starts with it: LECmd_Recent.csv from LECmd is unmapped.lecmd_recent.
    /// The same file from every host and user shares one table; different files of one tool do not.
    /// </summary>
    public static string Unmapped(string parser, string strippedFileName)
    {
        var stem = Path.GetFileNameWithoutExtension(strippedFileName);
        if (stem.StartsWith(parser + "_", StringComparison.OrdinalIgnoreCase)) stem = stem[(parser.Length + 1)..];
        var parserPart = Identifier(parser);
        var stemPart = stem.Length == 0 ? "" : Identifier(stem);
        return UnmappedPrefix + (stemPart.Length == 0 || stemPart == parserPart ? parserPart : parserPart + "_" + stemPart);
    }

    public static string Identifier(string text)
    {
        var cleaned = NotIdentifier().Replace(text.ToLowerInvariant(), "_").Trim('_');
        return cleaned.Length == 0 ? "unknown" : cleaned;
    }

    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NotIdentifier();
}
