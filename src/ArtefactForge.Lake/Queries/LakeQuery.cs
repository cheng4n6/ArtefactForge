using System.Reflection;
using System.Text.RegularExpressions;

namespace ArtefactForge.Lake.Queries;

/// <summary>A value a saved query takes, with the default it runs with when none is given.</summary>
public sealed record LakeQueryParameter(string Name, string Default, string Description);

/// <summary>
/// A file from the case folder a saved query reads, such as the analyst's Ransomware-Overrides.csv.
/// It is loaded into a temporary table of this name with these columns, all text, plus input_row
/// (its place in the file, from 1). A file that is not there gives an empty table, so a query never
/// has to ask whether the analyst made one.
/// </summary>
public sealed record LakeQueryInput(string Table, string FileName, IReadOnlyList<string> Columns);

/// <summary>
/// A lake table a saved query reads, and the columns it reads from it. A lake with no such table
/// (no host had that output) gets an empty one; a table without one of the columns (an older
/// tool version) gets it, empty. Both only for the query's connection: the lake is not changed.
/// </summary>
public sealed record LakeQueryTable(string Table, IReadOnlyList<string> Columns);

/// <summary>
/// The rows of every host's files that match <see cref="Pattern"/>, whichever raw table they were
/// loaded into: a file the lake has no mapping for goes to a table named after how it was found
/// (raw_unmapped_recmd_ntuser_recentdocs, or another name with outputs.json), so a query that
/// needs "the RecentDocs CSVs" names the files, as ArtefactForge looks for them, not the table.
///
/// The pattern is a host-relative folder and a file name pattern: Registry/*ProfileList*.csv for
/// files directly in Registry, Registry/**/*_RecentDocs*.csv for that folder and every one below
/// it. Names compare as Windows does, without regard to case. Two temporary objects are made:
/// <c>&lt;Table&gt;</c>, a view of the files' rows (host, source_id, row_no and these columns, all
/// text, empty where a file lacks one), and <c>&lt;Table&gt;_files</c>, one row per matching file
/// that exists (host, source_id, path, mtime, status), loaded or not.
/// </summary>
public sealed record LakeQueryFiles(string Table, string Pattern, IReadOnlyList<string> Columns);

/// <summary>
/// One saved query: a .sql file under Queries\ in this assembly whose leading comment block says
/// what it is. A "setup" query makes temporary tables for others and returns nothing; any other
/// query is one SELECT whose rows are its result.
///
///   -- title: Ransomware: one row per host
///   -- category: ransomware
///   -- severity: high
///   -- type: setup                     (optional; "result" when left out)
///   -- description: what it finds,
///   --   continued on lines indented under it
///   -- requires: ransomware_prepare    (setup queries run first, in order)
///   -- input: ransomware_overrides = Ransomware-Overrides.csv (Collection, Extension, NoteName)
///   -- table: raw_mftecmd_mft (FileName, ParentPath, FileSize)
///   -- files: da_profilelist = Registry/*ProfileList*.csv (KeyName, ProfileImagePath)
///   -- parameter: usn_min_files = 50 - renames to one extension before it is called
///
/// A parameter is read in the SQL as getvariable('usn_min_files'), as text: cast it where a
/// number is wanted.
/// </summary>
public sealed partial record LakeQuery
{
    public const string SetupType = "setup";
    public const string ResultType = "result";

    public required string Name { get; init; }
    public required string Title { get; init; }
    public string Category { get; init; } = "";
    public string Severity { get; init; } = "";
    public string Type { get; init; } = ResultType;
    public string Description { get; init; } = "";
    public IReadOnlyList<string> Requires { get; init; } = [];
    public IReadOnlyList<LakeQueryInput> Inputs { get; init; } = [];
    public IReadOnlyList<LakeQueryTable> Tables { get; init; } = [];
    public IReadOnlyList<LakeQueryFiles> Files { get; init; } = [];
    public IReadOnlyList<LakeQueryParameter> Parameters { get; init; } = [];
    public required string Sql { get; init; }

    public bool IsSetup => Type == SetupType;

    /// <summary>Reads a query file's header block. Throws InvalidDataException for a header it cannot use.</summary>
    public static LakeQuery Parse(string name, string text)
    {
        var fields = new List<(string Key, string Value)>();
        var lines = text.Replace("\r\n", "\n").Split('\n');
        foreach (var line in lines)
        {
            if (!line.StartsWith("--", StringComparison.Ordinal)) break;
            var body = line[2..];
            var field = HeaderField().Match(body);
            if (field.Success)
                fields.Add((field.Groups[1].Value.ToLowerInvariant(), field.Groups[2].Value.Trim()));
            else if (fields.Count > 0 && body.StartsWith("   ", StringComparison.Ordinal) && body.Trim().Length > 0)
                fields[^1] = (fields[^1].Key, (fields[^1].Value + " " + body.Trim()).Trim());
        }

        string One(string key) => fields.LastOrDefault(f => f.Key == key).Value ?? "";
        IEnumerable<string> All(string key) => fields.Where(f => f.Key == key).Select(f => f.Value);

        var title = One("title");
        if (title.Length == 0) throw new InvalidDataException($"Query {name} has no '-- title:' line");
        var type = One("type").ToLowerInvariant();
        if (type.Length == 0) type = ResultType;
        if (type is not (SetupType or ResultType))
            throw new InvalidDataException($"Query {name}: type must be '{SetupType}' or '{ResultType}', not '{type}'");

        return new LakeQuery
        {
            Name = name,
            Title = title,
            Category = One("category"),
            Severity = One("severity"),
            Type = type,
            Description = One("description"),
            Requires = All("requires").SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList(),
            Inputs = All("input").Select(v => ParseInput(name, v)).ToList(),
            Tables = All("table").Select(v => ParseTable(name, v)).ToList(),
            Files = All("files").Select(v => ParseFiles(name, v)).ToList(),
            Parameters = All("parameter").Select(v => ParseParameter(name, v)).ToList(),
            Sql = text
        };
    }

    private static LakeQueryInput ParseInput(string query, string value)
    {
        var m = InputField().Match(value);
        if (!m.Success)
            throw new InvalidDataException($"Query {query}: input must read 'table = File.csv (Column, Column)', not '{value}'");
        return new LakeQueryInput(m.Groups[1].Value, m.Groups[2].Value.Trim(), Columns(m.Groups[3].Value));
    }

    private static LakeQueryTable ParseTable(string query, string value)
    {
        var m = TableField().Match(value);
        if (!m.Success)
            throw new InvalidDataException($"Query {query}: table must read 'name (Column, Column)', not '{value}'");
        return new LakeQueryTable(m.Groups[1].Value, Columns(m.Groups[2].Value));
    }

    private static LakeQueryFiles ParseFiles(string query, string value)
    {
        var m = InputField().Match(value);
        if (!m.Success)
            throw new InvalidDataException($"Query {query}: files must read 'table = Folder/pattern.csv (Column, Column)', not '{value}'");
        var pattern = m.Groups[2].Value.Trim();
        if (!LakeFilePattern.IsValid(pattern))
            throw new InvalidDataException(
                $"Query {query}: files pattern '{pattern}' must be a folder, optionally /**, then a file name pattern");
        return new LakeQueryFiles(m.Groups[1].Value, pattern, Columns(m.Groups[3].Value));
    }

    private static LakeQueryParameter ParseParameter(string query, string value)
    {
        var m = ParameterField().Match(value);
        if (!m.Success)
            throw new InvalidDataException($"Query {query}: parameter must read 'name = default - description', not '{value}'");
        return new LakeQueryParameter(m.Groups[1].Value, m.Groups[2].Value.Trim(), m.Groups[3].Value.Trim());
    }

    private static List<string> Columns(string list) =>
        list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    [GeneratedRegex(@"^\s([A-Za-z]+):\s?(.*)$")]
    private static partial Regex HeaderField();

    [GeneratedRegex(@"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^()]+?)\s*\(([^()]*)\)$")]
    private static partial Regex InputField();

    [GeneratedRegex(@"^([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)$")]
    private static partial Regex TableField();

    [GeneratedRegex(@"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*(?:-\s*(.*))?$")]
    private static partial Regex ParameterField();
}

/// <summary>The saved queries built into the lake library.</summary>
public static class LakeQueryCatalogue
{
    private static readonly Lazy<IReadOnlyList<LakeQuery>> Loaded = new(Load);

    /// <summary>Every saved query, by name.</summary>
    public static IReadOnlyList<LakeQuery> All => Loaded.Value;

    public static LakeQuery? Find(string name) =>
        All.FirstOrDefault(q => q.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<LakeQuery> Load()
    {
        var assembly = typeof(LakeQueryCatalogue).Assembly;
        const string prefix = "Queries/";
        var queries = new List<LakeQuery>();
        foreach (var resource in assembly.GetManifestResourceNames()
                     .Where(r => r.StartsWith(prefix, StringComparison.Ordinal) && r.EndsWith(".sql", StringComparison.Ordinal))
                     .Order(StringComparer.Ordinal))
        {
            var name = resource[prefix.Length..^".sql".Length];
            queries.Add(LakeQuery.Parse(name, KindRegistry.ReadResource(assembly, resource)));
        }
        foreach (var query in queries)
            foreach (var required in query.Requires)
                if (queries.FirstOrDefault(q => q.Name == required) is not { IsSetup: true })
                    throw new InvalidDataException($"Query {query.Name} requires {required}, which is not a setup query");
        return queries;
    }
}
