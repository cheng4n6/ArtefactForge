using System.Text;
using System.Text.Json;
using DuckDB.NET.Data;

namespace ArtefactForge.Lake.Queries;

/// <summary>What <see cref="IocResults.Write"/> did.</summary>
public sealed record IocResultsSummary(string OutputRoot, bool Listed, int Iocs, int Hits, int HostsWithHits)
{
    public string Describe() =>
        !Listed ? "no IOCs.csv in the case, so nothing was swept"
        : $"{Iocs} IOC(s): {Hits} hit(s) on {HostsWithHits} host(s)";
}

/// <summary>
/// ArtefactForge's IocHits.csv from the lake's saved queries, under an output root of its own,
/// written as the IOC sweep writes it: the header unquoted, a cell quoted only when it must be,
/// UTF-8 with a byte order mark, CRLF.
///
/// The matching is the queries'. What is left here is what SQL does not do: reading the run's
/// _Logs\manifest.json for the module that wrote each file, and writing the file.
/// </summary>
public static class IocResults
{
    public const string Folder = "IOC";
    public const string HitsFileName = "IocHits.csv";
    public const string ListFileName = "IOCs.csv";

    public static readonly string[] Columns =
        ["IocType", "Ioc", "Host", "Module", "Time", "OutputFile", "LineNumber", "MatchingLine"];

    /// <summary>Where the lake build writes it: &lt;lake&gt;\results\IOC.</summary>
    public static string OutputRootFor(string lakeDirectory) => Path.Combine(lakeDirectory, LakeNames.ResultsFolder, Folder);

    /// <summary>
    /// Sweeps the hosts' rows for the case's IOCs and writes &lt;root&gt;\IocHits.csv; with no
    /// IOCs.csv in the case, as the run's own sweep, nothing. What was there before is removed
    /// first. Throws InvalidDataException for a list with no Value column, which the sweep refuses too.
    /// </summary>
    public static IocResultsSummary Write(LakeQuerySession session, string caseDirectory, string outputRoot,
        CancellationToken cancellationToken = default)
    {
        if (Directory.Exists(outputRoot)) Directory.Delete(outputRoot, recursive: true);
        var list = Path.Combine(caseDirectory, ListFileName);
        if (!File.Exists(list)) return new IocResultsSummary(outputRoot, false, 0, 0, 0);
        var header = LakeCsv.ReadHeader(list) ?? [];
        if (!header.Any(h => h.Trim().Equals("Value", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException($"{ListFileName} has no Value column; its first line should be: Type,Value,Note,Found on");

        session.Execute("CREATE TEMP TABLE IF NOT EXISTS ioc_modules (output_file VARCHAR, module VARCHAR)");
        foreach (var (file, module) in ModuleMap(caseDirectory))
        {
            using var command = session.CreateCommand();
            command.CommandText = "INSERT INTO ioc_modules VALUES ($file, $module)";
            command.Parameters.Add(new DuckDBParameter("file", file));
            command.Parameters.Add(new DuckDBParameter("module", module));
            command.ExecuteNonQuery();
        }
        cancellationToken.ThrowIfCancellationRequested();

        var rows = session.RunToRows(Query("ioc_hits"));
        var iocs = session.RunToRows(Query("ioc_list"));
        Directory.CreateDirectory(outputRoot);
        var path = Path.Combine(outputRoot, HitsFileName);
        using (var writer = new StreamWriter(path + ".tmp", false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            writer.Write(string.Join(",", Columns) + "\r\n");
            foreach (var row in rows) writer.Write(string.Join(",", Columns.Select(c => Escape(row[c]))) + "\r\n");
        }
        File.Move(path + ".tmp", path, overwrite: true);
        return new IocResultsSummary(outputRoot, true, iocs.Count, rows.Count,
            rows.Select(r => r["Host"]).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    private static LakeQuery Query(string name) =>
        LakeQueryCatalogue.Find(name) ?? throw new InvalidDataException($"The saved query {name} is missing from the lake library");

    /// <summary>The sweep's CSV rule (CsvText.Escape): quoted only for a comma, a quote or a line break.</summary>
    public static string Escape(string value) =>
        value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r')
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;

    /// <summary>
    /// The module that wrote each output file, by its path from the host folder down
    /// (HOST\Category\file.csv), from the case's last manifest, as the sweep's ModuleMap reads it.
    /// A file it does not list is named by its folder in the query. An unreadable manifest names none.
    /// </summary>
    public static Dictionary<string, string> ModuleMap(string caseDirectory)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var manifest = Path.Combine(caseDirectory, "_Logs", "manifest.json");
        try
        {
            if (!File.Exists(manifest)) return map;
            using var document = JsonDocument.Parse(File.ReadAllText(manifest));
            if (!document.RootElement.TryGetProperty("Results", out var results)) return map;
            foreach (var result in results.EnumerateArray())
            {
                var module = result.GetProperty("Module").GetString() ?? "";
                var collection = result.GetProperty("Collection").GetString() ?? "";
                var destination = result.GetProperty("Destination").GetString() ?? "";
                if (!result.TryGetProperty("Processors", out var processors) || destination.Length == 0) continue;
                var parts = destination.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                var from = Array.FindLastIndex(parts, p => p.Equals(collection, StringComparison.OrdinalIgnoreCase));
                if (from < 0) continue;
                var folder = Path.Combine(parts[from..]);
                foreach (var processor in processors.EnumerateArray())
                {
                    if (!processor.TryGetProperty("OutputFiles", out var outputs)) continue;
                    foreach (var text in outputs.EnumerateArray().Select(o => o.GetString() ?? ""))
                    {
                        if (text.Contains("=> FAILED", StringComparison.Ordinal)) continue;
                        var arrow = text.IndexOf(" => ", StringComparison.Ordinal);
                        map[Path.Combine(folder, arrow < 0 ? text : text[(arrow + 4)..])] = module;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
                                       or InvalidOperationException or KeyNotFoundException)
        {
            // As the sweep: without the manifest every file is named by its folder.
        }
        return map;
    }
}
