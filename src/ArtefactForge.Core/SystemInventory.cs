using System.Text;

namespace ArtefactForge.Core;

/// <summary>
/// Rolls the per-collection system summaries up into one inventory for the case.
///
/// When a batch covers ten hosts, the question asked first is usually "what are these machines"
/// rather than anything about a single one, and answering it should not mean opening ten files.
///
/// This is the one place the engine knows a module's output by name. The alternative - a module
/// scope that runs once per case - would be a larger change to the schema for a single use, so the
/// convention is documented instead: a module that writes SystemInfo\SystemInfo.csv with
/// Category/Item/Value columns is rolled up here.
/// </summary>
public static class SystemInventory
{
    private const string SummaryRelativePath = @"SystemInfo\SystemInfo.csv";

    /// <summary>Items lifted into the inventory, in the order they appear as columns.</summary>
    private static readonly string[] Headline =
    [
        "Hostname", "PRETTY_NAME", "DISTRIB_DESCRIPTION", "ProductName", "Timezone",
        "LastBootUtc", "IPAddresses", "DnsServers", "TotalAccounts", "InteractiveAccounts",
        "UID0Accounts", "MachineID", "Domain"
    ];

    /// <summary>Holds the number of CollectionGaps rows among the facts; not a summary item.</summary>
    public const string GapCountKey = "__gapCount";

    /// <summary>
    /// Writes SystemInventory.csv at the case root. Does nothing when no collection produced a
    /// summary, rather than leaving an empty file that looks like a failed run.
    /// </summary>
    public static string? Build(string caseDirectory)
    {
        var rows = new List<Dictionary<string, string>>();

        foreach (var (name, facts) in Collect(caseDirectory))
        {
            var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Collection"] = name
            };

            foreach (var item in Headline)
                if (facts.TryGetValue(item, out var value) && value.Length > 0)
                    row[item] = value;

            // Gaps are counted rather than listed: the detail lives in the per-collection summary,
            // and what matters here is which hosts have an incomplete picture.
            row["CollectionGaps"] = facts.TryGetValue(GapCountKey, out var gaps) ? gaps : "0";
            rows.Add(row);
        }

        if (rows.Count == 0) return null;

        var columns = new List<string> { "Collection" };
        columns.AddRange(Headline.Where(h => rows.Any(r => r.ContainsKey(h))));
        columns.Add("CollectionGaps");

        var csv = new StringBuilder();
        csv.AppendLine(string.Join(",", columns.Select(Escape)));
        foreach (var row in rows)
            csv.AppendLine(string.Join(",", columns.Select(c => Escape(row.TryGetValue(c, out var v) ? v : ""))));

        var path = Path.Combine(caseDirectory, "SystemInventory.csv");
        File.WriteAllText(path, csv.ToString());
        return path;
    }

    /// <summary>
    /// The summary facts of every collection in the case that produced one, by collection folder
    /// name, in name order. The evidence list reads the same facts as the inventory, so the two
    /// never disagree about a host.
    /// </summary>
    public static IReadOnlyList<(string Collection, IReadOnlyDictionary<string, string> Facts)> Collect(
        string caseDirectory)
    {
        var collected = new List<(string, IReadOnlyDictionary<string, string>)>();
        if (!Directory.Exists(caseDirectory)) return collected;

        foreach (var collectionDir in Directory.EnumerateDirectories(caseDirectory)
                                               .OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            var name = Path.GetFileName(collectionDir);
            if (name.StartsWith('_')) continue;   // _Logs, _Staging

            var summary = Path.Combine(collectionDir, SummaryRelativePath);
            if (!File.Exists(summary)) continue;

            var facts = ReadFacts(summary);
            if (facts.Count == 0) continue;
            collected.Add((name, facts));
        }

        return collected;
    }

    /// <summary>
    /// Item -> Value from a summary CSV. Later rows win, which matters where a distribution
    /// supplies the same item from more than one source file.
    /// </summary>
    private static Dictionary<string, string> ReadFacts(string path)
    {
        var facts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var gaps = 0;

        try
        {
            var lines = File.ReadAllLines(path);
            if (lines.Length < 2) return facts;

            var header = SplitCsv(lines[0]);
            var categoryIndex = Array.FindIndex(header, h => h.Equals("Category", StringComparison.OrdinalIgnoreCase));
            var itemIndex = Array.FindIndex(header, h => h.Equals("Item", StringComparison.OrdinalIgnoreCase));
            var valueIndex = Array.FindIndex(header, h => h.Equals("Value", StringComparison.OrdinalIgnoreCase));
            if (itemIndex < 0 || valueIndex < 0) return facts;

            foreach (var line in lines.Skip(1))
            {
                var fields = SplitCsv(line);
                if (fields.Length <= Math.Max(itemIndex, valueIndex)) continue;

                if (categoryIndex >= 0 && fields.Length > categoryIndex
                    && fields[categoryIndex].Equals("CollectionGaps", StringComparison.OrdinalIgnoreCase))
                {
                    gaps++;
                    continue;
                }

                var value = fields[valueIndex];
                if (value.Length > 0) facts[fields[itemIndex]] = value;
            }
        }
        catch (IOException) { return facts; }
        catch (UnauthorizedAccessException) { return facts; }

        facts[GapCountKey] = gaps.ToString();
        return facts;
    }

    /// <summary>Minimal RFC 4180 reader: enough for the summaries this writes, quotes included.</summary>
    private static string[] SplitCsv(string line)
    {
        var fields = new List<string>();
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
            else if (c == ',') { fields.Add(current.ToString()); current.Clear(); }
            else current.Append(c);
        }

        fields.Add(current.ToString());
        return [.. fields];
    }

    private static string Escape(string value) =>
        value.Contains(',') || value.Contains('"') || value.Contains('\n')
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;
}
