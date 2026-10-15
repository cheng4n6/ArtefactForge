using System.Text;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// Hayabusa and Chainsaw detections across the case, one row per rule, highest level first.
/// Informational hits are left out: on a busy host they run to hundreds of thousands and bury
/// everything else, and they stay in each host's timeline.
/// </summary>
internal sealed class DetectionsSection : ICaseReportSection
{
    private const int MaxRules = 100;

    private sealed class Rule
    {
        public string Title = "";
        public string Level = "";
        public readonly SortedSet<string> Tags = new(StringComparer.Ordinal);
        public readonly SortedSet<string> Tools = new(StringComparer.Ordinal);
        public readonly SortedSet<string> Hosts = new(StringComparer.OrdinalIgnoreCase);
        public long Hits;
        public DateTime? First;
        public DateTime? Last;
    }

    public ReportSection Build(CaseReportContext context)
    {
        var rules = new Dictionary<string, Rule>(StringComparer.OrdinalIgnoreCase);
        var problems = new List<string>();
        var anyTool = false;
        var critical = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var high = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

        foreach (var machine in context.Machines)
        {
            var name = machine[0].Name;
            foreach (var host in machine)
            {
                var detections = context.Detections.GetValueOrDefault(host.Collection) ?? HostDetections.None;
                anyTool |= detections.Tools.Count > 0;
                problems.AddRange(detections.Problems.Select(p => $"{host.Collection}: {p}"));
            }

            foreach (var hit in context.MachineDetections.GetValueOrDefault(name) ?? [])
            {
                if (hit.Level == DetectionSummary.Informational) continue;
                if (!rules.TryGetValue(hit.Title, out var rule)) rules[hit.Title] = rule = new Rule { Title = hit.Title, Level = hit.Level };
                if (rule.Level.Length == 0) rule.Level = hit.Level;
                foreach (var tag in hit.Tags.Split(", ", StringSplitOptions.RemoveEmptyEntries)) rule.Tags.Add(tag);
                foreach (var tool in hit.Tool.Split(", ", StringSplitOptions.RemoveEmptyEntries)) rule.Tools.Add(tool);
                rule.Hosts.Add(name);
                rule.Hits += hit.Hits;
                if (hit.First is { } f && (rule.First is null || f < rule.First)) rule.First = f;
                if (hit.Last is { } l && (rule.Last is null || l > rule.Last)) rule.Last = l;

                var tally = hit.Level == DetectionSummary.Critical ? critical : hit.Level == DetectionSummary.High ? high : null;
                if (tally is not null) tally[name] = tally.GetValueOrDefault(name) + hit.Hits;
            }
        }

        const string source = "Hayabusa and Chainsaw, grouped by rule. A rule both report, or a host collected more than once, "
                              + "is counted once per host. Informational hits are left out; every hit is in each host's EventLogs folder.";
        if (!anyTool)
            return new ReportSection
            {
                Id = "detections", Title = "Detections", Source = source,
                Body = Empty("No Hayabusa or Chainsaw output in this case. Run the Hayabusa or Chainsaw module to see detections here.")
            };

        var ordered = rules.Values
            .OrderBy(r => DetectionSummary.Rank(r.Level))
            .ThenByDescending(r => r.Hits)
            .ThenBy(r => r.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var total = ordered.Sum(r => r.Hits);

        var body = new StringBuilder();
        if (problems.Count > 0)
            body.Append("<div class=\"flags box\">")
                .Append(string.Concat(problems.Select(p => $"<div>{Pill("Incomplete", "med")} {E(p)}</div>")))
                .Append("</div>");

        if (ordered.Count == 0)
            body.Append(Empty("Hayabusa and Chainsaw found nothing above informational level."));
        else
        {
            body.Append("<div class=\"box tbl\"><table><thead><tr><th>Level</th><th>Rule</th><th>ATT&amp;CK</th><th>Found by</th>")
                .Append("<th>Hosts</th><th>Hits</th><th>First seen (UTC)</th><th>Last seen (UTC)</th></tr></thead><tbody>");
            foreach (var rule in ordered.Take(MaxRules))
            {
                var hosts = string.Join(", ", rule.Hosts.Take(4)) + (rule.Hosts.Count > 4 ? $" and {rule.Hosts.Count - 4} more" : "");
                body.Append("<tr>")
                    .Append($"<td>{LevelPill(rule.Level)}</td>")
                    .Append($"<td class=\"wrap\">{E(rule.Title)}</td>")
                    .Append($"<td class=\"mono\">{E(string.Join(", ", rule.Tags.Take(3)))}</td>")
                    .Append($"<td>{E(string.Join(", ", rule.Tools))}</td>")
                    .Append($"<td class=\"wrap\">{E(hosts)}</td>")
                    .Append($"<td>{N(rule.Hits)}</td>")
                    .Append($"<td class=\"mono\">{E(Time(rule.First))}</td>")
                    .Append($"<td class=\"mono\">{E(Time(rule.Last))}</td>")
                    .Append("</tr>");
            }
            body.Append("</tbody></table></div>");
            if (ordered.Count > MaxRules)
                body.Append($"<p class=\"muted\">The top {MaxRules} of {N(ordered.Count)} rules. The rest are in each host's EventLogs folder.</p>");
        }

        var findings = new List<ReportFinding>();
        if (critical.Count > 0)
            findings.Add(new ReportFinding(FindingLevel.Critical, N(critical.Values.Sum()), "Critical detections", ByHost(critical), "detections"));
        if (high.Count > 0)
            findings.Add(new ReportFinding(FindingLevel.High, N(high.Values.Sum()), "High detections", ByHost(high), "detections"));

        return new ReportSection
        {
            Id = "detections", Title = "Detections", Count = N(total), Source = source,
            Body = body.ToString(), Findings = findings
        };
    }

    internal static string LevelPill(string level) => level switch
    {
        DetectionSummary.Critical => Pill("Critical", "crit"),
        DetectionSummary.High => Pill("High", "high"),
        DetectionSummary.Medium => Pill("Medium", "med"),
        DetectionSummary.Low => Pill("Low", "low"),
        "" => Pill("Not given", "plain"),
        _ => Pill(level, "plain")
    };

    private static string ByHost(Dictionary<string, long> hits) =>
        string.Join(", ", hits.OrderByDescending(h => h.Value).Take(3).Select(h => $"{h.Key} {N(h.Value)}"))
        + (hits.Count > 3 ? $" and {hits.Count - 3} more" : "");
}
