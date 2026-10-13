using System.Net;
using System.Text;
using ArtefactForge.Core.Windows;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// The case's saved RDP traces, newest first: each as a chain from where it starts to the host it
/// was traced from, then its hops and flags. A trace whose hosts have changed since is marked.
/// </summary>
internal sealed class RdpSection : ICaseReportSection
{
    private sealed record Hop(
        string Number, string Result, string ToHost, string Time, string Account, string SourceIp, string ClientName,
        string FromHost, string ReceivingEvidence, string SendingEvidence, IReadOnlyList<string> Flags, string NextStep)
    {
        /// <summary>Where the connection came from: the host when known, else the address.</summary>
        public string Source => FromHost.Length > 0 ? FromHost : SourceIp.Length > 0 ? SourceIp : "Unknown source";
    }

    public ReportSection Build(CaseReportContext context)
    {
        const string source = "From the RdpTrace files in the case folder. Start a trace on the app's RDP trace tab.";
        var saved = RdpTrace.Saved(context.CaseDirectory);
        if (saved.Count == 0)
            return new ReportSection
            {
                Id = "rdp", Title = "RDP traces", Source = source,
                Body = Empty("No saved RDP traces in this case yet.")
            };

        var body = new StringBuilder();
        var findings = new List<ReportFinding>();
        var toCollect = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var stale = 0;
        var first = true;
        var externalReported = false;
        foreach (var trace in saved)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var hops = ReadHops(trace.Path);
            var last = hops.Count > 0 ? hops[hops.Count - 1] : null;
            var file = Path.GetFileName(trace.Path);

            var pills = new StringBuilder();
            if (last?.Result == RdpTrace.EndOfChain)
            {
                var external = IsExternal(last.SourceIp);
                pills.Append(Pill(external ? "Ends at external IP" : "End of chain", external ? "crit" : "high"));
                if (external && !externalReported)
                {
                    externalReported = true;
                    findings.Add(new ReportFinding(FindingLevel.Critical, last.SourceIp, "RDP chain ends at an external IP",
                        $"{hops.Count} {Plural(hops.Count, "hop", "hops")} into {trace.StartHost}", "rdp"));
                }
            }
            var collect = hops.Where(h => h.Result == RdpTrace.CollectNext).ToList();
            foreach (var h in collect) toCollect.Add(h.ClientName.Length > 0 ? $"{h.ClientName} ({h.SourceIp})" : h.SourceIp);
            if (collect.Count > 0) pills.Append(' ').Append(Pill($"{collect.Count} {Plural(collect.Count, "host", "hosts")} to collect", "med"));
            if (trace.Stale is { } why)
            {
                stale++;
                pills.Append(' ').Append(Pill("Out of date: " + why, "med"));
            }

            body.Append($"<details class=\"box trace\"{(first ? " open" : "")}><summary class=\"trace-meta\">")
                .Append($"<h3>{E(trace.Summary)}</h3>{pills}")
                .Append($"<span class=\"muted small\">{E(file)}, traced {E(Time(trace.TracedUtc))} UTC</span></summary>");
            first = false;

            if (hops.Count == 0)
            {
                body.Append($"<div class=\"flags\">{Muted("The trace file has no hops.")}</div></details>");
                continue;
            }

            body.Append(Chain(hops));
            body.Append("<div class=\"tbl\" style=\"border-top:1px solid var(--line)\"><table><thead><tr><th>Hop</th><th>From</th>")
                .Append("<th>To</th><th>Time (UTC)</th><th>Account</th><th>Evidence</th><th>Result</th></tr></thead><tbody>");
            foreach (var hop in hops)
            {
                var evidence = string.Join(" / ", new[] { hop.ReceivingEvidence, hop.SendingEvidence }.Where(e => e.Length > 0));
                body.Append("<tr>")
                    .Append($"<td>{E(hop.Number)}</td>")
                    .Append($"<td>{E(hop.Source)}{(hop.FromHost.Length > 0 && hop.SourceIp.Length > 0 ? $"<br><small class=\"mono muted\">{E(hop.SourceIp)}</small>" : "")}</td>")
                    .Append($"<td>{E(hop.ToHost)}</td>")
                    .Append($"<td class=\"mono\">{E(hop.Time)}</td>")
                    .Append($"<td>{E(hop.Account)}</td>")
                    .Append($"<td class=\"wrap muted\">{E(evidence)}</td>")
                    .Append($"<td>{ResultPill(hop.Result)}</td>")
                    .Append("</tr>");
            }
            body.Append("</tbody></table></div>");

            var notes = hops.SelectMany(h => h.Flags.Select(f => (h.Number, Text: f)))
                            .Concat(hops.Where(h => h.NextStep.Length > 0).Select(h => (h.Number, Text: "Next: " + h.NextStep)))
                            .ToList();
            if (notes.Count > 0)
                body.Append("<div class=\"flags\">")
                    .Append(string.Concat(notes.Select(n => $"<div>{Pill("Hop " + n.Number, "plain")} {E(n.Text)}</div>")))
                    .Append("</div>");
            body.Append("</details>");
        }

        if (toCollect.Count > 0)
            findings.Add(new ReportFinding(FindingLevel.Medium, N(toCollect.Count), Plural(toCollect.Count, "Host to collect next", "Hosts to collect next"),
                string.Join(", ", toCollect.Take(3)) + (toCollect.Count > 3 ? $" and {toCollect.Count - 3} more" : ""), "rdp"));
        if (stale > 0)
            findings.Add(new ReportFinding(FindingLevel.Medium, N(stale), Plural(stale, "RDP trace out of date", "RDP traces out of date"),
                "Hosts were reprocessed or added since; trace again to include them", "rdp"));

        return new ReportSection
        {
            Id = "rdp", Title = "RDP traces", Count = N(saved.Count), Source = source,
            Body = body.ToString(), Findings = findings
        };
    }

    /// <summary>Origin on the left, the host the trace started from on the right.</summary>
    private static string Chain(IReadOnlyList<Hop> hops)
    {
        var origin = hops[hops.Count - 1];
        var originClass = origin.Result == RdpTrace.EndOfChain ? " ext" : origin.Result == RdpTrace.CollectNext ? " collect" : "";
        var originNote = origin.Result == RdpTrace.EndOfChain ? (IsExternal(origin.SourceIp) ? "External" : "End of chain")
                       : origin.Result == RdpTrace.CollectNext ? "Not in the case" : "";
        var chain = new StringBuilder("<div class=\"chain-wrap\"><div class=\"chain\">")
            .Append($"<div class=\"node{originClass}\"><b class=\"mono\">{E(origin.Source)}</b><small>{E(originNote)}</small></div>");
        for (var i = hops.Count - 1; i >= 0; i--)
        {
            var hop = hops[i];
            var start = i == 0;
            chain.Append($"<div class=\"arrow\"><span>{E(ShortTime(hop.Time))}, {E(hop.Account)}</span><span class=\"ln\"></span>{ResultPill(hop.Result)}</div>")
                 .Append($"<div class=\"node{(start ? " start" : "")}\"><b>{E(hop.ToHost)}</b><small>{(start ? "Start" : "")}</small></div>");
        }
        return chain.Append("</div></div>").ToString();
    }

    private static string ShortTime(string time) => time.Length >= 16 ? time[5..16] : time;

    private static string ResultPill(string result) => result switch
    {
        RdpTrace.Confirmed => Pill(result, "ok"),
        RdpTrace.Inferred => Pill(result, "low"),
        RdpTrace.CollectNext => Pill(result, "med"),
        RdpTrace.EndOfChain => Pill(result, "crit"),
        _ => Pill(result, "plain")
    };

    private static bool IsExternal(string address) =>
        IPAddress.TryParse(address, out var ip) && !IPAddress.IsLoopback(ip) && !RdpTrace.IsInternal(ip);

    private static List<Hop> ReadHops(string path)
    {
        var hops = new List<Hop>();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return hops;
        var index = header.Select((name, i) => (name: name.Trim(), i))
                          .GroupBy(p => p.name, StringComparer.OrdinalIgnoreCase)
                          .ToDictionary(g => g.Key, g => g.First().i, StringComparer.OrdinalIgnoreCase);

        while (reader.ReadRecord() is { } fields)
        {
            string Cell(string name) => index.TryGetValue(name, out var i) && i < fields.Count ? fields[i].Trim() : "";
            if (Cell("Hop").Length == 0) continue;
            hops.Add(new Hop(Cell("Hop"), Cell("Result"), Cell("ToHost"), Cell("TimeUtc"), Cell("Account"), Cell("SourceIp"),
                             Cell("ClientName"), Cell("FromHost"), Cell("ReceivingEvidence"), Cell("SendingEvidence"),
                             Cell("Flags").Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries),
                             Cell("NextStep")));
        }
        return hops;
    }
}
