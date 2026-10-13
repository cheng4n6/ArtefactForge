using System.Text;
using ArtefactForge.Core.Ioc;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// The case's IOC list with what the sweeps found: one expandable row per IOC with the hosts it
/// was found on, and its hits with the matching text marked.
/// </summary>
internal sealed class IocSection : ICaseReportSection
{
    // Enough to read on the page; the full list is in IocHits.csv.
    private const int MaxHitsShown = 200;

    private sealed class Found
    {
        public readonly List<IocHit> Shown = [];
        public readonly SortedSet<string> Hosts = new(StringComparer.OrdinalIgnoreCase);
        public long Hits;
    }

    public ReportSection Build(CaseReportContext context)
    {
        const string source = "From IOCs.csv and IocHits.csv. Add or remove IOCs in the app, on Analysis > IOCs.";
        var caseDirectory = context.CaseDirectory;
        if (!IocList.Exists(caseDirectory))
            return new ReportSection
            {
                Id = "iocs", Title = "IOC hits", Source = source,
                Body = Empty("No IOC list for this case yet. IOCs added in the app, on Analysis > IOCs, are searched for across every host's output.")
            };

        var iocs = IocList.Load(caseDirectory);
        var found = new Dictionary<string, Found>(StringComparer.Ordinal);
        foreach (var hit in IocSweep.ReadHits(IocSweep.HitsPathFor(caseDirectory)))
        {
            var key = IocList.KeyFor(hit.IocType, hit.Ioc);
            if (!found.TryGetValue(key, out var f)) found[key] = f = new Found();
            f.Hits++;
            f.Hosts.Add(hit.Host);
            if (f.Shown.Count < MaxHitsShown) f.Shown.Add(hit);
        }

        var body = new StringBuilder();
        if (IocSweep.LastResult(caseDirectory) is { } last) body.Append($"<p class=\"muted\">Last sweep: {E(last)}</p>");
        if (iocs.Count == 0)
        {
            body.Append(Empty("The IOC list is empty."));
            return new ReportSection { Id = "iocs", Title = "IOC hits", Count = "0", Source = source, Body = body.ToString() };
        }

        // IOCs with hits first, most hits first; then the rest in list order.
        var ordered = iocs.Select((ioc, i) => (ioc, i, f: found.GetValueOrDefault(ioc.Key)))
                          .OrderByDescending(x => x.f?.Hits ?? 0)
                          .ThenBy(x => x.i)
                          .ToList();

        body.Append("<div class=\"box\">");
        var first = true;
        foreach (var (ioc, _, f) in ordered)
        {
            var hits = f?.Hits ?? 0;
            var tags = !ioc.IsSweepable ? Pill("Not searched: type not recognised", "med")
                     : hits == 0 ? Pill("No hits", "ok")
                     : string.Concat(f!.Hosts.Select(h => Pill(h, "plain")));
            var note = ioc.Note.Length > 0 ? " - " + ioc.Note : "";
            body.Append($"<details class=\"ioc\"{(first && hits > 0 ? " open" : "")}><summary>")
                .Append($"<span class=\"t\">{E(ioc.TypeLabel)}</span>")
                .Append($"<span class=\"v\">{E(ioc.Value)}</span>")
                .Append($"<button class=\"copy\" type=\"button\" data-copy=\"{E(ioc.Value)}\">Copy</button>")
                .Append($"<span class=\"n\">{N(hits)} {Plural(hits, "hit", "hits")}{E(note)}</span>")
                .Append($"<span class=\"r\">{tags}</span></summary>");
            first = false;

            if (f is not null && f.Shown.Count > 0)
            {
                body.Append("<div class=\"inner tbl\"><table><thead><tr><th>Host</th><th>Source</th><th>Time (UTC)</th>")
                    .Append("<th>Matching line</th></tr></thead><tbody>");
                foreach (var hit in f.Shown)
                    body.Append("<tr>")
                        .Append($"<td><b>{E(hit.Host)}</b></td>")
                        .Append($"<td title=\"{E(hit.OutputFile)} line {hit.LineNumber}\">{E(hit.Module)}</td>")
                        .Append($"<td class=\"mono\">{E(hit.Time)}</td>")
                        .Append($"<td class=\"mono wrap\">{Mark(hit.MatchingLine, ioc.Value)}</td>")
                        .Append("</tr>");
                body.Append("</tbody></table>");
                if (f.Hits > f.Shown.Count)
                    body.Append($"<p class=\"muted\">The first {N(f.Shown.Count)} of {N(f.Hits)} hits. Every hit is in IocHits.csv.</p>");
                body.Append("</div>");
            }
            body.Append("</details>");
        }
        body.Append("</div>");

        var sweepable = iocs.Count(i => i.IsSweepable);
        var withHits = iocs.Count(i => found.ContainsKey(i.Key));
        var totalHits = found.Values.Sum(f => f.Hits);
        var hosts = found.Values.SelectMany(f => f.Hosts).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var findings = new List<ReportFinding>();
        if (totalHits > 0)
            findings.Add(new ReportFinding(FindingLevel.High, N(totalHits),
                $"IOC {Plural(totalHits, "hit", "hits")} on {hosts} {Plural(hosts, "host", "hosts")}",
                $"{withHits} of {sweepable} {Plural(sweepable, "IOC", "IOCs")} found"
                + (sweepable - withHits > 0 ? $", {sweepable - withHits} with no hits" : ""), "iocs"));

        return new ReportSection
        {
            Id = "iocs", Title = "IOC hits", Count = N(totalHits), Source = source,
            Body = body.ToString(), Findings = findings
        };
    }
}
