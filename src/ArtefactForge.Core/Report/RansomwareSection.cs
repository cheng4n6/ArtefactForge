using System.Globalization;
using System.Text;
using ArtefactForge.Core.Windows;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// The case's Ransomware.csv: one row per host with its extension, note and encryption window,
/// each window drawn as a bar on one time axis so hosts can be compared at a glance.
/// </summary>
internal sealed class RansomwareSection : ICaseReportSection
{
    public ReportSection? Build(CaseReportContext context)
    {
        var rows = Ransomware.Load(context.CaseDirectory);
        if (rows.Count == 0) return null;   // no Windows host with MFTECmd output: nothing to say

        const string source = "Ransomware.csv, from each host's MFTECmd $MFT and USN journal output. "
                              + "Confirm or correct a host in Ransomware-Overrides.csv.";
        var found = rows.Where(r => r.IsFound).ToList();
        if (found.Count == 0)
            return new ReportSection
            {
                Id = "ransomware", Title = "Ransomware", Count = "0", Source = source,
                Body = Empty($"No encrypted files or ransom note found on the {rows.Count(r => r.Status == RansomwareFinding.NoneFound)} "
                             + "hosts checked. " + NotChecked(rows))
            };

        var windows = found.Where(r => r.StartUtc is not null && r.FinishUtc is not null).ToList();
        var axisStart = windows.Count > 0 ? windows.Min(r => r.StartUtc!.Value) : DateTime.MinValue;
        var axisEnd = windows.Count > 0 ? windows.Max(r => r.FinishUtc!.Value) : DateTime.MinValue;
        var span = Math.Max(1, (axisEnd - axisStart).TotalSeconds);

        var body = new StringBuilder("<div class=\"box tbl\"><table><thead><tr><th>Host</th><th>Extension</th><th>Note</th>")
            .Append("<th>Start (UTC)</th><th>Finish (UTC)</th><th>Files</th><th>Encryption window</th></tr></thead><tbody>");
        foreach (var r in rows.OrderBy(r => r.IsFound ? 0 : 1).ThenBy(r => r.StartUtc ?? DateTime.MaxValue).ThenBy(r => r.Host))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            // The detail goes on a line of its own under the host, as it can run to a few sentences.
            var detail = r.Differences.Length > 0 || r.Detail.Length > 0;
            var td = detail ? "<td style=\"border-bottom:0\"" : "<td";
            body.Append($"<tr>{td}><b>{E(r.Host.Length > 0 ? r.Host : r.Collection)}</b></td>");
            if (!r.IsFound)
            {
                var kind = r.Status == RansomwareFinding.NoneFound ? "ok" : r.Status == RansomwareFinding.FailedStatus ? "high" : "plain";
                body.Append($"{td} colspan=\"6\">{Pill(r.Status, kind)}</td></tr>");
                AppendDetail(body, r);
                continue;
            }

            body.Append($"{td} class=\"mono\">{E(r.Extension)}{Basis(r.ExtensionBasis)}</td>")
                .Append($"{td} class=\"mono\">{E(r.NoteName)}{Basis(r.NoteBasis)}")
                .Append(r.NoteSize is { } size ? $"<br>{Muted($"{N(size)} bytes in {N(r.NoteFolders)} {Plural(r.NoteFolders, "folder", "folders")}")}" : "")
                .Append("</td>")
                .Append($"{td} class=\"mono\">{E(Time(r.StartUtc))}{(r.StartIsEarliestSeen ? "<br>" + Pill("Earliest seen", "med") : "")}</td>")
                .Append($"{td} class=\"mono\">{E(Time(r.FinishUtc))}</td>")
                .Append($"{td}>{N(r.FilesAffected)}")
                .Append(r.PeakPerMinute is { } peak ? $"<br>{Muted($"up to {N(peak)} a minute")}" : "")
                .Append($"</td><td style=\"{(detail ? "border-bottom:0;" : "")}min-width:220px;width:30%\">");
            if (r.StartUtc is { } start && r.FinishUtc is { } finish)
            {
                var left = (start - axisStart).TotalSeconds / span * 100;
                var width = Math.Max(0.8, (finish - start).TotalSeconds / span * 100);
                body.Append("<div style=\"position:relative;height:10px;border-radius:5px;background:var(--bg);min-width:200px\">")
                    .Append($"<span title=\"{E(Time(start))} to {E(Time(finish))} UTC\" style=\"position:absolute;top:0;bottom:0;")
                    .Append($"left:{Pct(Math.Min(left, 99.2))};width:{Pct(Math.Min(width, 100 - Math.Min(left, 99.2)))};")
                    .Append("border-radius:5px;background:var(--crit)\"></span></div>")
                    .Append($"<span class=\"small\">{E(r.Source)}</span>");
            }
            body.Append("</td></tr>");
            AppendDetail(body, r);
        }
        body.Append("</tbody></table></div>");
        if (windows.Count > 0)
            body.Append($"<p class=\"muted small\">Bars share one axis, {E(Time(axisStart))} to {E(Time(axisEnd))} UTC. {E(NotChecked(rows))}</p>");

        var first = found.Where(r => r.StartUtc is not null).OrderBy(r => r.StartUtc).FirstOrDefault();
        var headline = found.Select(r => r.Extension).FirstOrDefault(e => e.Length > 0)
                       ?? found.Select(r => r.NoteName).First(n => n.Length > 0);
        var finding = new ReportFinding(FindingLevel.Critical, headline,
            $"Ransomware on {found.Count} of {rows.Count(r => r.Status is RansomwareFinding.Found or RansomwareFinding.NoneFound)} hosts checked",
            first is null ? "See the Ransomware section" : $"First seen on {first.Host} at {Time(first.StartUtc)} UTC", "ransomware");

        return new ReportSection
        {
            Id = "ransomware", Title = "Ransomware", Count = N(found.Count), Source = source,
            Body = body.ToString(), Findings = [finding]
        };
    }

    private static void AppendDetail(StringBuilder body, RansomwareFinding r)
    {
        if (r.Differences.Length == 0 && r.Detail.Length == 0) return;
        body.Append("<tr><td></td><td colspan=\"6\" class=\"wrap small\" style=\"padding-top:0\">");
        if (r.Differences.Length > 0) body.Append(Pill("Differs", "high")).Append(' ').Append(E(r.Differences)).Append("<br>");
        body.Append(Muted(r.Detail)).Append("</td></tr>");
    }

    private static string Basis(string basis) =>
        basis is RansomwareFinding.Detected or "" ? "" : " " + Pill(basis, basis == RansomwareFinding.Swept ? "med" : "plain");

    private static string Join(string a, string b) => a.Length == 0 ? b : b.Length == 0 ? a : a + "; " + b;

    private static string Pct(double value) => value.ToString("0.##", CultureInfo.InvariantCulture) + "%";

    private static string NotChecked(IReadOnlyList<RansomwareFinding> rows)
    {
        var count = rows.Count(r => r.Status == RansomwareFinding.NotChecked);
        return count == 0 ? "" : $"{count} {Plural(count, "host was", "hosts were")} not checked, as they have no MFTECmd output.";
    }
}
