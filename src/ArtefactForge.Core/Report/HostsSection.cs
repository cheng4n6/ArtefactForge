using System.Globalization;
using System.Text;
using ArtefactForge.Core.Windows;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// Every host in the case: what it is, when it was processed and how that went, how far back its
/// Security log reaches, and its detections by level. Missing logs, cleared logs and artefacts the
/// collection did not contain are raised as coverage gaps.
/// </summary>
internal sealed class HostsSection : ICaseReportSection
{
    public ReportSection Build(CaseReportContext context)
    {
        if (context.Hosts.Count == 0)
            return new ReportSection
            {
                Id = "hosts", Title = "Hosts", Count = "0",
                Body = Empty("No hosts have been processed into this case folder yet.")
            };

        var rows = new StringBuilder();
        var gaps = new List<string>();
        foreach (var host in context.Hosts)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var role = host.Role.Length > 0 ? Pill(host.Role, "plain")
                     : host.IsLinux ? Pill("Linux", "plain")
                     : Muted("Not known");
            var os = host.OperatingSystem.Length > 0 ? E(host.OperatingSystem) : Muted("No system summary");

            string processed, modules;
            if (context.Runs.TryGetValue(host.Collection, out var run))
            {
                processed = $"<td class=\"mono\">{E(run.ProcessedUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))}</td>";
                modules = $"{run.Completed} ok, {run.Skipped} skipped"
                          + (run.NeedsReview > 0 ? " " + Pill($"{run.NeedsReview} to review", "high") : "");
            }
            else
            {
                processed = $"<td>{Muted("Not recorded")}</td>";
                modules = Muted("Processed before the report existed");
            }

            if (host.CollectionGaps > 0)
                gaps.Add($"{host.Name} collection is missing {host.CollectionGaps} {Plural(host.CollectionGaps, "artefact", "artefacts")}");
            var gapCell = host.CollectionGaps > 0 ? Pill(N(host.CollectionGaps), "med") : Muted("0");

            rows.Append("<tr>")
                .Append($"<td><b>{E(host.Name)}</b>")
                .Append(host.Name.Equals(host.Collection, StringComparison.OrdinalIgnoreCase) ? "" : $"<br><small class=\"muted\">{E(host.Collection)}</small>")
                .Append("</td>")
                .Append($"<td>{role}</td><td>{os}</td><td class=\"mono\">{E(host.Addresses)}</td>")
                .Append(processed)
                .Append($"<td>{modules}</td>")
                .Append($"<td class=\"mono\">{SecurityLog(host, gaps)}</td>")
                .Append($"<td>{gapCell}</td>")
                .Append($"<td>{Levels(context, host)}</td>")
                .Append("</tr>");
        }

        var findings = new List<ReportFinding>();
        if (gaps.Count > 0)
            findings.Add(new ReportFinding(FindingLevel.Medium, N(gaps.Count), Plural(gaps.Count, "Coverage gap", "Coverage gaps"),
                string.Join("; ", gaps.Take(2)) + (gaps.Count > 2 ? $"; and {gaps.Count - 2} more" : ""), "hosts"));

        var body = new StringBuilder()
            .Append("<div class=\"box tbl\"><table><thead><tr><th>Host</th><th>Role</th><th>OS</th><th>IP</th>")
            .Append("<th>Processed (UTC)</th><th>Modules</th><th>Security log covers</th><th>Collection gaps</th><th>Detections</th>")
            .Append("</tr></thead><tbody>").Append(rows).Append("</tbody></table></div>")
            .Append("<div class=\"legend\"><span><i class=\"s-crit\"></i>Critical</span><span><i class=\"s-high\"></i>High</span>")
            .Append("<span><i class=\"s-med\"></i>Medium</span><span><i class=\"s-low\"></i>Low</span>")
            .Append("<span>Collection gaps are artefacts listed in the host's system summary as not collected.</span></div>");

        return new ReportSection
        {
            Id = "hosts", Title = "Hosts", Count = N(context.Hosts.Count),
            Source = "From each host's system summary, the last run that processed it and its event log output",
            Body = body.ToString(),
            Findings = findings
        };
    }

    /// <summary>How far back the host's Security log reaches, from the remote access sources file.</summary>
    private static string SecurityLog(ReportHost host, List<string> gaps)
    {
        if (!host.IsWindows) return Muted("Not Windows");
        var path = Path.Combine(host.Directory, RemoteAccess.Folder, RemoteAccess.SourcesFileName);
        if (!File.Exists(path)) return Muted("Not read yet");

        List<RemoteAccess.SourceRow> sources;
        try { sources = RemoteAccess.ReadSources(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Pill("Could not read", "med");
        }

        var security = sources.FirstOrDefault(s => s.Log == RemoteAccess.SecurityLog);
        if (security is null || security.Status != "used")
        {
            var what = security is null ? "No event log output" : "No Security log";
            gaps.Add($"{host.Name}: {what.ToLowerInvariant()}");
            return Pill(what, "med");
        }

        var text = E($"{Day(security.First)} to {Day(security.Last)}");
        if (security.Cleared.Count == 0) return text;
        var cleared = string.Join(", ", security.Cleared.Order().Select(t => Time(t)));
        gaps.Add($"{host.Name} Security log cleared {cleared}");
        return text + " " + Pill("Cleared " + cleared, "crit");
    }

    /// <summary>A bar of the host's detection hits by level, with the counts in its tooltip.</summary>
    private static string Levels(CaseReportContext context, ReportHost host)
    {
        var detections = context.Detections.GetValueOrDefault(host.Collection) ?? HostDetections.None;
        if (detections.Tools.Count == 0) return Muted("Not run");
        var problem = detections.Problems.Count > 0 ? " " + Pill("Could not read all", "med") : "";

        var rules = context.RatedDetections.GetValueOrDefault(host.Collection) ?? Array.Empty<RuleHits>();
        string[] levels = [DetectionSummary.Critical, DetectionSummary.High, DetectionSummary.Medium, DetectionSummary.Low];
        string[] classes = ["crit", "high", "med", "low"];
        var counts = levels.Select(l => rules.Where(r => r.Level == l).Sum(r => (long)r.Hits)).ToArray();
        var total = counts.Sum();
        if (total == 0) return Muted("None above informational") + problem;

        var title = string.Join(", ", levels.Select((l, i) => $"{N(counts[i])} {l.ToLowerInvariant()}"));
        var bar = new StringBuilder($"<div class=\"stack\" title=\"{E(title)}\" aria-label=\"{E(title)}\">");
        for (var i = 0; i < levels.Length; i++)
            if (counts[i] > 0)
                bar.Append($"<span class=\"s-{classes[i]}\" style=\"width:{Math.Max(2.0, counts[i] * 100.0 / total).ToString("0.#", CultureInfo.InvariantCulture)}%\"></span>");
        return bar.Append("</div>").ToString() + problem;
    }
}
