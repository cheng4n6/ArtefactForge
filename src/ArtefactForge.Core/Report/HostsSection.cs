using System.Globalization;
using System.Net;
using System.Net.Sockets;
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
        var repeated = context.Machines.Where(m => m.Count > 1).ToList();
        var collections = repeated.SelectMany(m => m.Select(h => (h.Collection, m.Count)))
            .ToDictionary(c => c.Collection, c => c.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var host in context.Hosts)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var role = host.Role.Length > 0 ? Pill(host.Role, "plain")
                     : host.IsLinux ? Pill("Linux", "plain")
                     : Muted("Not known");
            var os = host.OperatingSystem.Length > 0 ? E(host.OperatingSystem) : Muted("No system summary");

            var sources = ReadSources(host, out var sourcesProblem);
            context.Runs.TryGetValue(host.Collection, out var run);
            var collector = run?.Collector;

            string processed, modules;
            if (run is not null)
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
                .Append(collections.TryGetValue(host.Collection, out var times) ? "<br>" + Pill($"Collected {times} times", "med") : "")
                .Append("</td>")
                .Append($"<td>{role}</td><td>{os}</td><td class=\"mono\">{AddressList(host.Addresses, a => Ip(context, a))}</td>")
                .Append($"<td>{TimeZone(host, collector)}</td>")
                .Append($"<td class=\"mono\">{LastBoot(host, collector, sources)}</td>")
                .Append($"<td class=\"mono\">{Collected(collector)}</td>")
                .Append(processed)
                .Append($"<td>{modules}</td>")
                .Append($"<td class=\"mono\">{SecurityLog(host, sources, sourcesProblem, gaps)}</td>")
                .Append($"<td>{gapCell}</td>")
                .Append($"<td>{Levels(context, host)}</td>")
                .Append("</tr>");
        }

        var findings = new List<ReportFinding>();
        if (gaps.Count > 0)
            findings.Add(new ReportFinding(FindingLevel.Medium, N(gaps.Count), Plural(gaps.Count, "Coverage gap", "Coverage gaps"),
                string.Join("; ", gaps.Take(2)) + (gaps.Count > 2 ? $"; and {gaps.Count - 2} more" : ""), "hosts"));
        // A machine with a row per collection: say so, so the analyst knows why its detections are
        // counted once and can check which collection is the one they meant to keep.
        if (repeated.Count > 0)
            findings.Add(new ReportFinding(FindingLevel.Medium, N(repeated.Count), "Collected more than once",
                string.Join("; ", repeated.Take(2).Select(m => $"{m[0].Name} in {string.Join(", ", m.Select(h => h.Collection))}"))
                + (repeated.Count > 2 ? $"; and {repeated.Count - 2} more" : "")
                + ". Detections are counted once per host.", "hosts"));

        var body = new StringBuilder()
            .Append("<div class=\"box tbl\"><table><thead><tr><th>Host</th><th>Role</th><th>OS</th><th>IP</th>")
            .Append("<th>Time zone</th><th>Last boot (UTC)</th><th>Collected (UTC)</th>")
            .Append("<th>Processed (UTC)</th><th>Modules</th><th>Security log covers</th><th>Collection gaps</th><th>Detections</th>")
            .Append("</tr></thead><tbody>").Append(rows).Append("</tbody></table></div>")
            .Append("<div class=\"legend\"><span><i class=\"s-crit\"></i>Critical</span><span><i class=\"s-high\"></i>High</span>")
            .Append("<span><i class=\"s-med\"></i>Medium</span><span><i class=\"s-low\"></i>Low</span>")
            .Append("<span>Collection gaps are artefacts listed in the host's system summary as not collected.</span>")
            .Append("<span>Hover a time zone, boot or collection time for where it came from.</span>")
            .Append(repeated.Count > 0
                ? "<span>A host collected more than once has a row per collection; its detections are counted once.</span>"
                : "")
            .Append("</div>");

        return new ReportSection
        {
            Id = "hosts", Title = "Hosts", Count = N(context.Machines.Count),
            Source = "From each host's system summary, the last run that processed it and its event log output",
            Body = body.ToString(),
            Findings = findings
        };
    }

    private const int AddressesShown = 3;

    /// <summary>
    /// The host's addresses one per line in numeric order, IPv4 before IPv6. Past three, the rest
    /// fold away behind "N more" so a host with many adapters does not stretch its row.
    /// </summary>
    internal static string AddressList(string addresses, Func<string, string>? show = null)
    {
        show ??= E;
        var sorted = addresses.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(a => (Text: a, Ip: IPAddress.TryParse(a, out var ip) ? ip : null))
            .OrderBy(a => a.Ip is null ? 2 : a.Ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ThenBy(a => a.Ip is null ? a.Text : Convert.ToHexString(a.Ip.GetAddressBytes()), StringComparer.Ordinal)
            .Select(a => a.Text)
            .ToList();
        if (sorted.Count == 0) return "";

        string Lines(IEnumerable<string> list) => string.Join("<br>", list.Select(show));
        if (sorted.Count <= AddressesShown) return Lines(sorted);
        var rest = sorted.Count - AddressesShown;
        return Lines(sorted.Take(AddressesShown))
               + $"<details class=\"more\"><summary>{rest} more</summary>{Lines(sorted.Skip(AddressesShown))}</details>";
    }

    /// <summary>The host's remote access sources file: which logs it read and the time each covers. Null when there is none.</summary>
    private static List<RemoteAccess.SourceRow>? ReadSources(ReportHost host, out bool problem)
    {
        problem = false;
        if (!host.IsWindows) return null;
        var path = Path.Combine(host.Directory, RemoteAccess.Folder, RemoteAccess.SourcesFileName);
        if (!File.Exists(path)) return null;
        try { return RemoteAccess.ReadSources(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problem = true;
            return null;
        }
    }

    /// <summary>A time with where it came from on hover, and "Approx" beside an estimate.</summary>
    private static string Sourced(DateTime time, string from, bool approx = false) =>
        $"<span title=\"{E("From " + from)}\">{E(Time(time))}</span>"
        + (approx ? $" <span class=\"pill p-plain\" title=\"{E("An estimate: " + from)}\">Approx</span>" : "");

    /// <summary>When the collection was made, as its collector recorded it during the run that processed it.</summary>
    private static string Collected(CollectorTimes? collector) =>
        collector?.CollectedUtc is { } at
            ? Sourced(at, collector.CollectedFrom, collector.CollectedApprox)
            : $"<span title=\"Recorded from 0.5.0 on, from Velociraptor, UAC and KAPE collections, zips and live systems. Process the host again to record it.\">{Muted("Not recorded")}</span>";

    /// <summary>
    /// The host's time zone: the system's own setting from its summary (on Windows with the offset
    /// in effect when the registry was last written), else what the collector saw.
    /// </summary>
    private static string TimeZone(ReportHost host, CollectorTimes? collector)
    {
        var zone = host.Fact("Timezone");
        if (zone.Length > 0)
        {
            var from = "the system summary";
            // ActiveTimeBias is minutes to add to local time for UTC. RECmd can print a negative
            // DWORD as its unsigned value.
            if (long.TryParse(host.Fact("TimezoneActiveBiasMinutes"), out var bias))
            {
                if (bias > int.MaxValue) bias -= 1L << 32;
                if (Math.Abs(bias) <= 24 * 60)
                {
                    zone += $" ({CollectorTimesReader.Offset(TimeSpan.FromMinutes(-bias))})";
                    from += "; the offset is the one in effect when the registry was last written (ActiveTimeBias)";
                }
            }
            return $"<span title=\"{E("From " + from)}\">{E(zone)}</span>";
        }
        if (collector is { TimeZone.Length: > 0 })
            return $"<span title=\"{E("From " + collector.TimeZoneFrom)}\">{E(collector.TimeZone)}</span>";
        return Muted("Not recorded");
    }

    /// <summary>
    /// When the host last started: the collector's record of the running system, else the Linux
    /// summary's last wtmp boot, else the newest boot event in the Windows System log.
    /// </summary>
    private static string LastBoot(ReportHost host, CollectorTimes? collector, List<RemoteAccess.SourceRow>? sources)
    {
        if (collector?.BootUtc is { } boot) return Sourced(boot, collector.BootFrom);
        if (Windows.IpHistoryRecord.ParseTime(host.Fact("LastBootUtc")) is { } wtmp)
            return Sourced(wtmp, "the system summary (wtmp)");
        var boots = sources?.FirstOrDefault(s => s.Log == RemoteAccess.BootRow);
        if (boots is { Status: "used", Last: { } last })
            return Sourced(last, $"the newest of {N(boots.Events)} boot events in the System log (Kernel-General 12, EventLog 6005)");
        if (boots is not null) return Muted("No boot events");
        return Muted("Not recorded");
    }

    /// <summary>How far back the host's Security log reaches, from the remote access sources file.</summary>
    private static string SecurityLog(ReportHost host, List<RemoteAccess.SourceRow>? sources, bool problem, List<string> gaps)
    {
        if (!host.IsWindows) return Muted("Not Windows");
        if (problem) return Pill("Could not read", "med");
        if (sources is null) return Muted("Not read yet");

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
