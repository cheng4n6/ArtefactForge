using System.Globalization;
using System.Text;
using System.Text.Json;
using ArtefactForge.Core.Ioc;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>What a rebuild or snapshot did, for the app's status line, the CLI and the log.</summary>
public sealed record CaseReportResult(bool Written, string? Path, string Message)
{
    public string Describe() => Message;
}

/// <summary>
/// CaseReport.html in the case folder: one static, offline page that pulls together what the
/// case's summary files say (hosts, detections, IOC hits, RDP traces, IP history), with the
/// findings that most need a look at the top.
///
/// It is derived, never edited: rebuilt from the files after every run, IOC sweep and RDP trace,
/// so rebuilding loses nothing. "Export snapshot" writes a dated copy that is never touched again,
/// for sending. The page needs no server and no internet: styles and scripts are inline and the
/// fonts are the system's.
/// </summary>
public static class CaseReport
{
    public const string FileName = "CaseReport.html";
    private const string SnapshotPrefix = "CaseReport_";
    private const string LogName = "CaseReport.log";
    private const string RunsFileName = "Hosts.json";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    // Two rebuilds at once (a sweep finishing as a trace is saved) would race on the file.
    private static readonly object Gate = new();

    /// <summary>
    /// The report's sections, in page order. A later analysis adds its own here; each is built
    /// on its own, so one that fails shows its error in place and the rest of the report stands.
    /// </summary>
    public static IReadOnlyList<ICaseReportSection> Sections { get; } =
    [
        new HostsSection(),
        new DetectionsSection(),
        new RansomwareSection(),
        new IocSection(),
        new RdpSection(),
        new IpHistorySection()
    ];

    public static string PathFor(string caseDirectory) => Path.Combine(caseDirectory, FileName);

    /// <summary>
    /// The post-run step: records how the run went for each host it processed, then rebuilds the
    /// report. Never throws: a report that cannot be written is logged, and the run's own result
    /// stands.
    /// </summary>
    public static CaseReportResult AfterRun(RunReport report)
    {
        try
        {
            RecordRun(report);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            TryLog(report.CaseDirectory, "Could not record the run for the case report: " + ex.Message);
        }
        return Rebuild(report.CaseDirectory);
    }

    /// <summary>Rebuilds CaseReport.html from the case's files. Never throws for a problem with the case's files.</summary>
    public static CaseReportResult Rebuild(string caseDirectory, CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(caseDirectory))
            return new CaseReportResult(false, null, $"No case report: {caseDirectory} does not exist yet.");

        var path = PathFor(caseDirectory);
        try
        {
            lock (Gate)
            {
                var (html, hosts) = Render(caseDirectory, DateTime.UtcNow, snapshot: false, cancellationToken);
                AtomicFile.WriteAllText(path, html);
                var result = new CaseReportResult(true, path,
                    $"Case report rebuilt for {hosts} {Plural(hosts, "host", "hosts")}: {FileName}.");
                TryLog(caseDirectory, result.Message);
                return result;
            }
        }
        catch (OperationCanceledException)
        {
            return new CaseReportResult(false, path, "The case report was not rebuilt: stopped.");
        }
        catch (Exception ex)
        {
            // A boundary: the run, sweep or trace that asked for the report has already finished,
            // and a report that cannot be built must not undo that. It is logged and reported.
            var result = new CaseReportResult(false, path, $"The case report could not be rebuilt: {ex.Message}");
            TryLog(caseDirectory, result.Message);
            return result;
        }
    }

    /// <summary>
    /// Writes a dated copy, CaseReport_yyyy-MM-dd_HHmm.html, that is never rebuilt or replaced.
    /// A second snapshot in the same minute is saved beside it as _2, _3.
    /// </summary>
    public static CaseReportResult ExportSnapshot(string caseDirectory, DateTime? nowUtc = null,
                                                  CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(caseDirectory))
            return new CaseReportResult(false, null, $"No snapshot: {caseDirectory} does not exist yet.");

        var now = nowUtc ?? DateTime.UtcNow;
        var stem = SnapshotPrefix + now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture);
        var path = Path.Combine(caseDirectory, stem + ".html");
        for (var n = 2; File.Exists(path); n++) path = Path.Combine(caseDirectory, $"{stem}_{n}.html");

        try
        {
            lock (Gate)
            {
                var (html, _) = Render(caseDirectory, now, snapshot: true, cancellationToken);
                using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
                    writer.Write(html);
            }
            var result = new CaseReportResult(true, path, $"Snapshot saved as {Path.GetFileName(path)}.");
            TryLog(caseDirectory, result.Message);
            return result;
        }
        catch (OperationCanceledException)
        {
            return new CaseReportResult(false, null, "No snapshot was saved: stopped.");
        }
        catch (Exception ex)
        {
            // As for a rebuild: reported to the analyst, never thrown at the app.
            return new CaseReportResult(false, null, $"The snapshot could not be saved: {ex.Message}");
        }
    }

    /// <summary>The last rebuild's one-line result from the case's report log, if there has been one.</summary>
    public static string? LastResult(string caseDirectory)
    {
        var path = Path.Combine(caseDirectory, "_Logs", LogName);
        try
        {
            if (!File.Exists(path)) return null;
            return File.ReadLines(path).LastOrDefault(l => l.Length > 0);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    // --- page ---------------------------------------------------------------------------------------

    /// <summary>The page, and the number of hosts in it.</summary>
    internal static (string Html, int Hosts) Render(string caseDirectory, DateTime nowUtc, bool snapshot,
                                                   CancellationToken cancellationToken)
    {
        var facts = SystemInventory.Collect(caseDirectory)
            .ToDictionary(c => c.Collection, c => c.Facts, StringComparer.OrdinalIgnoreCase);
        var hosts = IocSweep.Hosts(caseDirectory)
            .Select(h => new ReportHost(h, Path.Combine(caseDirectory, h),
                facts.TryGetValue(h, out var f) ? f : new Dictionary<string, string>()))
            .ToList();

        var context = new CaseReportContext
        {
            CaseDirectory = caseDirectory,
            Hosts = hosts,
            GeneratedUtc = nowUtc,
            Snapshot = snapshot,
            Runs = ReadRuns(caseDirectory),
            CancellationToken = cancellationToken
        };

        var sections = new List<ReportSection>();
        foreach (var section in Sections)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (section.Build(context) is { } built) sections.Add(built);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                var name = section.GetType().Name.Replace("Section", "");
                sections.Add(new ReportSection
                {
                    Id = name.ToLowerInvariant(), Title = name,
                    Body = $"<div class=\"box empty\">{Pill("Not built", "crit")} This section could not be built: {E(ex.Message)}</div>",
                    Findings = [new ReportFinding(FindingLevel.High, "!", $"{name} section could not be built", ex.Message, name.ToLowerInvariant())]
                });
            }
        }

        return (Page(context, sections), context.Machines.Count);
    }

    private static string Page(CaseReportContext context, IReadOnlyList<ReportSection> sections)
    {
        var html = new StringBuilder();
        html.Append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
            .Append("<meta name=\"generator\" content=\"").Append(E("ArtefactForge " + BuildInfo.Version)).Append("\">")
            .Append("<title>").Append(E(context.CaseName)).Append(" - case report</title>")
            .Append("<style>").Append(ReportPage.Css).Append("</style></head><body>")
            .Append("<div class=\"page\"><nav id=\"nav\" aria-label=\"Sections\"><div class=\"brand\">Case report</div>")
            .Append("<a href=\"#overview\" class=\"on\">Overview</a>");
        foreach (var s in sections)
            html.Append($"<a href=\"#{E(s.Id)}\">{E(s.Title)}")
                .Append(s.Count is null ? "" : $" <span class=\"c\">{E(s.Count)}</span>")
                .Append("</a>");
        html.Append("</nav><main>");

        // --- header
        // Counted by machine: a host collected twice is still one host.
        var machines = context.Machines.Select(m => m[0]).ToList();
        var windows = machines.Count(h => h.IsWindows);
        var linux = machines.Count(h => h.IsLinux);
        var mix = new List<string>();
        if (windows > 0) mix.Add($"{windows} Windows");
        if (linux > 0) mix.Add($"{linux} Linux");
        var other = machines.Count - windows - linux;
        if (other > 0) mix.Add($"{other} not identified");
        var hostLine = $"{machines.Count} {Plural(machines.Count, "host", "hosts")}"
                       + (mix.Count > 0 ? ": " + string.Join(", ", mix) : "")
                       + (context.Hosts.Count > machines.Count ? $" ({context.Hosts.Count} collections)" : "");

        html.Append("<header class=\"case\" id=\"overview\">")
            .Append($"<h1>{E(context.CaseName)}</h1><div class=\"meta\">")
            .Append(context.Snapshot
                ? "<span class=\"live snap\"><i></i>Snapshot: a fixed copy, not updated</span>"
                : "<span class=\"live\"><i></i>Live report, rebuilt after every run, sweep and trace</span>")
            .Append($"<span>{(context.Snapshot ? "Taken" : "Generated")} <b>{E(context.GeneratedUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))} UTC</b></span>")
            .Append($"<span>ArtefactForge <b>{E(BuildInfo.Version)}</b></span>")
            .Append($"<span>{E(hostLine)}</span></div></header>");

        // --- needs attention
        var findings = sections.SelectMany(s => s.Findings).OrderBy(f => f.Level).ToList();
        html.Append("<section aria-labelledby=\"h-key\"><div class=\"sec-head\"><h2 id=\"h-key\">Needs attention</h2>")
            .Append("<span class=\"src\">Highest severity first. Each card links to its section.</span></div>");
        if (findings.Count == 0)
            html.Append("<div class=\"box empty\">Nothing is flagged yet. This lists critical and high detections, IOC hits, ")
                .Append("RDP traces that leave the case and gaps in what was collected, once there are any.</div>");
        else
        {
            html.Append("<div class=\"findings\">");
            foreach (var f in findings)
            {
                var kind = f.Level switch { FindingLevel.Critical => "crit", FindingLevel.High => "high", _ => "med" };
                var big = f.Headline.Length > 12 ? " long" : "";
                html.Append($"<a class=\"finding {kind}\" href=\"#{E(f.SectionId)}\">")
                    .Append($"<span class=\"big{big}\">{E(f.Headline)}</span>")
                    .Append($"<span class=\"lbl\">{E(f.Label)}</span>")
                    .Append($"<span class=\"sub\">{E(f.Detail)}</span></a>");
            }
            html.Append("</div>");
        }
        html.Append("</section>");

        // --- sections
        foreach (var s in sections)
        {
            html.Append($"<section id=\"{E(s.Id)}\" aria-labelledby=\"h-{E(s.Id)}\"><div class=\"sec-head\">")
                .Append($"<h2 id=\"h-{E(s.Id)}\">{E(s.Title)}</h2>")
                .Append(s.Source.Length > 0 ? $"<span class=\"src\">{E(s.Source)}</span>" : "")
                .Append("</div>").Append(s.Body).Append("</section>");
        }

        html.Append("<footer><span>Built from the summary files in the case folder. Nothing in this report is entered by hand, ")
            .Append("so rebuilding it never loses anything; IOCs and traces are kept in their own files.</span>")
            .Append(context.Snapshot
                ? "<span>This snapshot is not updated. The live report is CaseReport.html in the case folder.</span>"
                : "<span>To keep a fixed copy for sending, use Export snapshot in the app.</span>")
            .Append("</footer></main></div>");

        html.Append("<script>").Append(ReportPage.Script);
        foreach (var s in sections.Where(s => s.Script.Length > 0))
            html.Append("\ntry{").Append(s.Script).Append("}catch(e){console.error(e);}");
        html.Append("</script></body></html>\n");
        return html.ToString();
    }

    // --- run record ---------------------------------------------------------------------------------

    private static string RunsPath(string caseDirectory) => Path.Combine(caseDirectory, "_Logs", "CaseReport", RunsFileName);

    private static Dictionary<string, HostRun> ReadRuns(string caseDirectory)
    {
        var path = RunsPath(caseDirectory);
        try
        {
            if (File.Exists(path)
                && JsonSerializer.Deserialize<Dictionary<string, HostRun>>(File.ReadAllText(path)) is { } runs)
                return new Dictionary<string, HostRun>(runs, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            TryLog(caseDirectory, $"Could not read {RunsFileName}, so hosts show no run details: {ex.Message}");
        }
        return new Dictionary<string, HostRun>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Keeps, per host, how the last run that processed it went. The manifest only describes the
    /// latest run, which may have processed one new host out of ten.
    /// </summary>
    private static void RecordRun(RunReport report)
    {
        var hosts = IocSweep.Hosts(report.CaseDirectory).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var ran = report.Results
            .Where(r => r.Module != "Extract" && hosts.Contains(r.Collection))
            .GroupBy(r => r.Collection, StringComparer.OrdinalIgnoreCase)
            // A host whose every module was skipped as already done was not processed by this run.
            .Where(g => g.Any(r => r.Status != WorkStatus.Skipped))
            .ToList();
        if (ran.Count == 0) return;

        var runs = ReadRuns(report.CaseDirectory);
        var now = DateTime.UtcNow;
        foreach (var g in ran)
        {
            var needsReview = g.Count(r => r.Status is WorkStatus.Failed or WorkStatus.NoOutput or WorkStatus.CheckLog
                                                     or WorkStatus.ToolMissing or WorkStatus.TimedOut);
            runs[g.Key] = new HostRun(now, g.Count(r => r.Status == WorkStatus.Completed),
                                      g.Count(r => r.Status == WorkStatus.Skipped), needsReview);
        }

        var path = RunsPath(report.CaseDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        AtomicFile.WriteAllText(path, JsonSerializer.Serialize(runs, Json));
    }

    // --- log ----------------------------------------------------------------------------------------

    private static void Log(string caseDirectory, string line)
    {
        var logs = Path.Combine(caseDirectory, "_Logs");
        Directory.CreateDirectory(logs);
        File.AppendAllText(Path.Combine(logs, LogName),
            $"{DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}  {line}{Environment.NewLine}");
    }

    private static void TryLog(string caseDirectory, string line)
    {
        try { Log(caseDirectory, line); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The result is returned to the caller as well; only the log line is lost.
        }
    }
}
