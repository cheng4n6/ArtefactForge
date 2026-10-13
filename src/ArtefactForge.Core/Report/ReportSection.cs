namespace ArtefactForge.Core.Report;

/// <summary>How urgent a finding on the report's "Needs attention" row is. Highest first.</summary>
public enum FindingLevel { Critical, High, Medium }

/// <summary>
/// One card on the "Needs attention" row: a short statement that links to the section holding
/// the detail. <paramref name="Headline"/> is the large text (a count or a value).
/// </summary>
public sealed record ReportFinding(FindingLevel Level, string Headline, string Label, string Detail, string SectionId);

/// <summary>
/// One section of the case report. Body and Script are HTML and JavaScript the section built
/// itself, every value in them already escaped.
/// </summary>
public sealed class ReportSection
{
    /// <summary>The anchor, also the nav link's target. Lower case, no spaces.</summary>
    public required string Id { get; init; }
    public required string Title { get; init; }
    /// <summary>Shown beside the title in the nav; null for none.</summary>
    public string? Count { get; init; }
    /// <summary>Where the section's data comes from, shown in small type beside its title.</summary>
    public string Source { get; init; } = "";
    public required string Body { get; init; }
    /// <summary>Script the section needs, run once the page has loaded. Empty for none.</summary>
    public string Script { get; init; } = "";
    public IReadOnlyList<ReportFinding> Findings { get; init; } = [];
}

/// <summary>
/// A part of the case report. Each reads the case's own summary files and builds its section;
/// none writes anything. A new analysis (PowerShell decoding, ransomware, exfiltration) adds its
/// section by implementing this and adding itself to <see cref="CaseReport.Sections"/>.
/// </summary>
public interface ICaseReportSection
{
    /// <summary>The section, or null when it has nothing to show and nothing worth saying about it.</summary>
    ReportSection? Build(CaseReportContext context);
}

/// <summary>One host folder in the case and what its system summary says about it.</summary>
public sealed record ReportHost(string Collection, string Directory, IReadOnlyDictionary<string, string> Facts)
{
    private string Fact(string item) => Facts.TryGetValue(item, out var v) ? v.Trim() : "";

    /// <summary>The machine's own name where the summary has it, else the collection's.</summary>
    public string Name => Fact("Hostname") is { Length: > 0 } name ? name : Collection;

    public bool IsLinux => Fact("PRETTY_NAME").Length > 0 || Fact("DISTRIB_DESCRIPTION").Length > 0
                           || (Facts.Count == 0 && System.IO.Directory.Exists(Path.Combine(Directory, "Linux")));

    public bool IsWindows => Fact("ProductName").Length > 0
                             || (!IsLinux && System.IO.Directory.Exists(Path.Combine(Directory, "EventLogs")));

    public string Role => Fact("ComputerRole");

    public string OperatingSystem
    {
        get
        {
            var os = Fact("ProductName");
            if (os.Length > 0)
                return Fact("DisplayVersion") is { Length: > 0 } display ? os + " " + display : os;
            return Fact("PRETTY_NAME") is { Length: > 0 } pretty ? pretty : Fact("DISTRIB_DESCRIPTION");
        }
    }

    /// <summary>What the live system reported at collection time, else its static configuration.</summary>
    public string Addresses => Fact("LiveIPAddresses") is { Length: > 0 } live ? live : Fact("IPAddresses");

    /// <summary>CollectionGaps rows in the summary: artefacts the collection did not contain.</summary>
    public int CollectionGaps =>
        Facts.TryGetValue(SystemInventory.GapCountKey, out var gaps) && int.TryParse(gaps, out var n) ? n : 0;
}

/// <summary>What every section is given: the case, its hosts, and how this copy of the report is made.</summary>
public sealed class CaseReportContext
{
    public required string CaseDirectory { get; init; }
    public required IReadOnlyList<ReportHost> Hosts { get; init; }
    public required DateTime GeneratedUtc { get; init; }
    /// <summary>A dated copy for sending: frozen, so it does not call itself live.</summary>
    public bool Snapshot { get; init; }
    public CancellationToken CancellationToken { get; init; }

    public string CaseName => Path.GetFileName(CaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

    /// <summary>The case's own working folder for the report, under _Logs, for caches.</summary>
    public string WorkDirectory => Path.Combine(CaseDirectory, "_Logs", "CaseReport");

    /// <summary>What the last run that processed each host recorded, by collection.</summary>
    public IReadOnlyDictionary<string, HostRun> Runs { get; init; } =
        new Dictionary<string, HostRun>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The detection counts of each host, read once and shared by the hosts and detections sections.</summary>
    public IReadOnlyDictionary<string, HostDetections> Detections => _detections ??=
        Hosts.ToDictionary(h => h.Collection, h => DetectionSummary.ForHost(this, h), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Each host's detections, one row per rule, with a level on every rule that has one anywhere
    /// in the case: Chainsaw's CSV carries no level, so a rule Hayabusa also reported takes its.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<RuleHits>> RatedDetections => _rated ??= Rate();

    private Dictionary<string, HostDetections>? _detections;
    private Dictionary<string, IReadOnlyList<RuleHits>>? _rated;

    private Dictionary<string, IReadOnlyList<RuleHits>> Rate()
    {
        var levels = Detections.Values.SelectMany(d => d.Rules)
            .Where(r => r.Level.Length > 0)
            .GroupBy(r => r.Title, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Level, StringComparer.OrdinalIgnoreCase);
        return Detections.ToDictionary(
            d => d.Key,
            d => (IReadOnlyList<RuleHits>)d.Value.Merged()
                .Select(r => r.Level.Length > 0 ? r : r with { Level = levels.GetValueOrDefault(r.Title, "") })
                .ToList(),
            StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>What one run recorded about a host it processed: when, and how its modules ended.</summary>
public sealed record HostRun(DateTime ProcessedUtc, int Completed, int Skipped, int NeedsReview);
