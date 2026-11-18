using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// The evidence lake's last build, from _Lake\build.json: when, how much, and anything that needs
/// a look. Left out of a case that has never built one: the lake is optional.
/// </summary>
internal sealed class EvidenceLakeSection : ICaseReportSection
{
    private const string Source = @"_Lake\build.json, written by each evidence lake build";

    public ReportSection? Build(CaseReportContext context)
    {
        if (EvidenceLakeStep.Status(context.CaseDirectory) is not { } status) return null;

        var (pill, kind) = status.Result switch
        {
            "built" => ("Built", "ok"),
            "checklog" => ("Check", "med"),
            "notswapped" => ("Not replaced", "med"),
            _ => ("Not built", "crit")
        };
        var body = $"<div class=\"box\">{Pill(pill, kind)} {E(status.Describe())}";
        if (status.HasLake)
            body += $"<p class=\"muted small\">Query {E(status.DatabasePath is null ? "" : Path.GetFileName(status.DatabasePath))} in the " +
                    "case's _Lake folder with DuckDB or DBeaver; lake.log lists every source and why any was not loaded.</p>";
        body += "</div>";

        IReadOnlyList<ReportFinding> findings = status.NeedsAttention
            ? [new ReportFinding(status.HasLake ? FindingLevel.Medium : FindingLevel.High, "!", "Evidence lake", status.Describe(), "lake")]
            : [];
        return new ReportSection
        {
            Id = "lake", Title = "Evidence lake", Source = Source,
            Count = status.HasLake ? N(status.TimelineRows) : null,
            Body = body,
            Findings = findings
        };
    }
}
