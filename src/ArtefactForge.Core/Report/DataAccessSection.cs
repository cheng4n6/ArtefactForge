using System.Text;
using ArtefactForge.Core.DataAccess;
using ArtefactForge.Core.Windows;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// The case's DataAccess.csv in brief: one row per compromised account and host, with how many
/// files and folders it reached, when first and last, how, and which artefacts said so. The rows
/// themselves stay in the CSV.
/// </summary>
internal sealed class DataAccessSection : ICaseReportSection
{
    private sealed class Tally
    {
        public required string User { get; init; }
        public required string System { get; init; }
        public int Rows { get; set; }
        public DateTime First { get; set; } = DateTime.MaxValue;
        public DateTime Last { get; set; } = DateTime.MinValue;
        public Dictionary<string, int> Activities { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, int> Artefacts { get; } = new(StringComparer.Ordinal);
    }

    public ReportSection? Build(CaseReportContext context)
    {
        var path = DataAccessReport.PathFor(context.CaseDirectory);
        if (!File.Exists(path)) return null;   // no compromised users listed: nothing to say

        var compromised = CaseUsers.ReadCompromised(context.CaseDirectory);
        var tallies = new Dictionary<(string, string), Tally>();
        foreach (var cell in CaseUsers.Rows(path, context.CancellationToken))
        {
            if (IpHistoryRecord.ParseTime(cell("Date/Time (UTC)")) is not { } time) continue;
            var key = (cell("User").ToUpperInvariant(), cell("System").ToUpperInvariant());
            if (!tallies.TryGetValue(key, out var t))
                tallies[key] = t = new Tally { User = cell("User"), System = cell("System") };
            t.Rows++;
            if (time < t.First) t.First = time;
            if (time > t.Last) t.Last = time;
            var activity = cell("Activity");
            t.Activities[activity] = t.Activities.GetValueOrDefault(activity) + 1;
            var artefact = cell("Artefact");   // empty in a DataAccess.csv written before the column
            if (artefact.Length > 0) t.Artefacts[artefact] = t.Artefacts.GetValueOrDefault(artefact) + 1;
        }

        var listed = string.Join(", ", compromised.Select(u => u.Username.Length > 0 ? u.Username : u.Sid));
        const string source = "DataAccess.csv, from LNK files, jump lists, ShellBags, registry MRUs, Linux recent files "
                              + "and Security events, for the accounts in CompromisedUsers.csv.";
        if (tallies.Count == 0)
            return new ReportSection
            {
                Id = "dataaccess", Title = "Data access", Count = "0", Source = source,
                Body = Empty($"No dated file or folder activity found for {listed}.")
            };

        var body = new StringBuilder($"<p class=\"muted small\">Compromised accounts listed: {E(listed)}. "
                                     + "Every row, with its path, is in DataAccess.csv for filtering by time.</p>")
            .Append("<div class=\"box tbl\"><table><thead><tr><th>Account</th><th>Host</th><th>Rows</th>")
            .Append("<th>First (UTC)</th><th>Last (UTC)</th><th>Activity</th><th>Artefact</th></tr></thead><tbody>");
        foreach (var t in tallies.Values.OrderBy(t => t.User, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.First))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var activities = Counts(t.Activities);
            var artefacts = Counts(t.Artefacts);
            body.Append($"<tr><td><b>{E(t.User)}</b></td><td>{E(t.System)}</td><td>{N(t.Rows)}</td>")
                .Append($"<td class=\"mono\">{E(Time(t.First))}</td><td class=\"mono\">{E(Time(t.Last))}</td>")
                .Append($"<td class=\"wrap small\">{E(activities)}</td><td class=\"wrap small\">{E(artefacts)}</td></tr>");
        }
        body.Append("</tbody></table></div>");

        return new ReportSection
        {
            Id = "dataaccess", Title = "Data access", Count = N(tallies.Values.Sum(t => t.Rows)), Source = source,
            Body = body.ToString()
        };
    }

    private static string Counts(Dictionary<string, int> counts) =>
        string.Join(", ", counts.OrderByDescending(c => c.Value).ThenBy(c => c.Key, StringComparer.Ordinal)
                                .Select(c => $"{c.Key} {N(c.Value)}"));
}
