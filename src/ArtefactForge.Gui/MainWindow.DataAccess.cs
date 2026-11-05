using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using ArtefactForge.Core.DataAccess;
using ArtefactForge.Core.Report;

namespace ArtefactForge.Gui;

/// <summary>
/// The Data access sub-tab of Analysis: the case's accounts with a tick for the compromised ones,
/// and the button that writes DataAccess.csv. The account list, the matching and the report live
/// in Core; this shows them and edits CompromisedUsers.csv through Core.
/// </summary>
public partial class MainWindow
{
    private bool _dataAccessBusy;
    private int _dataAccessVersion;

    /// <summary>One account in the grid. Compromised when any row of CompromisedUsers.csv matches it.</summary>
    private sealed record DataAccessUserRow(string System, string Username, string Sid, string ProfilePath, string Source, bool Compromised);

    private async void RefreshDataAccess(string? message = null)
    {
        var caseDir = AnalysisCaseDirectory();
        var version = ++_dataAccessVersion;
        if (caseDir is null || !Directory.Exists(caseDir))
        {
            DataAccessGrid.ItemsSource = null;
            ShowDataAccessStatus("Nothing yet: the case has not been run.", false);
            DataAccessSources.Text = "";
            SetDataAccessEnabled();
            return;
        }

        try
        {
            // Built from output already in the case, so a case processed before this page existed needs no re-run.
            var (rows, status, sources, attention) = await Task.Run(() =>
            {
                DataAccessReport.BuildUserList(caseDir);
                return Describe(caseDir);
            });
            if (version != _dataAccessVersion) return;
            DataAccessGrid.ItemsSource = rows;
            ShowDataAccessStatus(message is null ? status : message + " " + status,
                                 attention || message?.Contains("could not", StringComparison.OrdinalIgnoreCase) == true);
            DataAccessSources.Text = sources;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            if (version != _dataAccessVersion) return;
            ShowDataAccessStatus(ex.Message, true);
        }
        SetDataAccessEnabled();
    }

    /// <summary>The grid's rows, the status line and the sources line for a case.</summary>
    private static (List<DataAccessUserRow> Rows, string Status, string Sources, bool Attention) Describe(string caseDir)
    {
        var accounts = CaseUsers.LoadUserList(caseDir);
        List<CompromisedUser> compromised;
        string? listProblem = null;
        try { compromised = CaseUsers.ReadCompromised(caseDir); }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            compromised = [];
            listProblem = ex.Message;
        }

        var rows = accounts.Select(a => new DataAccessUserRow(a.System, a.Username, a.Sid, a.ProfilePath, a.Source,
                                                              compromised.Any(u => CaseUsers.Matches(u, a.Username, a.Sid))))
                           .ToList();
        // Listed accounts no host has a profile for (a domain account seen only in share events) still show, ticked.
        foreach (var u in compromised.Where(u => !accounts.Any(a => CaseUsers.Matches(u, a.Username, a.Sid))))
            rows.Add(new DataAccessUserRow("", u.Username, u.Sid, "", "CompromisedUsers.csv", true));
        rows = rows.OrderByDescending(r => r.Compromised)
                   .ThenBy(r => r.System, StringComparer.OrdinalIgnoreCase)
                   .ThenBy(r => r.Username, StringComparer.OrdinalIgnoreCase)
                   .ToList();

        if (listProblem is not null) return (rows, listProblem, "", true);

        var hosts = accounts.Select(a => a.System).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var status = accounts.Count == 0
            ? "No accounts found yet: they come from RECmd's system hive output (ProfileList, SAM), the per-user output folders and LinuxUsers."
            : $"{accounts.Count} account{(accounts.Count == 1 ? "" : "s")} on {hosts} host{(hosts == 1 ? "" : "s")}.";
        var noSid = accounts.Where(a => a.Sid.Length == 0 && a.Source.Contains("Output folders"))
                            .Select(a => a.System).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (noSid.Count > 0)
            status += $" No SIDs for profiles on {string.Join(", ", noSid)}: run RECmd_SystemHives on {(noSid.Count == 1 ? "it" : "them")} to add them.";

        var sources = "";
        if (compromised.Count == 0)
        {
            status += " Tick the compromised accounts, then Build report.";
        }
        else
        {
            var summary = DataAccessReport.Summarise(caseDir);
            status += $" {compromised.Count} listed as compromised. "
                + (summary.Written is { } written
                    ? $"DataAccess.csv has {summary.Rows:N0} row{(summary.Rows == 1 ? "" : "s")} (built "
                      + written.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + ")."
                    : "Build report to write DataAccess.csv.");
            var used = summary.Sources.Where(s => s.Hosts > 0).Select(s => $"{s.Source} ({s.Hosts} host{(s.Hosts == 1 ? "" : "s")})").ToList();
            var missing = summary.Sources.Where(s => s.Hosts == 0).Select(s => s.Source).ToList();
            if (used.Count > 0) sources = "Read from: " + string.Join(", ", used) + ".";
            if (missing.Count > 0) sources += (sources.Length > 0 ? " " : "") + "Not in this case's output: " + string.Join(", ", missing) + ".";
            if (summary.Sources.Count == 0 && summary.Written is not null)
                sources = "No host has output the report reads: LNK files, jump lists, ShellBags, RECmd NTUSER, EvtxECmd or LinuxUserFiles.";
        }
        return (rows, status, sources, false);
    }

    private static OverviewLine OverviewDataAccess(string caseDir)
    {
        try
        {
            var accounts = CaseUsers.LoadUserList(caseDir);
            var compromised = CaseUsers.ReadCompromised(caseDir);
            if (accounts.Count == 0 && compromised.Count == 0) return new OverviewLine("No account list yet: open the page to build it.");
            var text = $"{accounts.Count} account{(accounts.Count == 1 ? "" : "s")}";
            if (compromised.Count == 0) return new OverviewLine(text + "; none listed as compromised.");
            var summary = DataAccessReport.Summarise(caseDir);
            return new OverviewLine(text + $"; {compromised.Count} listed as compromised; "
                + (summary.Written is null ? "report not built yet." : $"{summary.Rows:N0} rows in DataAccess.csv."));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new OverviewLine(ex.Message, true);
        }
    }

    private void ShowDataAccessStatus(string text, bool attention)
    {
        DataAccessStatus.Text = text;
        if (attention) DataAccessStatus.SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
        else DataAccessStatus.ClearValue(TextBlock.ForegroundProperty);
    }

    private void SetDataAccessEnabled()
    {
        var caseDir = AnalysisCaseDirectory();
        var exists = caseDir is not null && Directory.Exists(caseDir);
        DataAccessBuildButton.IsEnabled = exists && !_dataAccessBusy && RunButton.IsEnabled;
        DataAccessEditButton.IsEnabled = exists;
        DataAccessOpenButton.IsEnabled = exists && File.Exists(DataAccessReport.PathFor(caseDir!));
        DataAccessUsersButton.IsEnabled = exists && File.Exists(CaseUsers.UserListPathFor(caseDir!));
        DataAccessGrid.IsEnabled = exists && !_dataAccessBusy;
    }

    /// <summary>A tick adds the account to CompromisedUsers.csv; clearing it removes every row that matches the account.</summary>
    private void OnDataAccessTicked(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir || sender is not CheckBox { DataContext: DataAccessUserRow row } box) return;
        try
        {
            if (box.IsChecked == true)
            {
                CaseUsers.AddCompromised(caseDir, new CompromisedUser(row.Username, row.Sid),
                                         row.System.Length > 0 ? "seen on " + row.System : "");
            }
            else
            {
                foreach (var u in CaseUsers.ReadCompromised(caseDir).Where(u => CaseUsers.Matches(u, row.Username, row.Sid)))
                    CaseUsers.RemoveCompromised(caseDir, u);
            }
            RefreshDataAccess("Saved. Build report to bring DataAccess.csv up to date.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            box.IsChecked = row.Compromised;
            MessageBox.Show(this, ex.Message, CaseUsers.CompromisedFileName, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Reads the hosts whose output changed, then writes the case's DataAccess.csv.</summary>
    private async void OnDataAccessBuild(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir || !Directory.Exists(caseDir)) return;
        _dataAccessBusy = true;
        SetDataAccessEnabled();
        ShowDataAccessStatus("Reading each host's LNK, jump list, ShellBags, registry, Linux recent files and event log output. "
                             + "The event log takes longest, a minute or so a host the first time.", false);
        try
        {
            var results = await Task.Run(() =>
            {
                var built = DataAccessReport.Build(caseDir);
                CaseReport.Rebuild(caseDir);
                return built;
            });
            var failed = results.Where(r => r.Status == Core.WorkStatus.Failed).Select(r => $"{r.Collection}: {r.Reason}").ToList();
            var message = failed.Count > 0
                ? "Some hosts could not be read: " + string.Join("; ", failed) + "."
                : results.Count == 0 ? "No host's output had changed." : $"Read {results.Count} host{(results.Count == 1 ? "" : "s")}.";
            _dataAccessBusy = false;
            RefreshDataAccess(message);
            RefreshCaseBar();
        }
        finally
        {
            _dataAccessBusy = false;
            SetDataAccessEnabled();
        }
    }

    private void OnDataAccessEdit(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir || !Directory.Exists(caseDir)) return;
        try
        {
            Open(CaseUsers.EnsureCompromisedFile(caseDir));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, ex.Message, CaseUsers.CompromisedFileName, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnDataAccessOpen(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is { } caseDir) Open(DataAccessReport.PathFor(caseDir));
    }

    private void OnDataAccessUsers(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is { } caseDir) Open(CaseUsers.UserListPathFor(caseDir));
    }
}
