using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using ArtefactForge.Core.DataAccess;
using ArtefactForge.Core.Report;

namespace ArtefactForge.Gui;

/// <summary>
/// The Data access sub-tab of Analysis: the case's accounts, one row each, with a tick for the compromised ones,
/// and the button that writes DataAccess.csv. The account list, the matching and the report live
/// in Core; this shows them and edits CompromisedUsers.csv through Core.
/// </summary>
public partial class MainWindow
{
    private bool _dataAccessBusy;
    private int _dataAccessVersion;

    /// <summary>
    /// One account in the grid, across every host it was seen on. Compromised when any row of
    /// CompromisedUsers.csv matches it; a row listed there that no host has (a domain account
    /// seen only in share events) has no hosts.
    /// </summary>
    private sealed class DataAccessUserRow(AccountGroup group, bool compromised) : Observable
    {
        private bool _compromised = compromised;
        private bool _isExpanded;

        public AccountGroup Group { get; } = group;
        public string Username => Group.Username;
        public string Sid => Group.Sid;
        public IReadOnlyList<UserAccount> Accounts => Group.Accounts;
        public int Hosts { get; } = group.Accounts.Select(a => a.System).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        public string Source { get; } = group.Accounts.Count == 0
            ? CaseUsers.CompromisedFileName
            : string.Join("; ", group.Accounts.SelectMany(a => a.Source.Split("; ")).Distinct(StringComparer.OrdinalIgnoreCase));
        public bool CanExpand => Accounts.Count > 0;

        public bool Compromised { get => _compromised; set => Set(ref _compromised, value); }
        public bool IsExpanded { get => _isExpanded; set => Set(ref _isExpanded, value); }
    }

    /// <summary>What the page shows for a case: the accounts, the list, and the status and sources lines.</summary>
    private sealed record DataAccessState(List<AccountGroup> Groups, List<CompromisedUser> Compromised,
                                          string Status, string Sources, bool Attention);

    /// <param name="message">Said before the status, such as what a build did.</param>
    /// <param name="keepRows">
    /// Only re-tick the rows already shown and update the status, so a tick does not reload the
    /// list or lose the analyst's sort and expanded rows.
    /// </param>
    private async void RefreshDataAccess(string? message = null, bool keepRows = false)
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

        var shown = keepRows ? DataAccessGrid.ItemsSource as List<DataAccessUserRow> : null;
        try
        {
            // Built from output already in the case, so a case processed before this page existed needs no re-run.
            var state = await Task.Run(() =>
            {
                if (shown is null) DataAccessReport.BuildUserList(caseDir);
                return Describe(caseDir);
            });
            if (version != _dataAccessVersion) return;
            if (shown is not null)
            {
                foreach (var row in shown) row.Compromised = row.Group.IsListed(state.Compromised);
            }
            else
            {
                var rows = state.Groups.Select(g => new DataAccessUserRow(g, g.IsListed(state.Compromised)))
                                       .OrderByDescending(r => r.Compromised)
                                       .ThenBy(r => r.Username, StringComparer.OrdinalIgnoreCase)
                                       .ToList();
                ShowDataAccessRows(rows);
            }
            ShowDataAccessStatus(message is null ? state.Status : message + " " + state.Status,
                                 state.Attention || message?.Contains("could not", StringComparison.OrdinalIgnoreCase) == true);
            DataAccessSources.Text = state.Sources;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            if (version != _dataAccessVersion) return;
            ShowDataAccessStatus(ex.Message, true);
        }
        SetDataAccessEnabled();
    }

    /// <summary>New rows in the grid, sorted the way the analyst last sorted it and with the same accounts expanded.</summary>
    private void ShowDataAccessRows(List<DataAccessUserRow> rows)
    {
        if (DataAccessGrid.ItemsSource is List<DataAccessUserRow> old)
        {
            var expanded = old.Where(r => r.IsExpanded).Select(r => (r.Username.ToUpperInvariant(), r.Sid.ToUpperInvariant())).ToHashSet();
            foreach (var row in rows) row.IsExpanded = expanded.Contains((row.Username.ToUpperInvariant(), row.Sid.ToUpperInvariant()));
        }
        var sorts = DataAccessGrid.Items.SortDescriptions.ToList();
        var directions = DataAccessGrid.Columns.Select(c => c.SortDirection).ToList();
        DataAccessGrid.ItemsSource = rows;
        foreach (var sort in sorts) DataAccessGrid.Items.SortDescriptions.Add(sort);
        for (var i = 0; i < directions.Count; i++) DataAccessGrid.Columns[i].SortDirection = directions[i];
    }

    /// <summary>The case's accounts grouped into one entry each, its compromised list, and the status and sources lines.</summary>
    private static DataAccessState Describe(string caseDir)
    {
        var accounts = CaseUsers.LoadUserList(caseDir);
        var groups = CaseUsers.Group(accounts);
        List<CompromisedUser> compromised;
        string? listProblem = null;
        try { compromised = CaseUsers.ReadCompromised(caseDir); }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            compromised = [];
            listProblem = ex.Message;
        }

        // Listed accounts no host has a profile for (a domain account seen only in share events) still show, ticked.
        foreach (var u in compromised.Where(u => !accounts.Any(a => CaseUsers.Matches(u, a.Username, a.Sid))))
            groups.Add(new AccountGroup(u.Username, u.Sid, []));

        if (listProblem is not null) return new DataAccessState(groups, compromised, listProblem, "", true);

        var hosts = accounts.Select(a => a.System).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var found = groups.Count(g => g.Accounts.Count > 0);
        var status = accounts.Count == 0
            ? "No accounts found yet: they come from RECmd's system hive output (ProfileList, SAM), the per-user output folders and LinuxUsers."
            : $"{found} account{(found == 1 ? "" : "s")} on {hosts} host{(hosts == 1 ? "" : "s")}.";
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
        return new DataAccessState(groups, compromised, status, sources, false);
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

    /// <summary>
    /// A tick adds the account to CompromisedUsers.csv; clearing it removes every row that matches
    /// the account. The list stays as it is: only the ticks and the status change.
    /// </summary>
    private void OnDataAccessTicked(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir || sender is not CheckBox { DataContext: DataAccessUserRow row } box) return;
        try
        {
            if (box.IsChecked == true)
            {
                var hosts = row.Accounts.Select(a => a.System).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                CaseUsers.AddCompromised(caseDir, row.Group.AsCompromised,
                                         hosts.Count switch
                                         {
                                             0 => "",
                                             <= 3 => "seen on " + string.Join(", ", hosts),
                                             _ => $"seen on {hosts.Count} hosts"
                                         });
            }
            else
            {
                foreach (var u in CaseUsers.ReadCompromised(caseDir).Where(u => row.Group.IsListed([u])))
                    CaseUsers.RemoveCompromised(caseDir, u);
            }
            row.Compromised = box.IsChecked == true;
            RefreshDataAccess("Saved. Build report to bring DataAccess.csv up to date.", keepRows: true);
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
