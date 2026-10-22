using System.Globalization;
using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ArtefactForge.Core;
using ArtefactForge.Core.Ioc;
using ArtefactForge.Core.Report;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Gui;

/// <summary>
/// The Analysis tab: the case bar, the overview and the IP history and evidence list sub-tabs.
/// The IOCs, ransomware and RDP trace sub-tabs have their own files. Everything shown is read from the case
/// folder by Core; this only shows it.
/// </summary>
public partial class MainWindow
{
    private int _overviewVersion;
    private (string Path, DateTime Written, List<IpHistoryRecord> Rows)? _ipHistory;
    private (string CaseDirectory, EvidenceListResult Result)? _evidenceList;

    private void InitAnalysisTab()
    {
        // SelectionChanged bubbles up from the grids and combo boxes inside the tabs too.
        Tabs.SelectionChanged += (_, e) =>
        {
            if (ReferenceEquals(e.OriginalSource, Tabs) && Tabs.SelectedItem == AnalysisTab) RefreshAnalysis();
        };
        AnalysisTabs.SelectionChanged += (_, e) =>
        {
            if (ReferenceEquals(e.OriginalSource, AnalysisTabs)) RefreshAnalysis();
        };
    }

    /// <summary>The case the tab works on: Output and Case name on Setup, else the last run's case.</summary>
    private string? AnalysisCaseDirectory()
    {
        var output = OutputPath.Text.Trim();
        var caseName = CaseName.Text.Trim();
        if (output.Length > 0 && caseName.Length > 0) return Path.Combine(output, caseName);
        return _lastCaseDirectory;
    }

    /// <summary>The case bar and whichever sub-tab is showing.</summary>
    private void RefreshAnalysis()
    {
        RefreshCaseBar();
        if (AnalysisTabs.SelectedItem == OverviewTab) RefreshOverview();
        else if (AnalysisTabs.SelectedItem == IocTab) RefreshIocs();
        else if (AnalysisTabs.SelectedItem == RansomwareTab) RefreshRansomware();
        else if (AnalysisTabs.SelectedItem == RdpTab) RefreshRdp();
        else if (AnalysisTabs.SelectedItem == IpHistoryTab) RefreshIpHistory();
        else if (AnalysisTabs.SelectedItem == EvidenceListTab) RefreshEvidenceList();
    }

    private void RefreshCaseBar()
    {
        var caseDir = AnalysisCaseDirectory();
        if (caseDir is null)
        {
            AnalysisCaseText.Text = "No case chosen";
            AnalysisCaseDetail.Text = "Choose an output folder and a case name on Setup, or run a case.";
            return;
        }

        AnalysisCaseText.Text = "Case: " + Path.GetFileName(Path.TrimEndingDirectorySeparator(caseDir));
        if (!Directory.Exists(caseDir))
        {
            AnalysisCaseDetail.Text = caseDir + "; not created yet. IOCs added now are searched for when its hosts are processed.";
            return;
        }

        var hosts = IocSweep.Hosts(caseDir).Count;
        var report = CaseReport.PathFor(caseDir);
        AnalysisCaseDetail.Text = $"{caseDir}; {hosts} host{(hosts == 1 ? "" : "s")}; "
            + (File.Exists(report)
                ? "report updated " + File.GetLastWriteTime(report).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
                : "no report yet");
    }

    private void OnOpenCaseFolder(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is { } caseDir && Directory.Exists(caseDir)) Open(caseDir);
        else MessageBox.Show(this, "The case folder has not been created yet: run the case first.", "No case folder");
    }

    private void OnOverviewGo(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string name } && FindName(name) is TabItem tab) AnalysisTabs.SelectedItem = tab;
    }

    // --- overview -----------------------------------------------------------------------------------

    private sealed record OverviewLine(string Text, bool Attention = false);

    private async void RefreshOverview()
    {
        var caseDir = AnalysisCaseDirectory();
        var version = ++_overviewVersion;
        if (caseDir is null || !Directory.Exists(caseDir))
        {
            var none = new OverviewLine(caseDir is null ? "No case chosen." : "Nothing yet: the case has not been run.");
            ShowOverview(none, none, none, none, none);
            return;
        }

        var cached = _ipHistory;
        var evidence = _evidenceList is { } last && SamePath(last.CaseDirectory, caseDir) ? last.Result : null;
        var lines = await Task.Run(() => (Ioc: OverviewIocs(caseDir), Ransomware: OverviewRansomware(caseDir), Rdp: OverviewRdp(caseDir),
                                           Ip: OverviewIpHistory(caseDir, cached), Evidence: OverviewEvidence(caseDir, evidence)));
        // A slower refresh for an earlier case must not overwrite a newer one.
        if (version != _overviewVersion) return;
        _ipHistory = lines.Ip.Cache;
        ShowOverview(lines.Ioc, lines.Ransomware, lines.Rdp, lines.Ip.Line, lines.Evidence);
    }

    private void ShowOverview(OverviewLine ioc, OverviewLine ransomware, OverviewLine rdp, OverviewLine ip, OverviewLine evidence)
    {
        Show(OverviewIocText, ioc);
        Show(OverviewRansomwareText, ransomware);
        Show(OverviewRdpText, rdp);
        Show(OverviewIpText, ip);
        Show(OverviewEvidenceText, evidence);

        static void Show(TextBlock block, OverviewLine line)
        {
            block.Text = line.Text;
            if (line.Attention) block.SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
            else block.ClearValue(TextBlock.ForegroundProperty);
        }
    }

    private static OverviewLine OverviewIocs(string caseDir)
    {
        try
        {
            var entries = IocList.Load(caseDir);
            if (entries.Count == 0) return new OverviewLine("No IOCs on the list yet.");
            var counts = IocSweep.Summarise(caseDir);
            var found = entries.Count(e => counts.GetValueOrDefault(e.Key)?.Hits > 0);
            var hits = entries.Sum(e => counts.GetValueOrDefault(e.Key)?.Hits ?? 0);
            var listed = $"{entries.Count} IOC{(entries.Count == 1 ? "" : "s")}";
            return found == 0
                ? new OverviewLine(listed + "; none found.")
                : new OverviewLine($"{listed}; {found} found, {hits:N0} hit{(hits == 1 ? "" : "s")}.", true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new OverviewLine(ex.Message, true);
        }
    }

    private static OverviewLine OverviewRdp(string caseDir)
    {
        try
        {
            var saved = RdpTrace.Saved(caseDir);
            if (saved.Count == 0) return new OverviewLine("No saved traces yet.");
            var stale = saved.Count(s => s.Stale is not null);
            var line = $"{saved.Count} saved trace{(saved.Count == 1 ? "" : "s")}";
            return stale == 0
                ? new OverviewLine(line + ".")
                : new OverviewLine($"{line}; {stale} should be run again, as their hosts were processed since.", true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new OverviewLine(ex.Message, true);
        }
    }

    private static (OverviewLine Line, (string, DateTime, List<IpHistoryRecord>)? Cache) OverviewIpHistory(
        string caseDir, (string Path, DateTime Written, List<IpHistoryRecord> Rows)? cached)
    {
        try
        {
            var history = LoadIpHistory(caseDir, cached);
            return (new OverviewLine(DescribeIpHistory(history?.Rows)), history);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return (new OverviewLine(ex.Message, true), null);
        }
    }

    private static OverviewLine OverviewEvidence(string caseDir, EvidenceListResult? last)
    {
        if (last?.Outcome is EvidenceListOutcome.Locked or EvidenceListOutcome.Failed)
            return new OverviewLine(last.Describe(), true);
        return DescribeEvidenceListFile(caseDir);
    }

    // --- IP history ---------------------------------------------------------------------------------

    /// <summary>
    /// The case's IpHistory.csv, read again only when it has changed: a domain's history can run
    /// to tens of thousands of rows. Null when the case has none.
    /// </summary>
    private static (string Path, DateTime Written, List<IpHistoryRecord> Rows)? LoadIpHistory(
        string caseDir, (string Path, DateTime Written, List<IpHistoryRecord> Rows)? cached)
    {
        var path = Path.Combine(caseDir, IpHistory.FileName);
        if (!File.Exists(path)) return null;
        var written = File.GetLastWriteTimeUtc(path);
        if (cached is { } c && SamePath(c.Path, path) && c.Written == written) return c;
        return (path, written, IpHistoryRecord.Read(path));
    }

    private static string DescribeIpHistory(IReadOnlyList<IpHistoryRecord>? rows)
    {
        if (rows is null)
            return "No IP history: it is built when a domain controller or DHCP server is processed.";
        if (rows.Count == 0) return "IpHistory.csv has no rows.";
        var sources = string.Join(", ", rows.Select(r => r.Source).Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
        var first = rows.Min(r => r.FirstSeenUtc);
        var last = rows.Max(r => r.LastSeenUtc);
        return $"{rows.Count:N0} row{(rows.Count == 1 ? "" : "s")} from {sources}"
               + (first is null ? "." : $", {Day(first)} to {Day(last)}.");

        static string Day(DateTime? t) => t?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";
    }

    private async void RefreshIpHistory()
    {
        var caseDir = AnalysisCaseDirectory();
        IpLookupButton.IsEnabled = false;
        IpHistoryOpenButton.IsEnabled = false;
        if (caseDir is null || !Directory.Exists(caseDir))
        {
            IpHistoryStatus.Text = DescribeIpHistory(null);
            return;
        }

        var cached = _ipHistory;
        try
        {
            _ipHistory = await Task.Run(() => LoadIpHistory(caseDir, cached));
            IpHistoryStatus.Text = DescribeIpHistory(_ipHistory?.Rows);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            _ipHistory = null;
            IpHistoryStatus.Text = ex.Message;
        }
        IpLookupButton.IsEnabled = _ipHistory?.Rows.Count > 0;
        IpHistoryOpenButton.IsEnabled = _ipHistory is not null;
    }

    private void OnIpLookupKey(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        if (IpLookupButton.IsEnabled) OnIpLookup(sender, e);
    }

    private void OnIpLookup(object sender, RoutedEventArgs e)
    {
        if (_ipHistory is not { } history) return;
        IpLookupText.ClearValue(TextBlock.ForegroundProperty);

        var address = IpLookupAddressBox.Text.Trim();
        if (!IPAddress.TryParse(address, out _))
        {
            IpLookupText.Text = $"'{address}' is not an IP address.";
            return;
        }
        DateTime? at = null;
        if (IpLookupTimeBox.Text.Trim() is { Length: > 0 } text)
        {
            if (!DateTime.TryParse(text, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed))
            {
                IpLookupText.Text = $"'{text}' is not a date and time: use yyyy-MM-dd HH:mm:ss, in UTC.";
                return;
            }
            at = parsed;
        }

        var found = IpHistoryLookup.Find(history.Rows, address, at);
        if (found.Best is not { } best)
        {
            IpLookupText.Text = $"Nothing in the IP history had {address}.";
            return;
        }

        var who = best.HostName.Length > 0 ? best.HostName : "account " + best.Account;
        var when = best.FirstSeenUtc is null
            ? "at collection time"
            : $"from {IpHistoryRecord.Format(best.FirstSeenUtc)} to {IpHistoryRecord.Format(best.LastSeenUtc)} UTC";
        var line = $"{address}: {who} ({best.Source}, {when}).";
        if (found.Conflicts.Count > 0)
        {
            // Usually DHCP giving the address to two machines inside the span: the analyst has to
            // narrow the time, so this is not allowed to look like a clean answer.
            line += " Also named for it: "
                    + string.Join(", ", found.Conflicts.Select(c => $"{c.HostName} ({c.Source})").Distinct().Take(5))
                    + ". Narrow the time to tell them apart.";
            IpLookupText.SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
        }
        IpLookupText.Text = line;
    }

    private void OnIpHistoryOpen(object sender, RoutedEventArgs e)
    {
        if (_ipHistory is { } history) Open(history.Path);
    }

    // --- evidence list ------------------------------------------------------------------------------

    private void RefreshEvidenceList()
    {
        if (AnalysisCaseDirectory() is not { } caseDir) ShowEvidenceList(new OverviewLine(""));
        else if (_evidenceList is { } last && SamePath(last.CaseDirectory, caseDir)) ShowEvidenceList(last.Result);
        else ShowEvidenceList(DescribeEvidenceListFile(caseDir));
    }

    /// <summary>The evidence list as found in the case folder, when this session has not built it.</summary>
    private static OverviewLine DescribeEvidenceListFile(string caseDir)
    {
        var path = EvidenceList.PathFor(caseDir);
        if (!File.Exists(path)) return new OverviewLine("Not built yet: it is made when the case is run.");
        var saved = $"{EvidenceList.FileName}, saved {File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}";
        return EvidenceList.IsOpen(caseDir)
            ? new OverviewLine(saved + "; open in another program, so a run cannot update it.", true)
            : new OverviewLine(saved + ".");
    }

    private void ShowEvidenceList(OverviewLine line)
    {
        EvidenceListStatus.Text = line.Text;
        if (line.Attention) EvidenceListStatus.SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
        else EvidenceListStatus.ClearValue(TextBlock.ForegroundProperty);
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);
}
