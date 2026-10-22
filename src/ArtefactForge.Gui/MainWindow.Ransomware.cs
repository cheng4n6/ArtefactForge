using System.IO;
using System.Windows;
using System.Windows.Controls;
using ArtefactForge.Core.Report;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Gui;

/// <summary>
/// The Ransomware sub-tab of Analysis: one line per host. Detection, the overrides and the case
/// file live in Core; this shows the case's Ransomware.csv and asks Core to check again.
/// </summary>
public partial class MainWindow
{
    private bool _ransomwareBusy;

    private sealed record RansomwareRow(string Host, string Result, string Collection);

    private void RefreshRansomware(string? message = null)
    {
        var caseDir = AnalysisCaseDirectory();
        List<RansomwareFinding> rows = [];
        string status;
        var attention = false;
        if (caseDir is null || !Directory.Exists(caseDir))
        {
            status = "Nothing yet: the case has not been run.";
        }
        else
        {
            try
            {
                rows = Ransomware.Load(caseDir);
                (status, attention) = DescribeRansomware(rows);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                (status, attention) = (ex.Message, true);
            }
        }

        RansomwareGrid.ItemsSource = rows.Select(r => new RansomwareRow(r.Host.Length > 0 ? r.Host : r.Collection, r.Describe(), r.Collection))
                                         .ToList();
        RansomwareStatus.Text = message is null ? status : message + " " + status;
        if (attention || message is not null && message.Contains("could not", StringComparison.OrdinalIgnoreCase))
            RansomwareStatus.SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
        else RansomwareStatus.ClearValue(TextBlock.ForegroundProperty);
        SetRansomwareEnabled();
    }

    /// <summary>The case's result in a line, and whether the analyst has to look at it.</summary>
    private static (string Text, bool Attention) DescribeRansomware(IReadOnlyList<RansomwareFinding> rows)
    {
        if (rows.Count == 0) return ("Not checked yet: it is built from MFTECmd output when a Windows host is processed.", false);
        var found = rows.Where(r => r.IsFound).ToList();
        var checkedHosts = rows.Count(r => r.Status is RansomwareFinding.Found or RansomwareFinding.NoneFound);
        var failed = rows.Count(r => r.Status == RansomwareFinding.FailedStatus);
        var text = found.Count == 0
            ? $"No encrypted files or ransom note on the {checkedHosts} host{(checkedHosts == 1 ? "" : "s")} checked."
            : $"Ransomware on {found.Count} of {checkedHosts} host{(checkedHosts == 1 ? "" : "s")} checked"
              + (found.Select(r => r.Extension).FirstOrDefault(e => e.Length > 0) is { } ext ? $" ({ext})." : ".");
        var differ = rows.Count(r => r.Differences.Length > 0 && r.IsFound);
        if (differ > 0) text += $" {differ} differ{(differ == 1 ? "s" : "")} from the rest of the case.";
        if (failed > 0) text += $" {failed} could not be checked.";
        return (text, found.Count > 0 || failed > 0);
    }

    private static OverviewLine OverviewRansomware(string caseDir)
    {
        try
        {
            var (text, attention) = DescribeRansomware(Ransomware.Load(caseDir));
            return new OverviewLine(text, attention);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new OverviewLine(ex.Message, true);
        }
    }

    private void SetRansomwareEnabled()
    {
        var caseDir = AnalysisCaseDirectory();
        var exists = caseDir is not null && Directory.Exists(caseDir);
        RansomwareCheckButton.IsEnabled = exists && !_ransomwareBusy && RunButton.IsEnabled;
        RansomwareOverridesButton.IsEnabled = exists;
        RansomwareOpenButton.IsEnabled = exists && File.Exists(Ransomware.PathFor(caseDir!));
        RansomwareHostButton.IsEnabled = exists && RansomwareGrid.SelectedItem is RansomwareRow;
    }

    private void OnRansomwareSelected(object sender, SelectionChangedEventArgs e) => SetRansomwareEnabled();

    /// <summary>Checks again: hosts whose output or overrides changed are read again, then the case file and report.</summary>
    private async void OnRansomwareCheck(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir || !Directory.Exists(caseDir)) return;
        _ransomwareBusy = true;
        SetRansomwareEnabled();
        RansomwareStatus.ClearValue(TextBlock.ForegroundProperty);
        RansomwareStatus.Text = "Checking each host's MFT and USN journal output. A large MFT takes a few seconds a host.";
        try
        {
            var results = await Task.Run(() =>
            {
                var built = Ransomware.Build(caseDir);
                CaseReport.Rebuild(caseDir);
                return built;
            });
            var failed = results.Where(r => r.Status == Core.WorkStatus.Failed).Select(r => $"{r.Collection}: {r.Reason}").ToList();
            var message = failed.Count > 0
                ? "Some hosts could not be checked: " + string.Join("; ", failed) + "."
                : results.Count == 0 ? "Nothing had changed since the last check." : $"Checked {results.Count} host{(results.Count == 1 ? "" : "s")} again.";
            _ransomwareBusy = false;
            RefreshRansomware(message);
            RefreshCaseBar();
        }
        finally
        {
            _ransomwareBusy = false;
            SetRansomwareEnabled();
        }
    }

    private void OnRansomwareOverrides(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir || !Directory.Exists(caseDir)) return;
        try
        {
            Open(Ransomware.EnsureOverridesFile(caseDir));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, ex.Message, Ransomware.OverridesFileName, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnRansomwareOpen(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is { } caseDir) Open(Ransomware.PathFor(caseDir));
    }

    private void OnRansomwareHost(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir || RansomwareGrid.SelectedItem is not RansomwareRow row) return;
        var folder = Path.Combine(caseDir, row.Collection, Ransomware.Folder);
        Open(Directory.Exists(folder) ? folder : Path.Combine(caseDir, row.Collection));
    }
}
