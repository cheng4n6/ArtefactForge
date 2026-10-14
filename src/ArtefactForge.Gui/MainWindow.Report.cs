using System.IO;
using System.Windows;
using ArtefactForge.Core.Report;

namespace ArtefactForge.Gui;

/// <summary>
/// The case report buttons. The report is built in Core after every run, sweep and trace; the app
/// only opens it, builds it first for a case processed before the report existed, and saves snapshots.
/// </summary>
public partial class MainWindow
{
    /// <summary>The Analysis tab's case bar: the case the tab shows.</summary>
    private async void OnOpenCaseReport(object sender, RoutedEventArgs e) => await OpenCaseReport(AnalysisCaseDirectory());

    private async Task OpenCaseReport(string? caseDirectory)
    {
        if (caseDirectory is null || !Directory.Exists(caseDirectory))
        {
            MessageBox.Show(this, "Choose the output folder and case name on the Setup page, or run the case "
                                  + "first, so there is a case to report on.", "No case folder");
            return;
        }

        var path = CaseReport.PathFor(caseDirectory);
        if (!File.Exists(path))
        {
            var result = await Task.Run(() => CaseReport.Rebuild(caseDirectory));
            if (!result.Written)
            {
                MessageBox.Show(this, result.Describe(), "Case report", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }
        Open(path);
    }

    private async void OnExportSnapshot(object sender, RoutedEventArgs e)
    {
        var caseDirectory = AnalysisCaseDirectory();
        if (caseDirectory is null || !Directory.Exists(caseDirectory))
        {
            MessageBox.Show(this, "Choose the output folder and case name on the Setup page, or run the case "
                                  + "first, so there is a case to report on.", "No case folder");
            return;
        }

        ExportSnapshotButton.IsEnabled = false;
        try
        {
            var result = await Task.Run(() => CaseReport.ExportSnapshot(caseDirectory));
            if (!result.Written || result.Path is null)
            {
                MessageBox.Show(this, result.Describe(), "Export snapshot", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            Append(result.Describe());
            RefreshCaseBar();
            Open(result.Path);
        }
        finally
        {
            ExportSnapshotButton.IsEnabled = true;
        }
    }

    /// <summary>The last rebuild's result for the run log, without its time stamp.</summary>
    private static string? CaseReportLine(string caseDirectory)
    {
        var line = CaseReport.LastResult(caseDirectory);
        if (line is null) return null;
        var at = line.IndexOf("  ", StringComparison.Ordinal);
        return at >= 0 ? line[(at + 2)..] : line;
    }
}
