using System.IO;
using System.Windows;
using System.Windows.Controls;
using ArtefactForge.Core;

namespace ArtefactForge.Gui;

/// <summary>
/// The evidence lake row of the Analysis overview: what the last build recorded, a button that
/// builds it in the background, and its folder. The build and its status are Core's
/// (<see cref="EvidenceLakeStep"/>); this shows them. The lake is never built unasked.
/// </summary>
public partial class MainWindow
{
    private bool _lakeBuilding;
    private bool _lakeWired;

    /// <summary>The row's text and buttons for the case, from its _Lake\build.json.</summary>
    private void RefreshLakeOverview(string? caseDir)
    {
        WireLakeRow();
        if (_lakeBuilding) return;   // the build's progress is showing; it refreshes when done
        var line = LakeOverviewLine(caseDir);
        OverviewLakeText.Text = line.Text;
        if (line.Attention) OverviewLakeText.SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
        else OverviewLakeText.ClearValue(TextBlock.ForegroundProperty);
        UpdateLakeButtons();
    }

    /// <summary>The overview line for a case's lake. A build that failed or needs a look is in the warning colour.</summary>
    private static OverviewLine LakeOverviewLine(string? caseDir)
    {
        if (caseDir is null || !Directory.Exists(caseDir)) return new OverviewLine("Not built: the case has not been run.");
        var status = EvidenceLakeStep.Status(caseDir);
        return status is null
            ? new OverviewLine("Not built. Build it to load every host's output into one DuckDB file with a cross-host timeline.")
            : new OverviewLine(status.Describe(), status.NeedsAttention);
    }

    // The Run button is the one place that says a run is going; follow it rather than add a second flag.
    private void WireLakeRow()
    {
        if (_lakeWired) return;
        _lakeWired = true;
        RunButton.IsEnabledChanged += (_, _) => UpdateLakeButtons();
    }

    private void UpdateLakeButtons()
    {
        var caseDir = AnalysisCaseDirectory();
        var exists = caseDir is not null && Directory.Exists(caseDir);
        var running = !RunButton.IsEnabled;
        BuildLakeButton.IsEnabled = exists && !running && !_lakeBuilding;
        BuildLakeButton.ToolTip = running ? "A run is going: build the lake when it has finished"
            : _lakeBuilding ? "Building"
            : "Load every host's output into _Lake\\case.duckdb, in the background";
        OpenLakeButton.IsEnabled = exists && Directory.Exists(EvidenceLakeStep.FolderFor(caseDir!));
    }

    private async void OnBuildLake(object sender, RoutedEventArgs e)
    {
        var caseDir = AnalysisCaseDirectory();
        if (caseDir is null || !Directory.Exists(caseDir) || _lakeBuilding || !RunButton.IsEnabled) return;

        _lakeBuilding = true;
        UpdateLakeButtons();
        OverviewLakeText.ClearValue(TextBlock.ForegroundProperty);
        OverviewLakeText.Text = "Building...";
        var options = Preferences.Current.RunOptions.Clamped();
        var progress = new Progress<string>(line => OverviewLakeText.Text = "Building: " + line);
        WorkResult result;
        try
        {
            result = await Task.Run(() => EvidenceLakeStep.Build(caseDir, options.Workers,
                SavedRunOptions.ToBytes(options.KeepFreeGB), progress));
        }
        catch (Exception ex)
        {
            // The step reports what it expects in its result; anything else must not take the window down.
            result = EvidenceLakeStep.NotBuilt(caseDir, "The evidence lake could not be built: " + ex.Message);
            result.Status = WorkStatus.Failed;
        }
        finally
        {
            _lakeBuilding = false;
        }

        RefreshLakeOverview(caseDir);
        if (result.Status is not WorkStatus.Completed)
            MessageBox.Show(this, result.Reason, result.Status == WorkStatus.CheckLog ? "Evidence lake: check" : "Evidence lake not built",
                MessageBoxButton.OK, result.Status == WorkStatus.CheckLog ? MessageBoxImage.Warning : MessageBoxImage.Error);
    }

    private void OnOpenLakeFolder(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is { } caseDir && Directory.Exists(EvidenceLakeStep.FolderFor(caseDir)))
            Open(EvidenceLakeStep.FolderFor(caseDir));
    }
}
