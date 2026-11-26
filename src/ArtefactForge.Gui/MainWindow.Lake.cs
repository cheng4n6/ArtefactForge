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
    private object? _runButtonToolTip;

    /// <summary>Why Run and the other actions that write into the case wait while a lake is built.</summary>
    internal const string LakeBuildingReason =
        "The evidence lake is being built from this case, and it reads what this would write";

    /// <summary>
    /// True, after saying why, when a lake build is going: anything that writes into the case
    /// (a run, an IOC sweep, a saved trace, a rebuilt report, an update) waits for it, so the lake
    /// is never built from files that change under it. The Run button is disabled for the build
    /// as for a tool install, which the analysis tabs already follow; this covers the rest.
    /// </summary>
    private bool LakeBuildBlocks(string what)
    {
        if (!_lakeBuilding) return false;
        MessageBox.Show(this, $"{LakeBuildingReason}. Wait for the build to finish before {what}.", "Evidence lake building",
            MessageBoxButton.OK, MessageBoxImage.Information);
        return true;
    }

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

    // The Run button is the one place that says a run, tool install or update is going; follow it
    // rather than add a second flag. The lake build disables it too, for its own reason.
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
        var running = !RunButton.IsEnabled && !_lakeBuilding;
        BuildLakeButton.IsEnabled = exists && !running && !_lakeBuilding;
        BuildLakeButton.ToolTip = running ? "A run is going: build the lake when it has finished"
            : _lakeBuilding ? "Building"
            : "Load every host's output into _Lake\\case.duckdb, in the background";
        OpenLakeButton.IsEnabled = exists && Directory.Exists(EvidenceLakeStep.FolderFor(caseDir!));
        UpdateQueryLakeButton(caseDir);
    }

    private async void OnBuildLake(object sender, RoutedEventArgs e)
    {
        var caseDir = AnalysisCaseDirectory();
        if (caseDir is null || !Directory.Exists(caseDir) || _lakeBuilding || !RunButton.IsEnabled) return;

        _lakeBuilding = true;
        _runButtonToolTip = RunButton.ToolTip;
        RunButton.ToolTip = LakeBuildingReason + ": Run is available again when it finishes.";
        ToolTipService.SetShowOnDisabled(RunButton, true);
        RunButton.IsEnabled = false;
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
            RunButton.ToolTip = _runButtonToolTip;
            RunButton.IsEnabled = true;
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
