using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using ArtefactForge.Core;
using Microsoft.Win32;

namespace ArtefactForge.Gui;

/// <summary>
/// The evidence lake row's Query button: opens the case's lake read-only in the DuckDB CLI,
/// DuckDB's web UI or DBeaver, after checking the program is there and new enough. The checks and
/// commands are Core's (<see cref="LakeQueryApps"/>); this asks the analyst and starts them.
/// </summary>
public partial class MainWindow
{
    private bool _lakeQueryChecking;

    private void UpdateQueryLakeButton(string? caseDir)
    {
        var status = caseDir is null || !Directory.Exists(caseDir) ? null : EvidenceLakeStep.Status(caseDir);
        var hasLake = status is { HasLake: true, DatabasePath: { } path } && File.Exists(path);
        QueryLakeButton.IsEnabled = hasLake && !_lakeBuilding && !_lakeQueryChecking;
        QueryLakeButton.ToolTip = _lakeBuilding ? "Building: the lake can be opened when it has finished"
            : !hasLake ? "Build the evidence lake first"
            : "Open case.duckdb read-only in the DuckDB CLI, DuckDB's web UI or DBeaver";
    }

    private void OnQueryLake(object sender, RoutedEventArgs e)
    {
        if (QueryLakeButton.ContextMenu is not { } menu) return;
        menu.PlacementTarget = QueryLakeButton;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }

    private async void OnQueryLakeWith(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { Tag: string tag } || !Enum.TryParse<LakeQueryApp>(tag, out var app)) return;
        var caseDir = AnalysisCaseDirectory();
        if (caseDir is null || _lakeBuilding || _lakeQueryChecking) return;
        var status = EvidenceLakeStep.Status(caseDir);
        var caseName = Path.GetFileName(caseDir.TrimEnd(Path.DirectorySeparatorChar));

        _lakeQueryChecking = true;
        UpdateQueryLakeButton(caseDir);
        try
        {
            // The checks run the CLI, which takes a moment, so off the UI thread.
            var plan = await Task.Run(() => PlanLakeQuery(app, status, caseName));
            while (plan.Start is null)
            {
                if (!await ResolveLakeQueryProblem(app, plan)) return;
                plan = await Task.Run(() => PlanLakeQuery(app, status, caseName));
            }
            Process.Start(plan.Start)?.Dispose();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            MessageBox.Show(this, "The lake could not be opened: " + ex.Message, "Query evidence lake",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _lakeQueryChecking = false;
            UpdateQueryLakeButton(AnalysisCaseDirectory());
        }
    }

    private static LakeQueryPlan PlanLakeQuery(LakeQueryApp app, LakeStatus? status, string caseName)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var prefs = Preferences.Current;
        var duckDb = app == LakeQueryApp.DBeaver ? null
            : LakeQueryApps.FindDuckDb(prefs.DuckDbPath, Environment.GetEnvironmentVariable("PATH"), localAppData, File.Exists);
        var dbeaver = app != LakeQueryApp.DBeaver ? null
            : LakeQueryApps.FindDBeaver(prefs.DBeaverPath,
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), localAppData, File.Exists);
        return LakeQueryApps.Plan(app, status?.DatabasePath, status?.DuckDbVersion, caseName + " evidence lake",
            duckDb, dbeaver, LakeQueryApps.RunCheck);
    }

    /// <summary>
    /// Says what stops the lake opening and offers the fix: pointing at the program, or installing
    /// DuckDB's ui extension. True when the analyst took the fix, so the checks run again.
    /// </summary>
    private async Task<bool> ResolveLakeQueryProblem(LakeQueryApp app, LakeQueryPlan plan)
    {
        const string title = "Query evidence lake";
        switch (plan.Fix)
        {
            case LakeQueryFix.Locate:
            {
                var exe = app == LakeQueryApp.DBeaver ? LakeQueryApps.DBeaverExe : LakeQueryApps.DuckDbExe;
                if (MessageBox.Show(this, plan.Problem + $"\n\nLocate {exe} now?", title,
                        MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return false;
                var dialog = new OpenFileDialog { Title = "Locate " + exe, Filter = $"{exe}|{exe}|Programs (*.exe)|*.exe" };
                if (dialog.ShowDialog(this) != true) return false;
                if (app == LakeQueryApp.DBeaver) Preferences.Current.DBeaverPath = dialog.FileName;
                else Preferences.Current.DuckDbPath = dialog.FileName;
                Preferences.Save();
                return true;
            }
            case LakeQueryFix.InstallUi when plan.Program is { } duckDb:
            {
                if (MessageBox.Show(this, plan.Problem + "\n\nInstall the ui extension now?", title,
                        MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return false;
                var installed = await Task.Run(() =>
                    LakeQueryApps.RunCheck(LakeQueryApps.InstallUiStart(duckDb), TimeSpan.FromMinutes(2)));
                if (installed is not null) return true;
                MessageBox.Show(this, "DuckDB could not install the ui extension. Check this computer can reach the internet, " +
                    "or run duckdb -c \"INSTALL ui\" yourself to see why.", title, MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            default:
                MessageBox.Show(this, plan.Problem, title, MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
        }
    }
}
