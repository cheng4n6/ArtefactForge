using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ArtefactForge.Core.Ioc;
using Microsoft.Win32;

namespace ArtefactForge.Gui;

/// <summary>A row of the IOCs sub-tab: one IOC and how often the sweeps found it.</summary>
public sealed class IocRow
{
    public required IocEntry Entry { get; init; }
    public string Type => Entry.Type is null ? Entry.TypeLabel + " (not searched)" : Entry.TypeLabel;
    public string Value => Entry.Value;
    public string Note => Entry.Note;
    public string FoundOn => Entry.FoundOn;
    public int HitCount { get; init; }
    public int HostCount { get; init; }
    public bool HasHits => HitCount > 0;
    public string Hits => Entry.IsSweepable ? HitCount.ToString("N0") : "";
    public string Hosts => Entry.IsSweepable ? HostCount.ToString("N0") : "";
}

/// <summary>The IOCs sub-tab of Analysis. The list and the sweeps live in Core; this only shows them.</summary>
public partial class MainWindow
{
    private const string AutoType = "Auto";
    private bool _iocBusy;

    private void InitIocTab()
    {
        IocTypeBox.ItemsSource = new[] { AutoType }.Concat(Enum.GetValues<IocType>().Select(IocList.Label)).ToList();
        IocTypeBox.SelectedIndex = 0;
    }

    private int _iocVersion;

    private async void RefreshIocs(string? result = null)
    {
        var caseDir = AnalysisCaseDirectory();
        var version = ++_iocVersion;
        if (caseDir is null)
        {
            IocGrid.ItemsSource = null;
            IocResult.Text = "";
            SetIocEnabled();
            return;
        }

        try
        {
            // Read off the window's thread: a case with many hits has a large IocHits.csv.
            var (rows, last) = await Task.Run(() =>
            {
                var counts = IocSweep.Summarise(caseDir);
                var list = IocList.Load(caseDir).Select(e =>
                {
                    var count = counts.GetValueOrDefault(e.Key);
                    return new IocRow { Entry = e, HitCount = count?.Hits ?? 0, HostCount = count?.Hosts ?? 0 };
                }).ToList();
                return (list, result ?? IocSweep.LastResult(caseDir));
            });
            // A slower refresh for an earlier case must not overwrite a newer one.
            if (version != _iocVersion) return;
            IocGrid.ItemsSource = rows;
            IocResult.Text = last ?? "No sweep has run on this case yet.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            if (version != _iocVersion) return;
            IocGrid.ItemsSource = null;
            IocResult.Text = ex.Message;
        }
        SetIocEnabled();
    }

    private void SetIocEnabled()
    {
        // A run rebuilds the hits of the hosts it processes, so the list waits for it to finish.
        var free = !_iocBusy && RunButton.IsEnabled && AnalysisCaseDirectory() is not null;
        IocAddButton.IsEnabled = free;
        IocImportButton.IsEnabled = free;
        IocRemoveButton.IsEnabled = free;
        IocSweepButton.IsEnabled = free;
    }

    private void OnIocValueKey(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        if (IocAddButton.IsEnabled) OnIocAdd(sender, e);
    }

    private async void OnIocAdd(object sender, RoutedEventArgs e)
    {
        var caseDir = AnalysisCaseDirectory();
        var value = IocValueBox.Text.Trim();
        if (caseDir is null || value.Length == 0) return;

        var label = IocTypeBox.SelectedItem as string ?? AutoType;
        var type = label == AutoType ? IocList.Infer(value) : IocList.ParseType(label) ?? IocList.Infer(value);
        var entry = IocEntry.Create(type, value, IocNoteBox.Text, IocFoundOnBox.Text);

        IocValueBox.Clear();
        IocNoteBox.Clear();
        await RunIocAsync(caseDir, async progress =>
        {
            var added = IocList.Add(caseDir, [entry]);
            if (added.Count == 0) return $"{entry.TypeLabel} {entry.Value} is already on the list.";
            var result = await IocSweep.SweepAsync(caseDir, added, progress);
            return $"Added {entry.TypeLabel} {entry.Value}. " + result.Describe();
        });
    }

    private async void OnIocImport(object sender, RoutedEventArgs e)
    {
        var caseDir = AnalysisCaseDirectory();
        if (caseDir is null) return;
        var dialog = new OpenFileDialog
        {
            Title = "Import IOCs",
            Filter = "IOC lists (*.csv;*.txt)|*.csv;*.txt|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog(this) != true) return;

        await RunIocAsync(caseDir, async progress =>
        {
            var import = IocList.Import(caseDir, dialog.FileName);
            var line = $"Imported {import.Added.Count} IOC(s); {import.AlreadyListed} already listed"
                       + (import.Rejected.Count > 0 ? $"; {import.Rejected.Count} not added (type not recognised)." : ".");
            if (import.Added.Count == 0) return line;
            return line + " " + (await IocSweep.SweepAsync(caseDir, import.Added, progress)).Describe();
        });
    }

    private async void OnIocRemove(object sender, RoutedEventArgs e)
    {
        var caseDir = AnalysisCaseDirectory();
        var selected = IocGrid.SelectedItems.OfType<IocRow>().Select(r => r.Entry).ToList();
        if (caseDir is null || selected.Count == 0) return;

        var names = string.Join(Environment.NewLine, selected.Take(10).Select(s => $"{s.TypeLabel}: {s.Value}"))
                    + (selected.Count > 10 ? $"{Environment.NewLine}... and {selected.Count - 10} more" : "");
        if (MessageBox.Show(this, $"Take these off the case's IOC list, with their hits?{Environment.NewLine}{Environment.NewLine}{names}",
                "Remove IOCs", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        await RunIocAsync(caseDir, async _ =>
        {
            var removed = IocList.Remove(caseDir, selected);
            await IocSweep.RemoveHitsAsync(caseDir, removed);
            return $"Removed {removed.Count} IOC(s) and their hits.";
        });
    }

    private async void OnIocSweepAll(object sender, RoutedEventArgs e)
    {
        var caseDir = AnalysisCaseDirectory();
        if (caseDir is null) return;
        await RunIocAsync(caseDir, async progress => (await IocSweep.RebuildAllAsync(caseDir, progress)).Describe());
    }

    private void OnIocOpenList(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is { } caseDir) Open(IocList.PathFor(caseDir));
    }

    private void OnIocOpenHits(object sender, RoutedEventArgs e)
    {
        if (AnalysisCaseDirectory() is not { } caseDir) return;
        var hits = IocSweep.HitsPathFor(caseDir);
        if (File.Exists(hits)) Open(hits);
        else IocResult.Text = "There are no hits for this case yet.";
    }

    /// <summary>Runs one change to the list or sweep, with the buttons off and progress on the result line.</summary>
    private async Task RunIocAsync(string caseDir, Func<IProgress<string>, Task<string>> work)
    {
        _iocBusy = true;
        SetIocEnabled();
        var lastShown = DateTime.MinValue;
        var progress = new Progress<string>(message =>
        {
            if ((DateTime.Now - lastShown).TotalMilliseconds < 200) return;
            lastShown = DateTime.Now;
            IocResult.Text = message;
        });

        string result;
        try
        {
            IocResult.Text = "Working...";
            // Off the UI thread: saving the list and rewriting the hits file read and write files.
            result = await Task.Run(() => work(progress));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            result = ex.Message;
            MessageBox.Show(this, ex.Message, "IOCs", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _iocBusy = false;
        }
        RefreshIocs(result);
        RefreshCaseBar();
    }
}
