using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ArtefactForge.Core;
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
        var caseDir = AnalysisCaseDirectory();
        var open = RunButton.IsEnabled && caseDir is not null;
        // Adding never waits for a sweep: what is added meanwhile goes in the next batch. Remove
        // and Sweep all wait, one change at a time, so the result line reports the one in hand.
        var sweeping = _iocBusy || (_iocQueue is { IsBusy: true } queue && SameCase(queue, caseDir));
        IocAddButton.IsEnabled = open;
        IocImportButton.IsEnabled = open;
        IocRemoveButton.IsEnabled = open && !sweeping;
        IocSweepButton.IsEnabled = open && !sweeping;
    }

    private static bool SameCase(IocSweepQueue queue, string? caseDir) =>
        caseDir is not null && string.Equals(Path.GetFullPath(queue.CaseDirectory), Path.GetFullPath(caseDir),
                                             StringComparison.OrdinalIgnoreCase);

    private IocSweepQueue? _iocQueue;

    /// <summary>The add queue of this case, made when the first IOC is added to it.</summary>
    private IocSweepQueue QueueFor(string caseDir)
    {
        if (_iocQueue is { } current && SameCase(current, caseDir)) return current;

        // A queue still sweeping another case carries on; its result only goes to that case's files.
        var queue = new IocSweepQueue(caseDir);
        var lastShown = DateTime.MinValue;
        queue.Progress = new Progress<string>(message =>
        {
            if (!ReferenceEquals(queue, _iocQueue) || (DateTime.Now - lastShown).TotalMilliseconds < 200) return;
            lastShown = DateTime.Now;
            var waiting = queue.Waiting;
            IocResult.Text = message + (waiting > 0 ? $" ({waiting} more IOC{(waiting == 1 ? "" : "s")} waiting)" : "");
        });
        queue.BatchFinished += batch => Dispatcher.InvokeAsync(() => OnIocBatchSwept(queue, batch));
        return _iocQueue = queue;
    }

    private void OnIocBatchSwept(IocSweepQueue queue, IocSweepBatch batch)
    {
        if (!ReferenceEquals(queue, _iocQueue)) return;
        var waiting = queue.Waiting;
        var line = batch.Result?.Describe()
                   ?? $"The sweep of {batch.Iocs.Count} new IOC{(batch.Iocs.Count == 1 ? "" : "s")} failed: {batch.Error}";
        if (waiting > 0) line += $" {waiting} more IOC{(waiting == 1 ? "" : "s")} waiting for the next sweep.";
        if (batch.Error is not null)
            MessageBox.Show(this, line, "IOCs", MessageBoxButton.OK, MessageBoxImage.Warning);
        RefreshIocs(line);
        RefreshCaseBar();
    }

    /// <summary>
    /// Puts IOCs on the list at once and queues them for a sweep, without waiting for a sweep that
    /// is already running. <paramref name="add"/> saves them and says what it did.
    /// </summary>
    private async Task AddIocsAsync(string caseDir, Func<(IReadOnlyList<IocEntry> Added, string Line)> add)
    {
        IReadOnlyList<IocEntry> added;
        string line;
        try
        {
            // Off the window's thread: saving the list reads and writes it.
            (added, line) = await Task.Run(add);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            MessageBox.Show(this, ex.Message, "IOCs", MessageBoxButton.OK, MessageBoxImage.Warning);
            RefreshIocs(ex.Message);
            return;
        }

        if (added.Count > 0)
        {
            SweepSlots.Shared.KeepFreeBytes = SavedRunOptions.ToBytes(KeepFreeForSweeps());
            var queue = QueueFor(caseDir);
            var behind = queue.Sweeping > 0;
            queue.Add(added);
            line += behind
                ? $" It will be swept when the sweep running now finishes ({queue.Waiting} IOC{(queue.Waiting == 1 ? "" : "s")} waiting)."
                : " Sweeping...";
        }
        RefreshIocs(line);
    }

    /// <summary>Keep free as typed on the Setup tab, or as last saved when the box is not a number.</summary>
    private double KeepFreeForSweeps() =>
        SavedRunOptions.TryParseGB(KeepFreeGB.Text, CultureInfo.CurrentCulture, out var gb)
            ? new SavedRunOptions { KeepFreeGB = gb }.Clamped().KeepFreeGB
            : Preferences.Current.RunOptions.Clamped().KeepFreeGB;

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
        await AddIocsAsync(caseDir, () =>
        {
            var added = IocList.Add(caseDir, [entry]);
            return (added, added.Count == 0
                ? $"{entry.TypeLabel} {entry.Value} is already on the list."
                : $"Added {entry.TypeLabel} {entry.Value}.");
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

        await AddIocsAsync(caseDir, () =>
        {
            var import = IocList.Import(caseDir, dialog.FileName);
            return (import.Added, $"Imported {import.Added.Count} IOC(s); {import.AlreadyListed} already listed"
                                  + (import.Rejected.Count > 0 ? $"; {import.Rejected.Count} not added (type not recognised)." : "."));
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
        SweepSlots.Shared.KeepFreeBytes = SavedRunOptions.ToBytes(KeepFreeForSweeps());
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
