using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ArtefactForge.Core.Ioc;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Gui;

/// <summary>The RDP trace tab. Sessions, the trace and saving live in Core; this only shows them.</summary>
public partial class MainWindow
{
    private const string AllHosts = "All hosts";
    private bool _rdpBusy;
    private RdpTraceResult? _lastTrace;
    private string? _lastTracePath;

    private void InitRdpTab()
    {
        Tabs.SelectionChanged += (_, e) =>
        {
            if (ReferenceEquals(e.OriginalSource, Tabs) && Tabs.SelectedItem == RdpTab) RefreshRdp();
        };
    }

    private void RefreshRdp(string? result = null)
    {
        var caseDir = IocCaseDirectory();
        var selected = RdpHostBox.SelectedItem as string;
        if (caseDir is null || !Directory.Exists(caseDir))
        {
            RdpCaseText.Text = caseDir is null
                ? "Choose an output folder and a case name on Setup to trace RDP logons in the case."
                : "Case: " + caseDir + " (not created yet)";
            RdpHostBox.ItemsSource = null;
            RdpSessionGrid.ItemsSource = null;
            RdpSavedText.Text = "";
            if (result is not null) RdpResult.Text = result;
            SetRdpEnabled();
            return;
        }

        RdpCaseText.Text = "Case: " + caseDir;
        var hosts = new[] { AllHosts }.Concat(IocSweep.Hosts(caseDir)).ToList();
        RdpHostBox.ItemsSource = hosts;
        RdpHostBox.SelectedItem = selected is not null && hosts.Contains(selected) ? selected : AllHosts;
        if (result is not null) RdpResult.Text = result;
        else if (RdpResult.Text.Length == 0) RdpResult.Text = "Pick a host and a time, then Find sessions.";

        try
        {
            var saved = RdpTrace.Saved(caseDir);
            var stale = saved.Where(s => s.Stale is not null).ToList();
            RdpSavedText.Text = saved.Count == 0 ? "No saved traces in this case yet."
                : $"{saved.Count} saved trace{(saved.Count == 1 ? "" : "s")} in the case folder"
                  + (stale.Count == 0 ? "."
                     : $"; {stale.Count} should be run again ({string.Join("; ", stale.Select(s => s.Stale).Distinct().Take(3))}).");
            _lastTracePath ??= saved.FirstOrDefault()?.Path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            RdpSavedText.Text = ex.Message;
        }
        SetRdpEnabled();
    }

    private void SetRdpEnabled()
    {
        var free = !_rdpBusy && RunButton.IsEnabled && IocCaseDirectory() is { } caseDir && Directory.Exists(caseDir);
        RdpFindButton.IsEnabled = free;
        RdpTraceButton.IsEnabled = free && RdpSessionGrid.SelectedItem is RdpSession;
        RdpOpenButton.IsEnabled = _lastTracePath is not null && File.Exists(_lastTracePath);
        RdpIocIpButton.IsEnabled = free && _lastTrace?.EndAddress is not null;
        RdpIocAccountButton.IsEnabled = free && _lastTrace?.Accounts.Count > 0;
    }

    private void OnRdpKey(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        if (RdpFindButton.IsEnabled) OnRdpFind(sender, e);
    }

    private void OnRdpSessionSelected(object sender, SelectionChangedEventArgs e) => SetRdpEnabled();

    private void OnRdpSessionDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (RdpTraceButton.IsEnabled) OnRdpTrace(sender, e);
    }

    private async void OnRdpFind(object sender, RoutedEventArgs e)
    {
        if (IocCaseDirectory() is not { } caseDir) return;

        DateTime? at = null;
        if (RdpTimeBox.Text.Trim() is { Length: > 0 } text)
        {
            if (!DateTime.TryParse(text, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed))
            {
                RdpResult.Text = $"'{text}' is not a date and time: use yyyy-MM-dd HH:mm:ss, in UTC.";
                return;
            }
            at = parsed;
        }
        var window = TimeSpan.FromHours(Hours(RdpWindowBox.Text, 24));
        var host = RdpHostBox.SelectedItem is string h && h != AllHosts ? h : null;
        var ip = RdpIpBox.Text.Trim();
        var account = RdpAccountBox.Text.Trim();

        List<RdpSession>? sessions = null;
        await RunRdpAsync(() =>
        {
            var hosts = RdpTrace.LoadHosts(caseDir);
            if (hosts.Count == 0)
                return "No Windows host in this case has RDP data: the trace reads EvtxECmd output, so run EvtxECmd first.";
            sessions = RdpTrace.FindSessions(hosts, host, at - window, at + window, ip, account);
            var problems = hosts.Where(x => x.Problem is not null).Select(x => $"{x.HostName}: {x.Problem}").ToList();
            return (sessions.Count == 0 ? "No RDP sessions match." : $"{sessions.Count:N0} RDP session{(sessions.Count == 1 ? "" : "s")}. Pick one and Trace.")
                   + (problems.Count > 0 ? " " + string.Join(" ", problems) : "");
        });
        RdpSessionGrid.ItemsSource = sessions;
        SetRdpEnabled();
    }

    private async void OnRdpTrace(object sender, RoutedEventArgs e)
    {
        if (IocCaseDirectory() is not { } caseDir || RdpSessionGrid.SelectedItem is not RdpSession session) return;
        var lookback = TimeSpan.FromHours(Hours(RdpLookbackBox.Text, 12));

        await RunRdpAsync(() =>
        {
            var hosts = RdpTrace.LoadHosts(caseDir);
            var trace = RdpTrace.Trace(hosts, RdpTrace.LoadIpHistory(caseDir), session, new RdpTraceOptions { Lookback = lookback });
            _lastTracePath = RdpTrace.Save(caseDir, trace, hosts);
            _lastTrace = trace;
            return trace.Summary + " Saved as " + Path.GetFileName(_lastTracePath) + ".";
        });
    }

    private void OnRdpOpen(object sender, RoutedEventArgs e)
    {
        if (_lastTracePath is { } path) Open(path);
    }

    private async void OnRdpAddIp(object sender, RoutedEventArgs e)
    {
        if (_lastTrace?.EndAddress is not { } address) return;
        await AddRdpIocs([IocEntry.Create(IocType.IP, address, "RDP trace end point", _lastTrace.Hops[^1].ToHost)]);
    }

    private async void OnRdpAddAccounts(object sender, RoutedEventArgs e)
    {
        if (_lastTrace is not { } trace) return;
        await AddRdpIocs(trace.Accounts.Select(a => IocEntry.Create(IocType.Account, a, "RDP trace account", trace.Start.Host)).ToList());
    }

    private async Task AddRdpIocs(IReadOnlyList<IocEntry> entries)
    {
        if (IocCaseDirectory() is not { } caseDir) return;
        var progress = new Progress<string>(m => RdpResult.Text = m);
        await RunRdpAsync(() =>
        {
            var added = IocList.Add(caseDir, entries);
            if (added.Count == 0) return "Already on the IOC list.";
            var result = IocSweep.SweepAsync(caseDir, added, progress).GetAwaiter().GetResult();
            return $"Added {string.Join(", ", added.Select(a => a.Value))} to the IOC list. " + result.Describe();
        });
    }

    /// <summary>From the IOCs tab: list the sessions from an IP address or account.</summary>
    private void OnIocTraceRdp(object sender, RoutedEventArgs e)
    {
        if (IocGrid.SelectedItem is not IocRow row) return;
        if (row.Entry.Type is not (IocType.IP or IocType.Account))
        {
            IocResult.Text = "An RDP trace starts from an IP address or an account.";
            return;
        }
        RdpTimeBox.Clear();
        RdpIpBox.Text = row.Entry.Type == IocType.IP ? row.Entry.Value : "";
        RdpAccountBox.Text = row.Entry.Type == IocType.Account ? row.Entry.Value : "";
        Tabs.SelectedItem = RdpTab;
        RdpHostBox.SelectedItem = AllHosts;
        if (RdpFindButton.IsEnabled) OnRdpFind(sender, e);
    }

    private static double Hours(string text, double fallback) =>
        double.TryParse(text.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var h) && h > 0 ? h : fallback;

    /// <summary>Runs one step off the UI thread, with the buttons off and the result on the result line.</summary>
    private async Task RunRdpAsync(Func<string> work)
    {
        _rdpBusy = true;
        SetRdpEnabled();
        string result;
        try
        {
            RdpResult.Text = "Working...";
            result = await Task.Run(work);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            result = ex.Message;
            MessageBox.Show(this, ex.Message, "RDP trace", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _rdpBusy = false;
        }
        RefreshRdp(result);
    }
}
