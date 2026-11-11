using ArtefactForge.Core;
using ArtefactForge.Core.Ioc;
using ArtefactForge.Core.Report;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Tests;

/// <summary>
/// CaseReport.html: built from the case's summary files, offline, escaped, rebuilt by sweeps and
/// traces, and snapshotted into dated copies that are never replaced. Made-up hosts and accounts;
/// documentation addresses for anything external.
/// </summary>
public class CaseReportTests
{
    private const string HayabusaHeader =
        "\"Timestamp\",\"RuleTitle\",\"Level\",\"Computer\",\"Channel\",\"EventID\",\"MitreTactics\",\"MitreTags\","
        + "\"OtherTags\",\"RecordID\",\"Details\",\"ExtraFieldInfo\",\"RuleFile\",\"EvtxFile\"";

    private static string Hayabusa(string time, string rule, string level, string tags = "") =>
        $"\"{time} +00:00\",\"{rule}\",\"{level}\",\"DC01.corp.example\",\"Sec\",\"4688\",\"\",\"{tags}\",\"\",\"1\",\"x\",\"\",\"r.yml\",\"Security.evtx\"";

    private const string ChainsawHeader =
        "\"timestamp\",\"detections\",\"path\",\"count\",\"Event.System.Provider\",\"Event ID\",\"Record ID\",\"Computer\",\"Event Data\"";

    private static string Chainsaw(string time, string rules) =>
        $"\"{time}+00:00\",\"{rules}\",\"C:\\x\\Security.evtx\",\"1\",\"Microsoft-Windows-Security-Auditing\",\"4688\",\"1\",\"DC01\",\"{{}}\"";

    private static void Write(TempDirectory dir, string relative, params string[] lines) =>
        File.WriteAllLines(dir.File(relative), lines);

    private static void SystemInfo(TempDirectory dir, string host, params (string Item, string Value)[] facts) =>
        Write(dir, Path.Combine(host, "SystemInfo", "SystemInfo.csv"),
              ["\"Category\",\"Item\",\"Value\",\"Source\"",
               .. facts.Select(f => $"\"Identity\",\"{f.Item}\",\"{f.Value}\",\"test\"")]);

    private static TempDirectory Case()
    {
        var dir = new TempDirectory();
        SystemInfo(dir, "DC01", ("Hostname", "DC01"), ("ProductName", "Windows Server 2022"),
                   ("ComputerRole", "Domain controller"), ("IPAddresses", "10.0.0.10"));
        Write(dir, Path.Combine("DC01", "EventLogs", "Hayabusa_Timeline.csv"),
              HayabusaHeader,
              Hayabusa("2026-03-01 10:00:00.000", "Mimikatz Use", "crit", "T1003.001 ¦ Cred"),
              Hayabusa("2026-03-01 10:05:00.000", "Mimikatz Use", "crit", "T1003.001"),
              Hayabusa("2026-03-01 10:10:00.000", "Encoded PowerShell", "high"),
              Hayabusa("2026-03-01 09:00:00.000", "Logon (Network)", "info"),
              Hayabusa("2026-03-01 09:01:00.000", "Logon (Network)", "info"));
        Write(dir, Path.Combine("DC01", "EventLogs", "sigma.csv"),
              ChainsawHeader,
              Chainsaw("2026-03-01T10:00:00.000000", "Mimikatz Use"),
              Chainsaw("2026-03-01T11:00:00.000000", "Chainsaw Only Rule"));
        Write(dir, Path.Combine("DC01", RemoteAccess.Folder, RemoteAccess.SourcesFileName),
              "Log,Status,Events,FirstEventUtc,LastEventUtc,ClearedUtc,Input",
              "Security,used,10,2026-02-20 00:00:00,2026-03-02 00:00:00,2026-03-01 09:30:00,EventLogs\\EvtxECmd_EventLogs.csv");

        SystemInfo(dir, "WEB01", ("Hostname", "WEB01"), ("PRETTY_NAME", "Ubuntu 22.04.4 LTS"));
        Write(dir, Path.Combine("WEB01", "Linux", "Auth.csv"), "Time,Line", "2026-03-01 08:00:00,Accepted password for root from 203.0.113.7");
        return dir;
    }

    private static string Report(TempDirectory dir) => File.ReadAllText(CaseReport.PathFor(dir.Path));

    [Fact]
    public void Rebuild_writes_one_offline_page_with_every_section()
    {
        using var dir = Case();

        var result = CaseReport.Rebuild(dir.Path);

        Assert.True(result.Written, result.Message);
        var html = Report(dir);
        foreach (var id in new[] { "overview", "hosts", "detections", "iocs", "rdp", "ips" })
            Assert.Contains($"id=\"{id}\"", html);
        Assert.Contains("DC01", html);
        Assert.Contains("Ubuntu 22.04.4 LTS", html);
        Assert.Contains("2 hosts: 1 Windows, 1 Linux", html);
        // Nothing is fetched: no external scripts, styles or fonts.
        Assert.DoesNotContain("<script src", html);
        Assert.DoesNotContain("<link", html);
        Assert.DoesNotContain("http://", html);
        Assert.DoesNotContain("https://", html);
        Assert.Contains("Case report rebuilt", CaseReport.LastResult(dir.Path));
    }

    [Fact]
    public void Detections_are_counted_by_rule_once_per_host_and_informational_hits_are_left_out()
    {
        using var dir = Case();

        CaseReport.Rebuild(dir.Path);

        var html = Report(dir);
        // Mimikatz 2 (Hayabusa's 2, not 2 + Chainsaw's 1), Encoded PowerShell 1, Chainsaw Only Rule 1.
        Assert.Contains("Detections <span class=\"c\">4</span>", html);
        Assert.Contains("T1003.001", html);
        Assert.Contains("Chainsaw, Hayabusa", html);
        Assert.Contains("Chainsaw Only Rule", html);
        Assert.Contains("Not given", html);
        Assert.DoesNotContain("Logon (Network)", html);
        Assert.Contains("Critical detections", html);
        Assert.Contains("DC01 2", html);
    }

    [Fact]
    public void A_host_collected_twice_has_its_detections_counted_once_and_is_flagged()
    {
        using var dir = Case();
        // DC01 collected again later: the same Security log, now with one more event in it.
        SystemInfo(dir, "DC01_2", ("Hostname", "DC01"), ("ProductName", "Windows Server 2022"));
        Write(dir, Path.Combine("DC01_2", "EventLogs", "Hayabusa_Timeline.csv"),
              HayabusaHeader,
              Hayabusa("2026-03-01 10:00:00.000", "Mimikatz Use", "crit", "T1003.001"),
              Hayabusa("2026-03-01 10:05:00.000", "Mimikatz Use", "crit", "T1003.001"),
              Hayabusa("2026-03-01 10:10:00.000", "Encoded PowerShell", "high"),
              Hayabusa("2026-03-02 08:00:00.000", "Encoded PowerShell", "high"));

        CaseReport.Rebuild(dir.Path);

        var html = Report(dir);
        // Mimikatz 2, Encoded PowerShell 2 (the later collection's), Chainsaw Only Rule 1: not 8.
        Assert.Contains("Detections <span class=\"c\">5</span>", html);
        Assert.Contains("DC01 2", html);
        Assert.DoesNotContain("DC01 4", html);
        Assert.Contains("2026-03-02 08:00:00", html);
        Assert.Contains("Collected more than once", html);
        Assert.Contains("DC01 in DC01, DC01_2", html);
        Assert.Contains("Collected 2 times", html);
        Assert.Contains("2 hosts: 1 Windows, 1 Linux (3 collections)", html);
    }

    [Fact]
    public void A_cleared_security_log_is_shown_and_raised_as_a_coverage_gap()
    {
        using var dir = Case();

        CaseReport.Rebuild(dir.Path);

        var html = Report(dir);
        Assert.Contains("2026-02-20 to 2026-03-02", html);
        Assert.Contains("Cleared 2026-03-01 09:30:00", html);
        Assert.Contains("Coverage gap", html);
    }

    [Fact]
    public void Detection_counts_are_read_again_when_the_timeline_changes()
    {
        using var dir = Case();
        CaseReport.Rebuild(dir.Path);
        Assert.True(File.Exists(Path.Combine(dir.Path, "_Logs", "CaseReport", "Detections", "DC01.json")));

        var timeline = Path.Combine(dir.Path, "DC01", "EventLogs", "Hayabusa_Timeline.csv");
        File.AppendAllLines(timeline, [Hayabusa("2026-03-01 12:00:00.000", "Encoded PowerShell", "high")]);
        File.SetLastWriteTimeUtc(timeline, DateTime.UtcNow.AddMinutes(1));
        CaseReport.Rebuild(dir.Path);

        Assert.Contains("Detections <span class=\"c\">5</span>", Report(dir));
    }

    [Fact]
    public void Values_from_the_case_are_escaped()
    {
        using var dir = Case();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "<script>alert(1)</script>.exe", "<b>note</b>")]);

        CaseReport.Rebuild(dir.Path);

        var html = Report(dir);
        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain("<b>note</b>", html);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;.exe", html);
    }

    [Fact]
    public async Task An_IOC_sweep_rebuilds_the_report_with_its_hits()
    {
        using var dir = Case();
        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.IP, "203.0.113.7", "Seen in SSH logs")]);

        await IocSweep.SweepAsync(dir.Path, added);

        var html = Report(dir);
        Assert.Contains("203.0.113.7", html);
        Assert.Contains("<mark>203.0.113.7</mark>", html);
        Assert.Contains("IOC hit on 1 host", html);
        Assert.Contains("Seen in SSH logs", html);
    }

    [Fact]
    public async Task IOC_hits_are_shown_by_host_whatever_order_the_hosts_were_swept_in()
    {
        // Hosts swept as their modules finish are written to IocHits.csv in the order they
        // finished, which varies by run; the report must not.
        using var dir = Case();
        Write(dir, Path.Combine("APP01", "Linux", "Auth.csv"), "Time,Line", "2026-03-01 08:30:00,Failed password for admin from 203.0.113.7");
        IocList.Add(dir.Path, [IocEntry.Create(IocType.IP, "203.0.113.7")]);

        await IocSweep.RebuildHostsAsync(dir.Path, ["WEB01"]);
        await IocSweep.RebuildHostsAsync(dir.Path, ["APP01"]);

        var report = Report(dir);
        var html = report[report.IndexOf("id=\"iocs\"", StringComparison.Ordinal)..];   // the hosts table lists them too
        var app = html.IndexOf("<td><b>APP01</b>", StringComparison.Ordinal);
        var web = html.IndexOf("<td><b>WEB01</b>", StringComparison.Ordinal);
        Assert.True(app >= 0 && web >= 0, "both hosts' hits are shown");
        Assert.True(app < web, "APP01's hit comes before WEB01's");
    }

    [Fact]
    public void A_saved_RDP_trace_is_drawn_and_an_external_end_is_raised()
    {
        using var dir = Case();
        var start = new RdpSession("DC01", "DC01", new DateTime(2026, 3, 1, 10, 0, 0, DateTimeKind.Utc), null, "Logon",
                                   "alice", "10.0.0.21", "WS02", []);
        RdpHop[] hops =
        [
            new() { Number = 1, Result = RdpTrace.Confirmed, ToHost = "DC01", TimeUtc = start.StartUtc, Account = "alice",
                    SourceIp = "10.0.0.21", FromHost = "WS02", Flags = ["Account change: bob, then alice"] },
            new() { Number = 2, Result = RdpTrace.EndOfChain, ToHost = "WS02", TimeUtc = start.StartUtc.AddMinutes(-20),
                    Account = "bob", SourceIp = "203.0.113.7" }
        ];
        var trace = new RdpTraceResult(start, hops, "From DC01 back to 203.0.113.7 in 2 hops.", "203.0.113.7",
                                       ["alice", "bob"], [], ["DC01"]);

        RdpTrace.Save(dir.Path, trace, []);

        var html = Report(dir);
        Assert.Contains("From DC01 back to 203.0.113.7 in 2 hops.", html);
        Assert.Contains("RDP chain ends at an external IP", html);
        Assert.Contains("node ext", html);
        Assert.Contains("Account change: bob, then alice", html);
    }

    [Fact]
    public void After_a_run_each_processed_host_shows_how_its_modules_ended()
    {
        using var dir = Case();
        var report = new RunReport { CaseDirectory = dir.Path, LogDirectory = Path.Combine(dir.Path, "_Logs") };
        report.Results.Add(new WorkResult { Collection = "DC01", Module = "PECmd", Category = "ProgramExecution", Status = WorkStatus.Completed });
        report.Results.Add(new WorkResult { Collection = "DC01", Module = "SrumECmd", Category = "SRUM", Status = WorkStatus.Failed });
        report.Results.Add(new WorkResult { Collection = "DC01", Module = "RBCmd", Category = "FileDeletion", Status = WorkStatus.Skipped });

        var result = CaseReport.AfterRun(report);

        Assert.True(result.Written, result.Message);
        var html = Report(dir);
        Assert.Contains("1 ok, 1 skipped", html);
        Assert.Contains("1 to review", html);
        // WEB01 was not in this run.
        Assert.Contains("Processed before the report existed", html);
    }

    [Fact]
    public void A_snapshot_is_dated_says_it_is_fixed_and_never_replaces_another()
    {
        using var dir = Case();
        var at = new DateTime(2026, 3, 2, 14, 5, 0, DateTimeKind.Utc);

        var first = CaseReport.ExportSnapshot(dir.Path, at);
        var second = CaseReport.ExportSnapshot(dir.Path, at);

        Assert.True(first.Written, first.Message);
        Assert.Equal("CaseReport_2026-03-02_1405.html", Path.GetFileName(first.Path));
        Assert.Equal("CaseReport_2026-03-02_1405_2.html", Path.GetFileName(second.Path));
        var html = File.ReadAllText(first.Path!);
        Assert.Contains("Snapshot: a fixed copy, not updated", html);
        Assert.DoesNotContain("Live report", html);
    }

    [Fact]
    public void Host_addresses_are_sorted_one_per_line_and_fold_away_past_three()
    {
        Assert.Equal("10.0.0.2<br>10.0.0.10<br>192.168.1.5",
                     HostsSectionAddresses("192.168.1.5, 10.0.0.10, 10.0.0.2"));

        var many = HostsSectionAddresses("fe80::1, 192.168.56.1 10.0.0.9, 192.168.10.194, 10.0.0.9");
        Assert.StartsWith("10.0.0.9<br>192.168.10.194<br>192.168.56.1<details class=\"more\"><summary>1 more</summary>fe80::1</details>", many);
    }

    [Fact]
    public void A_case_folder_that_does_not_exist_is_reported_not_thrown()
    {
        using var dir = new TempDirectory();

        var result = CaseReport.Rebuild(Path.Combine(dir.Path, "NoSuchCase"));

        Assert.False(result.Written);
        Assert.Contains("does not exist", result.Message);
    }

    [Fact]
    public void Hayabusa_and_Chainsaw_times_are_read_as_UTC()
    {
        Assert.Equal(new DateTime(2026, 3, 1, 10, 0, 0, DateTimeKind.Utc),
                     DetectionSummary.ParseTime("2026-03-01 10:00:00.123 +00:00"));
        Assert.Equal(new DateTime(2026, 3, 1, 10, 0, 0, DateTimeKind.Utc),
                     DetectionSummary.ParseTime("2026-03-01T10:00:00.123456+00:00"));
        Assert.Null(DetectionSummary.ParseTime("not a time"));
    }

    [Fact]
    public void Each_host_shows_its_time_zone_last_boot_and_when_it_was_collected()
    {
        using var dir = Case();
        // ActiveTimeBias -60 (British Summer Time), as RECmd prints a negative DWORD.
        SystemInfo(dir, "WS01", ("Hostname", "WS01"), ("ProductName", "Windows 11 Pro"),
                   ("Timezone", "GMT Standard Time"), ("TimezoneActiveBiasMinutes", "4294967236"));
        Write(dir, Path.Combine("WS01", RemoteAccess.Folder, RemoteAccess.SourcesFileName),
              "Log,Status,Events,FirstEventUtc,LastEventUtc,ClearedUtc,Input",
              "Security,used,10,2026-02-20 00:00:00,2026-03-02 00:00:00,,EventLogs\\EvtxECmd_EventLogs.csv",
              "System boots,used,4,2026-02-01 08:00:00,2026-03-01 07:00:05,,EventLogs\\EvtxECmd_EventLogs.csv");
        SystemInfo(dir, "WEB01", ("Hostname", "WEB01"), ("PRETTY_NAME", "Ubuntu 22.04.4 LTS"),
                   ("Timezone", "Europe/London"), ("LastBootUtc", "2026-02-27 06:30:00"));

        var run = new RunReport { CaseDirectory = dir.Path, LogDirectory = Path.Combine(dir.Path, "_Logs") };
        run.Results.Add(new WorkResult { Collection = "WS01", Module = "PECmd", Category = "ProgramExecution", Status = WorkStatus.Completed });
        run.Results.Add(new WorkResult { Collection = "WEB01", Module = "LinuxAuth", Category = "Linux", Status = WorkStatus.Completed });
        run.CollectorTimes["WS01"] = new CollectorTimes
        {
            CollectedUtc = new DateTime(2026, 3, 2, 9, 15, 0, DateTimeKind.Utc),
            CollectedFrom = "Velociraptor client_info.json (ClientStart)"
        };
        run.CollectorTimes["WEB01"] = new CollectorTimes
        {
            CollectedUtc = new DateTime(2026, 3, 2, 9, 40, 0, DateTimeKind.Utc),
            CollectedFrom = "when WEB01.zip was last written; the collector recorded no time",
            CollectedApprox = true
        };
        CaseReport.AfterRun(run);

        var html = Report(dir);
        Assert.Contains("GMT Standard Time (UTC+01:00)", html);
        Assert.Contains("Europe/London", html);
        Assert.Contains(">2026-03-01 07:00:05<", html);   // WS01: the newest System log boot
        Assert.Contains(">2026-02-27 06:30:00<", html);   // WEB01: wtmp
        Assert.Contains(">2026-03-02 09:15:00<", html);
        Assert.Contains("From Velociraptor client_info.json (ClientStart)", html);
        Assert.Contains(">Approx</span>", html);
        Assert.Contains("Not recorded", html);   // DC01 was not processed by this run

        // A later run that skipped WS01's zip as done records no times for it; the first run's stand.
        var again = new RunReport { CaseDirectory = dir.Path, LogDirectory = Path.Combine(dir.Path, "_Logs") };
        again.Results.Add(new WorkResult { Collection = "WS01", Module = "RBCmd", Category = "FileDeletion", Status = WorkStatus.Completed });
        CaseReport.AfterRun(again);
        Assert.Contains(">2026-03-02 09:15:00<", Report(dir));
    }

    [Fact]
    public void Known_addresses_are_labelled_from_the_case_file_and_the_summaries_and_bad_lines_are_raised()
    {
        using var dir = Case();
        Write(dir, KnownAddresses.FileName,
              "Address,Label,Note",
              "# Remote access ranges",
              "10.0.0.0/8,Office LAN,",
              "203.0.113.0/24,VPN,Remote access pool",
              "not-an-ip,Bad,",
              "10.1.2.3/8,Typo,");

        CaseReport.Rebuild(dir.Path);

        var html = Report(dir);
        // DC01's own address: its role makes it DC, which is more specific than the office range.
        Assert.Contains("10.0.0.10 <span class=\"pill p-tag\" title=\"Domain controller DC01. From system summary\">DC</span>", html);
        Assert.Contains(">Remote access pool<", html);
        Assert.Contains("line 5: not-an-ip is not an IP address", html);
        Assert.Contains("line 6: 10.1.2.3/8 is not an IP address", html);
        Assert.Contains("Lines of KnownAddresses.csv not read", html);
    }

    [Fact]
    public void Addresses_in_the_IP_history_link_to_it_and_the_RDP_trace_shows_their_labels()
    {
        using var dir = Case();
        Write(dir, KnownAddresses.FileName, "Address,Label,Note", "203.0.113.0/24,VPN,Remote access pool");
        Write(dir, IpHistory.FileName,
              string.Join(",", IpHistoryRecord.Columns),
              "10.0.0.10,DC01,DC01$,,2026-03-01 08:00:00,2026-03-01 18:00:00,Kerberos,12,DC01",
              "10.0.0.21,WS02,WS02$,,2026-03-01 08:00:00,2026-03-01 18:00:00,Kerberos,4,DC01");
        var start = new RdpSession("DC01", "DC01", new DateTime(2026, 3, 1, 10, 0, 0, DateTimeKind.Utc), null, "Logon",
                                   "alice", "10.0.0.21", "WS02", []);
        RdpHop[] hops =
        [
            new() { Number = 1, Result = RdpTrace.Confirmed, ToHost = "DC01", TimeUtc = start.StartUtc, Account = "alice",
                    SourceIp = "10.0.0.21", FromHost = "WS02" },
            new() { Number = 2, Result = RdpTrace.EndOfChain, ToHost = "WS02", TimeUtc = start.StartUtc.AddMinutes(-20),
                    Account = "bob", SourceIp = "203.0.113.7" }
        ];
        RdpTrace.Save(dir.Path, new RdpTraceResult(start, hops, "From DC01 back to 203.0.113.7 in 2 hops.", "203.0.113.7",
                                                   ["alice", "bob"], [], ["DC01"]), []);

        var html = Report(dir);
        Assert.Contains("<a class=\"ip\" href=\"#ips\" data-ip=\"10.0.0.21\"", html);
        Assert.Contains("<a class=\"ip\" href=\"#ips\" data-ip=\"10.0.0.10\"", html);
        // Not in the IP history, so not a link; but labelled, on the hop and on its finding.
        Assert.DoesNotContain("data-ip=\"203.0.113.7\"", html);
        Assert.Contains("203.0.113.7 <span class=\"pill p-tag\"", html);
        Assert.Contains("Known as VPN.", html);
        Assert.Contains("window.ipLookup", html);
    }

    [Fact]
    public void The_most_specific_known_address_wins_and_the_analysts_label_wins_a_tie()
    {
        using var dir = Case();
        SystemInfo(dir, "WS01", ("Hostname", "WS01"), ("ProductName", "Windows 11 Pro"),
                   ("IPAddresses", "10.0.0.50"), ("DnsServers", "10.0.0.10, 10.0.0.53"), ("Gateways", "10.0.0.1"));
        Write(dir, KnownAddresses.FileName, "Address,Label,Note", "10.0.0.0/24,Server VLAN,", "10.0.0.53,Resolver,Pi-hole");
        var hosts = IocSweep.Hosts(dir.Path)
            .Select(h => new ReportHost(h, Path.Combine(dir.Path, h),
                SystemInventory.Collect(dir.Path).Single(c => c.Collection == h).Facts))
            .ToList();

        var known = KnownAddresses.Load(dir.Path, hosts);

        Assert.Equal("DC", known.For("10.0.0.10")?.Label);          // a DC that is also a DNS server
        Assert.Equal("Resolver", known.For("10.0.0.53")?.Label);    // the analyst's, over "DNS"
        Assert.Equal("Gateway", known.For("10.0.0.1")?.Label);
        Assert.Equal("Server VLAN", known.For("10.0.0.50")?.Label);
        Assert.Equal("Server VLAN", known.For("::ffff:10.0.0.99")?.Label);
        Assert.Null(known.For("192.168.1.1"));
        Assert.Null(known.For("not an address"));
    }

    [Fact]
    public void Known_addresses_file_is_created_with_its_header_and_never_overwritten()
    {
        using var dir = new TempDirectory();

        var path = KnownAddresses.EnsureFile(dir.Path);
        Assert.StartsWith("Address,Label,Note", File.ReadAllText(path).TrimStart('﻿'));
        File.WriteAllText(path, "Address,Label,Note\n10.8.0.0/16,VPN,\n");
        KnownAddresses.EnsureFile(dir.Path);
        Assert.Contains("10.8.0.0/16,VPN", File.ReadAllText(path));
        Assert.Empty(KnownAddresses.Load(dir.Path, []).Problems);
    }

    private static string HostsSectionAddresses(string addresses) =>
        (string)typeof(CaseReport).Assembly.GetType("ArtefactForge.Core.Report.HostsSection")!
            .GetMethod("AddressList", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!
            .Invoke(null, [addresses, null])!;
}
