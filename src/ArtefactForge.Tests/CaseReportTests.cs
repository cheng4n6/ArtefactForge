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

    private static string HostsSectionAddresses(string addresses) =>
        (string)typeof(CaseReport).Assembly.GetType("ArtefactForge.Core.Report.HostsSection")!
            .GetMethod("AddressList", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!
            .Invoke(null, [addresses])!;
}
