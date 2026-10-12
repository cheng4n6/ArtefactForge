using ArtefactForge.Core;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Tests;

/// <summary>
/// The IP history: DHCP server logs, Kerberos and DNS audit events from EvtxECmd's output, the
/// per-collection build, the case roll-up and the "who had this address" lookup. Event rows are
/// written the way EvtxECmd writes them, Payload JSON included, with made-up hosts and addresses.
/// </summary>
public class IpHistoryTests
{
    private const string EvtxHeader =
        "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,ThreadId,Computer,"
        + "ChunkNumber,UserId,MapDescription,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,"
        + "PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,Keywords,"
        + "ExtraDataOffset,Payload";

    private static readonly string[] DhcpV4Log =
    [
        "\t\tMicrosoft DHCP Service Activity Log",
        "",
        "Event ID  Meaning",
        "00\tThe log was started.",
        "10\tA new IP address was leased to a client.",
        "ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name, TransactionID, QResult,Probationtime, CorrelationID,Dhcid,VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),RelayAgentInformation,DnsRegError.",
        "00,07/01/26,00:00:01,Started,,,,,0,6,,,,,,,,,0",
        "10,07/01/26,09:15:00,Assign,10.0.0.25,host01.corp.example,0050569A1B2C,,1234,0,,,,,,,,,0",
        "11,07/01/26,13:15:00,Renew,10.0.0.25,host01.corp.example,0050569A1B2C,,1235,0,,,,,,,,,0",
        "30,07/01/26,13:15:01,DNS Update Request,10.0.0.25,host01.corp.example,,,0,6,,,,,,,,,0",
        "10,99/99/26,13:15:00,Assign,10.0.0.26,host02.corp.example,0050569A1B2D,,1236,0,,,,,,,,,0"
    ];

    private static string Payload(params (string Name, string Value)[] data) =>
        "\"{\"\"EventData\"\":{\"\"Data\"\":["
        + string.Join(",", data.Select(d => $"{{\"\"@Name\"\":\"\"{d.Name}\"\",\"\"#text\"\":\"\"{d.Value}\"\"}}"))
        + "]}}\"";

    private static string Event(string time, int id, string provider, string channel, string payload) =>
        $"1,1,{time},{id},Info,{provider},{channel},4,8,DC01,0,,,,,,,,,,,,False,C:\\x\\Security.evtx,Audit success,0,{payload}";

    private static string Kerberos(string time, int id, string account, string address, string status = "0x0") =>
        Event(time, id, "Microsoft-Windows-Security-Auditing", "Security",
              Payload(("TargetUserName", account), ("TargetDomainName", "CORP"), ("IpAddress", address), ("Status", status)));

    private static string DnsAudit(string time, int id, string name, string rdata) =>
        Event(time, id, "Microsoft-Windows-DNSServer", "Microsoft-Windows-DNSServer/Audit",
              Payload(("Type", "1"), ("NAME", name), ("TTL", "1200"), ("RDATA", rdata), ("Zone", "corp.example")));

    private static void WriteEvtx(TempDirectory dir, string collection, params string[] events)
    {
        var folder = dir.Dir(Path.Combine(collection, "EventLogs"));
        File.WriteAllLines(Path.Combine(folder, "EvtxECmd_EventLogs.csv"), [EvtxHeader, .. events]);
    }

    private static void WriteSummary(TempDirectory dir, string collection, string role, string host, string addresses)
    {
        var folder = dir.Dir(Path.Combine(collection, "SystemInfo"));
        File.WriteAllLines(Path.Combine(folder, "SystemInfo.csv"),
        [
            "\"Category\",\"Item\",\"Value\",\"Source\"",
            $"\"Identity\",\"Hostname\",\"{host}\",\"SYSTEM\"",
            $"\"Identity\",\"ComputerRole\",\"{role}\",\"SYSTEM\"",
            $"\"Network\",\"IPAddresses\",\"{addresses}\",\"SYSTEM\""
        ]);
    }

    private static Dictionary<string, Dictionary<string, string>> Sources(TempDirectory dir, string collection) =>
        CsvReader.Read(Path.Combine(dir.Path, collection, IpHistory.Folder, IpHistory.SourcesFileName))
                 .ToDictionary(r => r["Source"]);

    // --- DHCP server logs ---------------------------------------------------------------------

    [Fact]
    public void Dhcp_log_keeps_lease_events_and_converts_local_time_to_utc()
    {
        var zone = TimeZoneInfo.FindSystemTimeZoneById("GMT Standard Time");   // BST in July

        var events = DhcpServerLogExport.Parse(DhcpV4Log, zone, out var unreadable);

        Assert.Equal(2, events.Count);                       // log start and DNS update left out
        Assert.Equal(1, unreadable);                         // 99/99/26
        var assign = events[0];
        Assert.Equal(10, assign.EventId);
        Assert.Equal("10.0.0.25", assign.IpAddress);
        Assert.Equal("host01.corp.example", assign.HostName);
        Assert.Equal("00-50-56-9A-1B-2C", assign.MacAddress);
        Assert.Equal(new DateTime(2026, 7, 1, 9, 15, 0), assign.LocalTime);
        Assert.Equal(new DateTime(2026, 7, 1, 8, 15, 0), assign.TimeUtc);
    }

    [Fact]
    public void Dhcp_log_without_a_time_zone_leaves_utc_empty_rather_than_guessing()
    {
        var events = DhcpServerLogExport.Parse(DhcpV4Log, null, out _);

        Assert.All(events, e => Assert.Null(e.TimeUtc));
        Assert.Equal(new DateTime(2026, 7, 1, 9, 15, 0), events[0].LocalTime);
    }

    [Fact]
    public void Dhcpv6_log_is_read_by_its_own_column_names()
    {
        string[] log =
        [
            "ID,Date,Time,Description,IPV6 Address,Host Name,Error Code, Duid Length, Duid Bytes(Hex),User Name,Dhcid,Subnet Prefix.",
            "11000,07/01/26,09:15:00,Solicit,fd00::25,host01.corp.example,,14,0001000123456789,,,fd00::"
        ];

        var e = Assert.Single(DhcpServerLogExport.Parse(log, TimeZoneInfo.Utc, out _));

        Assert.Equal("DHCPv6", e.Protocol);
        Assert.Equal("fd00::25", e.IpAddress);
        Assert.Equal("0001000123456789", e.Duid);
        Assert.Equal("", e.MacAddress);
    }

    [Fact]
    public async Task Dhcp_module_reports_a_missing_time_zone_so_the_run_is_reviewed()
    {
        using var dir = new TempDirectory();
        var log = dir.File(Path.Combine("root", "Windows", "System32", "dhcp", "DhcpSrvLog-Wed.log"));
        File.WriteAllLines(log, DhcpV4Log);
        var stdout = Path.Combine(dir.Path, "o.log");
        var stderr = Path.Combine(dir.Path, "e.log");

        var outcome = await Builtins.RunAsync("builtin:WindowsDhcpServerLog",
            $"--root \"{Path.Combine(dir.Path, "root")}\" --out \"{dir.Dir("out")}\"", stdout, stderr, null, CancellationToken.None);

        Assert.Equal(0, outcome.ExitCode);
        Assert.True(outcome.WroteToStderr);
        Assert.Contains("no SYSTEM hive", File.ReadAllText(stderr));
        var rows = CsvReader.Read(Path.Combine(dir.Path, "out", DhcpServerLogExport.OutputFile));
        Assert.Equal(2, rows.Count);
        Assert.Equal("", rows[0]["TimeUtc"]);
        Assert.Equal("2026-07-01 09:15:00", rows[0]["LocalTime"]);
        Assert.Equal("Windows/System32/dhcp/DhcpSrvLog-Wed.log", rows[0]["SourceFile"]);
    }

    // --- event log --------------------------------------------------------------------------------

    [Fact]
    public void Kerberos_events_tie_computer_accounts_to_addresses()
    {
        using var dir = new TempDirectory();
        WriteEvtx(dir, "DC01",
            Kerberos("2026-07-01 08:00:00.1234567", 4768, "HOST01$", "::ffff:10.0.0.25"),
            Kerberos("2026-07-01 10:00:00.0000000", 4769, "HOST01$@CORP.EXAMPLE", "::ffff:10.0.0.25"),
            Kerberos("2026-07-01 09:00:00.0000000", 4768, "alice", "10.0.0.25"),
            Kerberos("2026-07-01 09:30:00.0000000", 4768, "HOST09$", "10.0.0.99", status: "0x18"),
            Kerberos("2026-07-01 09:31:00.0000000", 4769, "DC01$@CORP.EXAMPLE", "::1"),
            Kerberos("2026-07-01 09:32:00.0000000", 4769, "DC01$@CORP.EXAMPLE", "-"));

        var found = IpHistory.ReadEventLog(Path.Combine(dir.Path, "DC01", "EventLogs", "EvtxECmd_EventLogs.csv"), "DC01");

        Assert.True(found.SecuritySeen);
        Assert.Equal(3, found.Kerberos.Events);              // refused, loopback and local left out
        var rows = found.Kerberos.Rows.OrderBy(r => r.Account).ToList();
        var host = rows.Single(r => r.Account == "HOST01$");
        Assert.Equal("10.0.0.25", host.IpAddress);
        Assert.Equal("HOST01", host.HostName);
        Assert.Equal(new DateTime(2026, 7, 1, 8, 0, 0), host.FirstSeenUtc);
        Assert.Equal(new DateTime(2026, 7, 1, 10, 0, 0), host.LastSeenUtc);
        Assert.Equal(2, host.EventCount);
        var user = rows.Single(r => r.Account == "alice");
        Assert.Equal("", user.HostName);
    }

    [Fact]
    public void Dns_audit_record_events_map_names_to_addresses()
    {
        using var dir = new TempDirectory();
        WriteEvtx(dir, "DC01",
            DnsAudit("2026-07-01 08:00:00.0000000", 519, "host03.corp.example.", "0x0A000007"),
            DnsAudit("2026-07-02 08:00:00.0000000", 520, "host03.corp.example.", "0x0A000007"));

        var found = IpHistory.ReadEventLog(Path.Combine(dir.Path, "DC01", "EventLogs", "EvtxECmd_EventLogs.csv"), "DC01");

        Assert.True(found.DnsAuditSeen);
        var row = Assert.Single(found.Dns.Rows);
        Assert.Equal("10.0.0.7", row.IpAddress);
        Assert.Equal("host03.corp.example", row.HostName);
        Assert.Equal(2, row.EventCount);
    }

    [Theory]
    [InlineData("0x0A000005", "10.0.0.5")]
    [InlineData("C0A80A01", "192.168.10.1")]
    [InlineData("10.0.0.9", "10.0.0.9")]
    [InlineData("0xFD000000000000000000000000000025", "fd00::25")]
    [InlineData("host.corp.example", null)]
    public void Dns_rdata_is_read_as_hex_or_as_an_address(string rdata, string? expected) =>
        Assert.Equal(expected, IpHistory.DnsRecordAddress(rdata));

    [Fact]
    public void Event_data_reads_a_single_data_element_as_well_as_a_list()
    {
        var one = IpHistory.EventData("{\"EventData\":{\"Data\":{\"@Name\":\"IpAddress\",\"#text\":\"10.0.0.1\"}}}");
        var unnamed = IpHistory.EventData("{\"EventData\":{\"Data\":\"text\"}}");

        Assert.Equal("10.0.0.1", one["IpAddress"]);
        Assert.Empty(unnamed);
        Assert.Empty(IpHistory.EventData("not json"));
    }

    // --- per collection ---------------------------------------------------------------------------

    [Fact]
    public void Domain_controller_gets_a_history_and_says_which_sources_were_absent()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "DC01", "Domain controller", "DC01", "10.0.0.2");
        WriteEvtx(dir, "DC01", Kerberos("2026-07-01 08:00:00.0000000", 4768, "HOST01$", "10.0.0.25"));

        var result = IpHistory.BuildCollection(Path.Combine(dir.Path, "DC01"));

        Assert.NotNull(result);
        Assert.Equal(WorkStatus.Completed, result!.Status);
        Assert.Contains("DHCP: not present", result.Reason);
        var row = Assert.Single(CsvReader.Read(Path.Combine(dir.Path, "DC01", IpHistory.Folder, IpHistory.FileName)));
        Assert.Equal("HOST01", row["HostName"]);
        Assert.Equal("Kerberos", row["Source"]);
        Assert.Equal("DC01", row["Collection"]);
        var sources = Sources(dir, "DC01");
        Assert.Equal("used", sources["Kerberos"]["Status"]);
        Assert.Equal("2026-07-01 08:00:00", sources["Kerberos"]["FirstSeenUtc"]);
        Assert.StartsWith("not present", sources["DHCP"]["Status"]);
        Assert.StartsWith("not present", sources["DNS audit"]["Status"]);
    }

    [Fact]
    public void Header_columns_are_the_documented_ones_in_order()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "DC01", "Domain controller", "DC01", "10.0.0.2");
        WriteEvtx(dir, "DC01", Kerberos("2026-07-01 08:00:00.0000000", 4768, "HOST01$", "10.0.0.25"));

        IpHistory.BuildCollection(Path.Combine(dir.Path, "DC01"));

        var header = File.ReadLines(Path.Combine(dir.Path, "DC01", IpHistory.Folder, IpHistory.FileName)).First();
        Assert.Equal("\"IpAddress\",\"HostName\",\"Account\",\"MacAddress\",\"FirstSeenUtc\",\"LastSeenUtc\","
                     + "\"Source\",\"EventCount\",\"Collection\"", header);
    }

    [Fact]
    public void Workstation_is_left_alone()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "WS01", "Workstation", "WS01", "10.0.0.25");
        WriteEvtx(dir, "WS01", Kerberos("2026-07-01 08:00:00.0000000", 4769, "WS01$@CORP.EXAMPLE", "10.0.0.25"));

        Assert.Null(IpHistory.BuildCollection(Path.Combine(dir.Path, "WS01")));
        Assert.False(Directory.Exists(Path.Combine(dir.Path, "WS01", IpHistory.Folder)));
    }

    [Fact]
    public void Without_a_summary_kerberos_events_identify_a_domain_controller()
    {
        using var dir = new TempDirectory();
        WriteEvtx(dir, "DC02", Kerberos("2026-07-01 08:00:00.0000000", 4768, "HOST01$", "10.0.0.25"));

        var result = IpHistory.BuildCollection(Path.Combine(dir.Path, "DC02"));

        Assert.Equal(WorkStatus.Completed, result!.Status);
        Assert.Contains("Kerberos events in its Security log", result.Reason);
    }

    [Fact]
    public void Domain_controller_with_no_kerberos_events_is_flagged_for_review()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "DC01", "Domain controller", "DC01", "10.0.0.2");
        WriteEvtx(dir, "DC01",
            Kerberos("2026-07-01 08:00:00.0000000", 4624, "alice", "10.0.0.25"),
            DnsAudit("2026-07-01 08:00:00.0000000", 515, "host03.corp.example", "0x0A000007"));

        var result = IpHistory.BuildCollection(Path.Combine(dir.Path, "DC01"));

        Assert.Equal(WorkStatus.CheckLog, result!.Status);
        Assert.StartsWith("no events", Sources(dir, "DC01")["Kerberos"]["Status"]);
    }

    [Fact]
    public void Domain_controller_without_evtxecmd_output_is_skipped_with_the_reason()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "DC01", "Domain controller", "DC01", "10.0.0.2");

        var result = IpHistory.BuildCollection(Path.Combine(dir.Path, "DC01"));

        Assert.Equal(WorkStatus.Skipped, result!.Status);
        Assert.Contains("EvtxECmd", result.Reason);
    }

    [Fact]
    public void Dhcp_output_is_merged_into_the_domain_controller_history()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "DC01", "Domain controller", "DC01", "10.0.0.2");
        WriteEvtx(dir, "DC01", Kerberos("2026-07-01 08:00:00.0000000", 4768, "HOST01$", "10.0.0.25"));
        var dhcp = dir.Dir(Path.Combine("DC01", IpHistory.Folder));
        File.WriteAllLines(Path.Combine(dhcp, DhcpServerLogExport.OutputFile),
        [
            string.Join(",", DhcpServerLogExport.Columns.Select(c => $"\"{c}\"")),
            "\"2026-07-01 08:15:00\",\"2026-07-01 09:15:00\",\"DHCP\",\"10\",\"Assign\",\"10.0.0.25\",\"host01.corp.example\",\"00-50-56-9A-1B-2C\",\"\",\"x\""
        ]);

        var result = IpHistory.BuildCollection(Path.Combine(dir.Path, "DC01"));

        Assert.Equal(WorkStatus.Completed, result!.Status);
        var rows = CsvReader.Read(Path.Combine(dir.Path, "DC01", IpHistory.Folder, IpHistory.FileName));
        Assert.Equal(["Kerberos", "DHCP"], rows.Select(r => r["Source"]));     // by first seen
        Assert.Equal("00-50-56-9A-1B-2C", rows[1]["MacAddress"]);
        Assert.Equal("used", Sources(dir, "DC01")["DHCP"]["Status"]);
    }

    [Fact]
    public void Unchanged_inputs_are_not_rebuilt_and_a_newer_input_is()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "DC01", "Domain controller", "DC01", "10.0.0.2");
        WriteEvtx(dir, "DC01", Kerberos("2026-07-01 08:00:00.0000000", 4768, "HOST01$", "10.0.0.25"));
        var collection = Path.Combine(dir.Path, "DC01");
        IpHistory.BuildCollection(collection);

        var again = IpHistory.BuildCollection(collection);
        Assert.Equal(WorkStatus.Skipped, again!.Status);
        Assert.Contains("unchanged", again.Reason);

        var evtx = Path.Combine(collection, "EventLogs", "EvtxECmd_EventLogs.csv");
        File.SetLastWriteTimeUtc(evtx, DateTime.UtcNow.AddMinutes(5));
        Assert.Equal(WorkStatus.Completed, IpHistory.BuildCollection(collection)!.Status);
    }

    // --- case roll-up -----------------------------------------------------------------------------

    [Fact]
    public void Case_rollup_merges_domain_controllers_and_adds_each_hosts_own_addresses()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "DC01", "Domain controller", "DC01", "10.0.0.2");
        WriteSummary(dir, "DC02", "Domain controller", "DC02", "10.0.0.3");
        WriteSummary(dir, "WS01", "Workstation", "WS01", "10.0.0.40, 127.0.0.1");
        WriteEvtx(dir, "DC01", Kerberos("2026-07-01 08:00:00.0000000", 4768, "HOST01$", "10.0.0.25"));
        WriteEvtx(dir, "DC02", Kerberos("2026-07-02 08:00:00.0000000", 4768, "HOST01$", "10.0.0.25"));
        dir.Dir("_Logs");

        var results = IpHistory.Build(dir.Path);

        Assert.Equal(2, results.Count);                      // the workstation adds no result
        var rows = CsvReader.Read(Path.Combine(dir.Path, IpHistory.FileName));
        var kerberos = Assert.Single(rows, r => r["Source"] == "Kerberos");
        Assert.Equal("2026-07-01 08:00:00", kerberos["FirstSeenUtc"]);
        Assert.Equal("2026-07-02 08:00:00", kerberos["LastSeenUtc"]);
        Assert.Equal("2", kerberos["EventCount"]);
        Assert.Equal("DC01; DC02", kerberos["Collection"]);
        var own = rows.Where(r => r["Source"] == "SystemInfo").ToList();
        Assert.Equal(["10.0.0.2", "10.0.0.3", "10.0.0.40"], own.Select(r => r["IpAddress"]));
        Assert.Equal("", own[0]["FirstSeenUtc"]);
    }

    [Fact]
    public void Case_without_a_domain_controller_gets_no_rollup()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "WS01", "Workstation", "WS01", "10.0.0.40");

        Assert.Empty(IpHistory.Build(dir.Path));
        Assert.False(File.Exists(Path.Combine(dir.Path, IpHistory.FileName)));
    }

    // --- lookup -----------------------------------------------------------------------------------

    private static IpHistoryRecord Row(string host, string first, string last, string source = "Kerberos",
                                       string address = "10.0.0.25") =>
        new(address, host, host.Length > 0 ? host + "$" : "alice", "", DateTime.Parse(first), DateTime.Parse(last),
            source, 1, "DC01");

    [Fact]
    public void Lookup_follows_an_address_that_dhcp_gave_to_another_machine()
    {
        IpHistoryRecord[] rows =
        [
            Row("HOST01", "2026-07-01 08:00", "2026-07-01 17:00"),
            Row("HOST02", "2026-07-02 08:00", "2026-07-02 17:00"),
            Row("", "2026-07-01 08:00", "2026-07-02 17:00")
        ];

        Assert.Equal("HOST01", IpHistoryLookup.Find(rows, "10.0.0.25", new DateTime(2026, 7, 1, 12, 0, 0)).Best!.HostName);
        Assert.Equal("HOST02", IpHistoryLookup.Find(rows, "::ffff:10.0.0.25", new DateTime(2026, 7, 2, 12, 0, 0)).Best!.HostName);
        // Between the two, the nearer sighting wins.
        Assert.Equal("HOST02", IpHistoryLookup.Find(rows, "10.0.0.25", new DateTime(2026, 7, 2, 7, 0, 0)).Best!.HostName);
        Assert.Empty(IpHistoryLookup.Find(rows, "10.0.0.25", new DateTime(2026, 7, 1, 12, 0, 0)).Conflicts);
        Assert.Null(IpHistoryLookup.Find(rows, "10.0.0.99", null).Best);
    }

    [Fact]
    public void Lookup_returns_overlapping_hosts_as_conflicts_and_prefers_dhcp()
    {
        IpHistoryRecord[] rows =
        [
            Row("HOST01", "2026-07-01 08:00", "2026-07-01 17:00"),
            Row("host02.corp.example", "2026-07-01 10:00", "2026-07-01 11:00", source: "DHCP"),
            Row("HOST02", "2026-07-01 09:00", "2026-07-01 12:00", source: "DNS audit")
        ];

        var result = IpHistoryLookup.Find(rows, "10.0.0.25", new DateTime(2026, 7, 1, 10, 30, 0));

        Assert.Equal("DHCP", result.Best!.Source);
        var conflict = Assert.Single(result.Conflicts);      // HOST02 by DNS is the same machine
        Assert.Equal("HOST01", conflict.HostName);
    }
}
