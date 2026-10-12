using ArtefactForge.Core;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Tests;

/// <summary>
/// The per-host remote access file and the RDP trace built on it. Event rows are written the way
/// EvtxECmd writes them, Payload JSON included, with made-up hosts, accounts and addresses
/// (documentation ranges for anything external).
/// </summary>
public class RdpTraceTests
{
    private const string EvtxHeader =
        "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,ThreadId,Computer,"
        + "ChunkNumber,UserId,MapDescription,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,"
        + "PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,Keywords,"
        + "ExtraDataOffset,Payload";

    private const string Rcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
    private const string Lsm = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    private const string RdpCore = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
    private const string Client = "Microsoft-Windows-TerminalServices-RDPClient/Operational";

    private static string EventData(params (string Name, string Value)[] data) =>
        "\"{\"\"EventData\"\":{\"\"Data\"\":["
        + string.Join(",", data.Select(d => $"{{\"\"@Name\"\":\"\"{d.Name}\"\",\"\"#text\"\":\"\"{d.Value}\"\"}}"))
        + "]}}\"";

    private static string UserData(params (string Name, string Value)[] data) =>
        "\"{\"\"UserData\"\":{\"\"EventXML\"\":{\"\"@xmlns\"\":\"\"Event_NS\"\","
        + string.Join(",", data.Select(d => $"\"\"{d.Name}\"\":\"\"{d.Value}\"\""))
        + "}}}\"";

    private static string Event(string computer, string time, int id, string channel, string payload) =>
        $"1,1,{time}.0000000,{id},Info,Provider,{channel},4,8,{computer},0,,,,,,,,,,,,False,C:\\x\\log.evtx,,0,{payload}";

    private static string Logon(string computer, string time, string user, string address, string workstation) =>
        Event(computer, time, 4624, "Security", EventData(("TargetUserName", user), ("TargetDomainName", "CORP"),
              ("LogonType", "10"), ("IpAddress", address), ("WorkstationName", workstation), ("TargetLogonId", "0x1234")));

    private static string Authenticated(string computer, string time, string user, string address) =>
        Event(computer, time, 1149, Rcm, UserData(("Param1", user), ("Param2", "CORP"), ("Param3", address)));

    private static string SessionLogon(string computer, string time, string user, string address) =>
        Event(computer, time, 21, Lsm, UserData(("User", "CORP\\\\" + user), ("SessionID", "2"), ("Address", address)));

    private static string TcpAccepted(string computer, string time, string addressAndPort) =>
        Event(computer, time, 131, RdpCore, EventData(("ConnType", "TCP"), ("ClientIP", addressAndPort)));

    private static string Connecting(string computer, string time, string server) =>
        Event(computer, time, 1024, Client, EventData(("Value", server), ("CustomLevel", "Info")));

    private static void WriteHost(TempDirectory dir, string host, string addresses, params string[] events)
    {
        var info = dir.Dir(Path.Combine(host, "SystemInfo"));
        File.WriteAllLines(Path.Combine(info, "SystemInfo.csv"),
        [
            "\"Category\",\"Item\",\"Value\",\"Source\"",
            $"\"Identity\",\"Hostname\",\"{host}\",\"SYSTEM\"",
            $"\"Network\",\"IPAddresses\",\"{addresses}\",\"SYSTEM\""
        ]);
        var logs = dir.Dir(Path.Combine(host, "EventLogs"));
        File.WriteAllLines(Path.Combine(logs, "EvtxECmd_EventLogs.csv"), [EvtxHeader, .. events]);
    }

    /// <summary>
    /// An outside address logs on to WS01, which connects to SRV01, which connects to DC01.
    /// </summary>
    private static void WriteChain(TempDirectory dir, string srv01ConnectsAt = "2026-07-01 11:59:55")
    {
        WriteHost(dir, "DC01", "10.0.0.10",
            TcpAccepted("dc01.corp.example", "2026-07-01 11:59:57", "10.0.0.30:50123"),
            Authenticated("dc01.corp.example", "2026-07-01 11:59:58", "admin", "10.0.0.30"),
            Logon("dc01.corp.example", "2026-07-01 12:00:00", "admin", "10.0.0.30", "SRV01"),
            SessionLogon("dc01.corp.example", "2026-07-01 12:00:02", "admin", "10.0.0.30"));
        WriteHost(dir, "SRV01", "10.0.0.30",
            Logon("srv01.corp.example", "2026-07-01 11:30:00", "alice", "10.0.0.21", "WS01"),
            Connecting("srv01.corp.example", srv01ConnectsAt, "dc01"));
        WriteHost(dir, "WS01", "10.0.0.21",
            Logon("ws01.corp.example", "2026-07-01 10:00:00", "alice", "203.0.113.50", "kali"),
            Connecting("ws01.corp.example", "2026-07-01 11:29:56", "srv01.corp.example"));
    }

    private static RdpSession SessionOn(string caseDir, string host) =>
        RdpTrace.FindSessions(RdpTrace.LoadHosts(caseDir), host).First();

    [Fact]
    public void Events_from_one_connection_are_joined_into_one_session()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);

        var sessions = RdpTrace.FindSessions(RdpTrace.LoadHosts(dir.Path), "dc01");

        var session = Assert.Single(sessions);
        Assert.Equal("DC01", session.Host);
        Assert.Equal(new DateTime(2026, 7, 1, 11, 59, 58, DateTimeKind.Utc), session.StartUtc);
        Assert.Equal("CORP\\admin", session.Account);
        Assert.Equal("10.0.0.30", session.SourceIp);
        Assert.Equal("SRV01", session.ClientName);
        Assert.Equal("Logon", session.Kind);
        Assert.Equal(["RCM 1149", "Security 4624", "LSM 21", "RdpCoreTS 131"], session.Evidence);
    }

    [Fact]
    public void Sessions_are_filtered_by_time_address_and_account()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);
        var hosts = RdpTrace.LoadHosts(dir.Path);
        var noon = new DateTime(2026, 7, 1, 12, 0, 0, DateTimeKind.Utc);

        Assert.Equal(3, RdpTrace.FindSessions(hosts).Count);
        Assert.Equal(2, RdpTrace.FindSessions(hosts, fromUtc: noon.AddHours(-1), toUtc: noon).Count);
        Assert.Equal("WS01", Assert.Single(RdpTrace.FindSessions(hosts, sourceIp: "203.0.113.50")).Host);
        Assert.Equal(2, RdpTrace.FindSessions(hosts, account: "ALICE").Count);
    }

    [Fact]
    public void Trace_follows_the_chain_back_to_an_external_address()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);

        var trace = RdpTrace.Trace(dir.Path, SessionOn(dir.Path, "DC01"));

        Assert.Collection(trace.Hops,
            h =>
            {
                Assert.Equal(RdpTrace.Confirmed, h.Result);
                Assert.Equal(("SRV01", "DC01"), (h.FromHost, h.ToHost));
                Assert.Contains("RDPClient 1024 to dc01", h.SendingEvidence);
                Assert.Equal("+00:00:03", h.ClockOffset);
            },
            h =>
            {
                Assert.Equal(RdpTrace.Confirmed, h.Result);
                Assert.Equal(("WS01", "SRV01"), (h.FromHost, h.ToHost));
                Assert.Contains(h.Flags, f => f.StartsWith("account changes: CORP\\alice logs on to SRV01, CORP\\admin to DC01"));
            },
            h =>
            {
                Assert.Equal(RdpTrace.EndOfChain, h.Result);
                Assert.Equal("203.0.113.50", h.SourceIp);
                Assert.Contains("external address", h.Flags);
            });
        Assert.Equal("203.0.113.50", trace.EndAddress);
        Assert.StartsWith("3 hops, ends at external IP 203.0.113.50", trace.Summary);
        Assert.Equal(["DC01", "SRV01", "WS01"], trace.HostsUsed);
    }

    [Fact]
    public void A_source_host_not_in_the_case_is_marked_collect_next()
    {
        using var dir = new TempDirectory();
        WriteHost(dir, "DC01", "10.0.0.10",
            Logon("dc01", "2026-07-01 12:00:00", "admin", "10.0.0.30", "SRV01"));

        var trace = RdpTrace.Trace(dir.Path, SessionOn(dir.Path, "DC01"));

        var hop = Assert.Single(trace.Hops);
        Assert.Equal(RdpTrace.CollectNext, hop.Result);
        Assert.Equal("SRV01", hop.FromHost);
        Assert.Equal(["SRV01"], trace.HostsToCollect);
        Assert.Contains("1 host to collect", trace.Summary);
    }

    [Fact]
    public void Loopback_source_ends_the_chain_as_tunnelled_rdp()
    {
        using var dir = new TempDirectory();
        WriteHost(dir, "DC01", "10.0.0.10",
            Logon("dc01", "2026-07-01 12:00:00", "admin", "127.0.0.1", "DC01"));

        var hop = Assert.Single(RdpTrace.Trace(dir.Path, SessionOn(dir.Path, "DC01")).Hops);

        Assert.Equal(RdpTrace.EndOfChain, hop.Result);
        Assert.Contains(hop.Flags, f => f.StartsWith("loopback source address"));
    }

    [Fact]
    public void A_client_event_outside_the_match_window_is_inferred_with_a_clock_flag()
    {
        using var dir = new TempDirectory();
        WriteChain(dir, srv01ConnectsAt: "2026-07-01 11:50:00");

        var hop = RdpTrace.Trace(dir.Path, SessionOn(dir.Path, "DC01")).Hops[0];

        Assert.Equal(RdpTrace.Inferred, hop.Result);
        Assert.Equal("SRV01", hop.FromHost);
        Assert.Contains(hop.Flags, f => f.StartsWith("possible clock difference") && f.Contains("+00:09:58"));
    }

    [Fact]
    public void Dhcp_reuse_of_the_source_address_is_flagged()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);
        IpHistoryRecord.Write(Path.Combine(dir.Path, IpHistory.FileName),
        [
            new("10.0.0.30", "SRV01", "SRV01$", "", new DateTime(2026, 7, 1, 8, 0, 0), new DateTime(2026, 7, 1, 18, 0, 0), "Kerberos", 5, "DC01"),
            new("10.0.0.30", "LAPTOP7", "", "00AA", new DateTime(2026, 7, 1, 11, 0, 0), new DateTime(2026, 7, 1, 13, 0, 0), "DHCP", 2, "DC01")
        ]);

        var hop = RdpTrace.Trace(dir.Path, SessionOn(dir.Path, "DC01")).Hops[0];

        // The DHCP lease outranks Kerberos, but the client event on SRV01 confirms SRV01.
        Assert.Equal(("SRV01", RdpTrace.Confirmed), (hop.FromHost, hop.Result));
        Assert.Contains(hop.Flags, f => f.StartsWith("DHCP reuse: 10.0.0.30 also belonged to SRV01"));
        Assert.Contains(hop.Flags, f => f.StartsWith("the address and client name point to different machines"));
    }

    [Fact]
    public void Saved_traces_are_never_overwritten_and_are_marked_after_a_host_is_reprocessed()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);
        var hosts = RdpTrace.LoadHosts(dir.Path);
        var trace = RdpTrace.Trace(hosts, [], RdpTrace.FindSessions(hosts, "DC01")[0]);

        var first = RdpTrace.Save(dir.Path, trace, hosts);
        var second = RdpTrace.Save(dir.Path, trace, hosts);

        Assert.Equal("RdpTrace_DC01_20260701-115958.csv", Path.GetFileName(first));
        Assert.Equal("RdpTrace_DC01_20260701-115958_2.csv", Path.GetFileName(second));
        Assert.All(RdpTrace.Saved(dir.Path), s => Assert.Null(s.Stale));

        var file = Path.Combine(dir.Path, "SRV01", RemoteAccess.Folder, RemoteAccess.FileName);
        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddMinutes(5));
        Assert.All(RdpTrace.Saved(dir.Path), s => Assert.Equal("reprocessed since: SRV01", s.Stale));
        var rows = CsvReader.Read(first);
        Assert.Equal("Confirmed", rows[0]["Result"]);
        Assert.Equal("End of chain", rows[2]["Result"]);
    }

    [Fact]
    public void Remote_access_file_is_built_once_and_rebuilt_only_when_its_input_changes()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);

        var built = RemoteAccess.Build(dir.Path);
        Assert.Equal(3, built.Count);
        Assert.All(built, r => Assert.Equal(WorkStatus.Completed, r.Status));
        Assert.Empty(RemoteAccess.Build(dir.Path));

        File.SetLastWriteTimeUtc(Path.Combine(dir.Path, "WS01", "EventLogs", "EvtxECmd_EventLogs.csv"), DateTime.UtcNow.AddMinutes(5));
        Assert.Equal("WS01", Assert.Single(RemoteAccess.Build(dir.Path)).Collection);

        var sources = CsvReader.Read(Path.Combine(dir.Path, "DC01", RemoteAccess.Folder, RemoteAccess.SourcesFileName))
                               .ToDictionary(r => r["Log"]);
        Assert.Equal("used", sources["Security"]["Status"]);
        Assert.StartsWith("not present", sources["RDPClient"]["Status"]);
        Assert.StartsWith("not present", sources["Prefetch"]["Status"]);
    }

    [Fact]
    public void Cleared_logs_are_recorded_and_flagged_on_the_hop()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);
        var logs = Path.Combine(dir.Path, "SRV01", "EventLogs", "EvtxECmd_EventLogs.csv");
        File.AppendAllLines(logs, [Event("srv01", "2026-07-01 12:30:00", 1102, "Security", EventData(("SubjectUserName", "alice")))]);

        var hop = RdpTrace.Trace(dir.Path, SessionOn(dir.Path, "DC01")).Hops[0];

        Assert.Contains("SRV01: Security log cleared at 2026-07-01 12:30:00", hop.Flags);
    }

    [Fact]
    public void Outbound_artefacts_come_from_the_registry_prefetch_and_jump_lists()
    {
        using var dir = new TempDirectory();
        WriteChain(dir);
        File.WriteAllLines(Path.Combine(dir.Dir(Path.Combine("SRV01", "Registry")), "alice_RECmd_NTUSER.csv"),
        [
            "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile",
            @"x,NtUser,RDP,Remote,ROOT\Software\Microsoft\Terminal Server Client\Servers\dc01,UsernameHint,RegSz,CORP\admin,,,,False,False,2026-07-01 11:59:59,",
            @"x,NtUser,RDP,Remote,ROOT\Software\Microsoft\Terminal Server Client\Default,MRU0,RegSz,dc01,,,,False,False,2026-07-01 11:59:59,"
        ]);
        File.WriteAllLines(Path.Combine(dir.Dir(Path.Combine("SRV01", "Prefetch")), "PECmd_Output.csv"),
        [
            "SourceFilename,ExecutableName,RunCount,LastRun,PreviousRun0,PreviousRun1",
            @"C:\Windows\Prefetch\MSTSC.EXE-1234.pf,MSTSC.EXE,2,2026-07-01 11:59:50,2026-06-01 09:00:00,"
        ]);
        File.WriteAllLines(Path.Combine(dir.Dir(Path.Combine("SRV01", "JumpLists", "alice")), "20260701_AutomaticDestinations.csv"),
        [
            "SourceFile,AppId,AppIdDescription,LastModified,Path,Arguments",
            @"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1bc392b8e104a00e.automaticDestinations-ms,1bc392b8e104a00e,Remote Desktop,2026-07-01 11:59:55,,/v:dc01.corp.example"
        ]);

        var hop = RdpTrace.Trace(dir.Path, SessionOn(dir.Path, "DC01")).Hops[0];

        Assert.Contains("Registry MRU (alice) names dc01, last written 2026-07-01 11:59:59", hop.SendingEvidence);
        Assert.Contains("Jump list (alice) names dc01", hop.SendingEvidence);
        Assert.Contains("mstsc.exe (Prefetch) at 2026-07-01 11:59:50", hop.SendingEvidence);
    }

    [Theory]
    [InlineData("10.0.0.5:51234", "10.0.0.5")]
    [InlineData("[fe80::1]:51234", "fe80::1")]
    [InlineData("::ffff:10.0.0.5", "10.0.0.5")]
    [InlineData("-", "")]
    [InlineData("LOCAL", "")]
    public void Addresses_lose_their_port_and_mapping(string text, string expected) =>
        Assert.Equal(expected, RemoteAccess.CleanAddress(text));
}
