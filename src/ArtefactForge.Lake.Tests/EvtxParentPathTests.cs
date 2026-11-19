using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

/// <summary>
/// evtxecmd mapping version 2: a process start's parent in the timeline's parent_path, from the
/// Payload's ParentProcessName (Security 4688) or ParentImage (Sysmon 1). Made-up events with
/// EvtxECmd's header.
/// </summary>
public class EvtxParentPathTests
{
    private static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    private static string Data(params (string Name, string? Text)[] items) =>
        "{\"EventData\":{\"Data\":[" + string.Join(",", items.Select(i => i.Text is null
            ? $"{{\"@Name\":\"{i.Name}\"}}"
            : $"{{\"@Name\":\"{i.Name}\",\"#text\":\"{i.Text.Replace("\\", "\\\\")}\"}}")) + "]}}";

    private static Dictionary<string, string> Event(string record, string time, string channel, string id, string executable, string payload) => new()
    {
        ["RecordNumber"] = record, ["EventRecordId"] = record, ["TimeCreated"] = time, ["EventId"] = id, ["Channel"] = channel,
        ["Provider"] = "p", ["Computer"] = "HOST01", ["ExecutableInfo"] = executable, ["SourceFile"] = "x.evtx", ["Payload"] = payload
    };

    [Fact]
    public void Process_starts_carry_their_parent_and_other_events_do_not()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\EventLogs\EvtxECmd_EventLogs.csv", Csv(EvtxHeader,
            Event("1", "2026-11-01 10:00:00.0000000", "Security", "4688", @"C:\Windows\System32\cmd.exe /c whoami",
                Data(("NewProcessName", @"C:\Windows\System32\cmd.exe"), ("ParentProcessName", @"C:\Windows\System32\inetsrv\w3wp.exe"))),
            Event("2", "2026-11-01 10:00:01.0000000", "Microsoft-Windows-Sysmon/Operational", "1", @"C:\Windows\System32\whoami.exe",
                Data(("Image", @"C:\Windows\System32\whoami.exe"), ("ParentImage", @"C:\Windows\System32\cmd.exe"))),
            // A 4688 whose parent was not logged (the System process starting smss, as on a real host).
            Event("3", "2026-11-01 10:00:02.0000000", "Security", "4688", @"C:\Windows\System32\smss.exe",
                Data(("NewProcessName", @"C:\Windows\System32\smss.exe"), ("ParentProcessName", null))),
            Event("4", "2026-11-01 10:00:03.0000000", "Security", "4688", @"C:\x.exe", "{not json"),
            // Not a process start: a ParentImage-looking field means nothing here.
            Event("5", "2026-11-01 10:00:04.0000000", "Security", "4624", "", Data(("ParentProcessName", @"C:\nope.exe")))));
        // An output without the Payload column still maps, with no parents.
        temp.Write(@"HOST02\EventLogs\EvtxECmd_EventLogs.csv", Csv(EvtxHeader.Where(h => h != "Payload").ToArray(),
            Event("1", "2026-11-01 11:00:00.0000000", "Security", "4688", @"C:\y.exe", "")));

        var result = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false });
        using var lake = OpenLake(result.DatabasePath!);
        var rows = Rows(lake, "SELECT host, event_id, category, path, parent_path FROM timeline WHERE kind = 'evtxecmd' ORDER BY host, ts");

        Assert.Equal(6, rows.Count);
        Assert.Equal((@"C:\Windows\System32\cmd.exe", @"C:\Windows\System32\inetsrv\w3wp.exe"), ((string)rows[0]["path"]!, (string)rows[0]["parent_path"]!));
        Assert.Equal((@"C:\Windows\System32\whoami.exe", @"C:\Windows\System32\cmd.exe"), ((string)rows[1]["path"]!, (string)rows[1]["parent_path"]!));
        Assert.Null(rows[2]["parent_path"]);
        Assert.Equal("process", rows[3]["category"]);
        Assert.Null(rows[3]["parent_path"]);
        Assert.Equal("logon", rows[4]["category"]);
        Assert.Null(rows[4]["parent_path"]);
        Assert.Equal("HOST02", rows[5]["host"]);
        Assert.Null(rows[5]["parent_path"]);
        Assert.Equal(2, Convert.ToInt32(Scalar(lake, "SELECT max(mapping_version) FROM sources WHERE kind = 'evtxecmd'")));
    }
}
