using System.Text.Json;
using ArtefactForge.Lake.Contract;
using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

public sealed class LakeBuilderTests
{
    private static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    private static string LakePath(TempDirectory temp) => Path.Combine(temp.Path, "_Lake", "case.duckdb");

    [Fact]
    public void Sources_listed_in_outputs_json_are_loaded_raw_and_mapped_into_the_timeline()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.Built, result.Outcome);
        Assert.Equal(["HOST01"], result.Hosts);
        Assert.Equal(LakePath(temp), result.DatabasePath);
        using var lake = OpenLake(LakePath(temp));
        var sources = Rows(lake, "SELECT path, kind, status, parser_version, rows_loaded FROM sources ORDER BY source_id")
            .ToDictionary(r => (string)r["path"]!);
        Assert.Equal("evtxecmd", sources["EventLogs/EvtxECmd_EventLogs.csv"]["kind"]);
        Assert.Equal("pecmd.timeline", sources["Prefetch/PECmd_Output_Timeline.csv"]["kind"]);
        Assert.Equal("pecmd.output", sources["Prefetch/PECmd_Output.csv"]["kind"]);
        Assert.Equal("mftecmd.mft", sources["FileSystem/MFTECmd_MFT.csv"]["kind"]);
        Assert.Equal("mftecmd.usnjournal", sources["FileSystem/MFTECmd_USNJournal.csv"]["kind"]);
        Assert.Equal("1.0.0.0", sources["EventLogs/EvtxECmd_EventLogs.csv"]["parser_version"]);
        Assert.Equal(2L, sources["EventLogs/EvtxECmd_EventLogs.csv"]["rows_loaded"]);
        Assert.Equal(true, Scalar(lake, "SELECT manifest FROM hosts WHERE host = 'HOST01'"));
        Assert.Equal("HOST01.corp.example", Scalar(lake, "SELECT hostname FROM hosts WHERE host = 'HOST01'"));
    }

    [Fact]
    public void A_source_whose_module_did_not_complete_is_recorded_but_not_loaded()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");

        var result = LakeBuilder.Build(temp.Path, Small);

        var amcache = Assert.Single(result.Sources, s => s.Path == "Amcache/AmcacheParser_Output.csv");
        Assert.Equal(SourceStatus.Skipped, amcache.Status);
        Assert.Equal(OutputStatus.Failed, amcache.OutputStatus);
        Assert.Contains("'failed'", amcache.Reason);
        using var lake = OpenLake(LakePath(temp));
        Assert.Equal("skipped", Scalar(lake, "SELECT status FROM sources WHERE path = 'Amcache/AmcacheParser_Output.csv'"));
    }

    [Fact]
    public void A_folder_without_outputs_json_is_read_by_file_name_and_header()
    {
        using var temp = new TempDirectory();
        // Raw KAPE / EZ Tools output: tool timestamps on the names, and one file saved under a name
        // of the analyst's own that only its header identifies.
        temp.Write(@"HOST01\EventLogs\20261101100301_EvtxECmd_Output.csv", EvtxCsv(), byteOrderMark: true);
        temp.Write(@"HOST01\Prefetch\20261101100301_PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        temp.Write(@"HOST01\FileSystem\MFT.csv", MftCsv(), byteOrderMark: true);
        temp.Write(@"HOST01\FileSystem\whatever-i-called-it.csv", UsnCsv(), byteOrderMark: true);

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.Built, result.Outcome);
        var kinds = result.Sources.ToDictionary(s => s.Path, s => s.Kind);
        Assert.Equal("evtxecmd", kinds["EventLogs/20261101100301_EvtxECmd_Output.csv"]);
        Assert.Equal("pecmd.timeline", kinds["Prefetch/20261101100301_PECmd_Output_Timeline.csv"]);
        Assert.Equal("mftecmd.mft", kinds["FileSystem/MFT.csv"]);
        Assert.Equal("mftecmd.usnjournal", kinds["FileSystem/whatever-i-called-it.csv"]);
        Assert.All(result.Sources, s => Assert.Equal("unknown", s.ParserVersion));
        using var lake = OpenLake(LakePath(temp));
        Assert.Equal(false, Scalar(lake, "SELECT manifest FROM hosts WHERE host = 'HOST01'"));
        Assert.Equal(1L, Scalar(lake, "SELECT count(*) FROM timeline WHERE kind = 'mftecmd.usnjournal'"));
    }

    [Fact]
    public void With_a_host_name_the_whole_folder_is_one_host_and_the_lake_can_go_elsewhere()
    {
        using var temp = new TempDirectory();
        temp.Write(@"output\Prefetch\PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        var lakeFolder = Path.Combine(temp.Path, "lake");

        var result = LakeBuilder.Build(Path.Combine(temp.Path, "output"),
            Small with { SingleHost = "HOST01", LakeDirectory = lakeFolder });

        Assert.Equal(LakeOutcome.Built, result.Outcome);
        Assert.Equal(["HOST01"], result.Hosts);
        Assert.True(File.Exists(Path.Combine(lakeFolder, "case.duckdb")));
        Assert.False(Directory.Exists(Path.Combine(temp.Path, "output", "_Lake")));
    }

    [Fact]
    public void A_file_named_like_a_kind_whose_header_does_not_fit_is_reported_and_kept_raw_but_not_mapped()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        // A PECmd timeline from a tool that wrote other columns.
        temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv", "When,Program\r\n2026-11-01 09:21:00,UPDATER.EXE\r\n");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.BuiltCheckLog, result.Outcome);
        var source = Assert.Single(result.Sources, s => s.Path == "Prefetch/PECmd_Output_Timeline.csv");
        Assert.Equal(SourceStatus.HeaderMismatch, source.Status);
        Assert.Equal("unmapped.pecmd", source.Kind);
        Assert.Contains("missing RunTime, ExecutableName", source.Reason);
        Assert.True(source.NeedsReview);
        using var lake = OpenLake(LakePath(temp));
        Assert.Equal(0L, Scalar(lake, $"SELECT count(*) FROM timeline WHERE source_id = {source.SourceId}"));
        Assert.Equal("UPDATER.EXE", Scalar(lake, $"SELECT Program FROM raw_unmapped_pecmd WHERE source_id = {source.SourceId}"));
        Assert.Contains("header_mismatch", File.ReadAllText(Path.Combine(temp.Path, "_Lake", "build.json")));
    }

    [Fact]
    public void A_CSV_with_no_mapping_is_kept_in_a_raw_table_so_nothing_is_lost()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");

        var result = LakeBuilder.Build(temp.Path, Small);

        var lnk = Assert.Single(result.Sources, s => s.Path == "LNKFiles/alice/alice_LECmd_Recent.csv");
        Assert.Equal(SourceStatus.Loaded, lnk.Status);
        Assert.Equal("unmapped.lecmd", lnk.Kind);
        Assert.Equal(1, lnk.RowsLoaded);
        Assert.Equal(0, lnk.TimelineRows);
        using var lake = OpenLake(LakePath(temp));
        var row = Assert.Single(Rows(lake, "SELECT * FROM raw_unmapped_lecmd"));
        Assert.Equal("HOST01", row["host"]);
        Assert.Equal(1L, row["row_no"]);
        Assert.Equal(@"C:\Users\alice\Documents\a.docx", row["LocalPath"]);
    }

    [Fact]
    public void Files_of_one_kind_with_different_columns_share_one_widened_raw_table()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Other\Tool_A.csv", "Name,Size\r\nalpha,1\r\n");
        temp.Write(@"HOST02\Other\Tool_A.csv", "Name,Owner\r\nbeta,alice\r\n");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.Built, result.Outcome);
        using var lake = OpenLake(LakePath(temp));
        var rows = Rows(lake, "SELECT host, Name, Size, Owner FROM raw_unmapped_tool ORDER BY host");
        Assert.Equal("1", rows[0]["Size"]);
        Assert.Null(rows[0]["Owner"]);
        Assert.Equal("alice", rows[1]["Owner"]);
    }

    [Fact]
    public void A_CSV_column_named_like_a_lake_column_is_renamed_and_the_rename_noted()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Summary\Summary_Hosts.csv", "Host,Status\r\nHOST01,Found\r\n");

        var result = LakeBuilder.Build(temp.Path, Small);

        var source = Assert.Single(result.Sources);
        Assert.Contains("Host to csv_Host", source.Reason);
        using var lake = OpenLake(LakePath(temp));
        var row = Assert.Single(Rows(lake, "SELECT host, csv_Host FROM raw_unmapped_summary"));
        Assert.Equal("HOST01", row["csv_Host"]);
    }

    [Fact]
    public void Rows_the_CSV_reader_cannot_read_are_counted_and_flagged_not_dropped_in_silence()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv",
            "RunTime,ExecutableName\r\n2026-11-01 09:21:00,A.EXE\r\n2026-11-01 09:22:00,B.EXE,extra\r\n2026-11-01 09:23:00,C.EXE\r\n");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.BuiltCheckLog, result.Outcome);
        var source = Assert.Single(result.Sources);
        Assert.Equal(2, source.RowsLoaded);
        Assert.Equal(1, source.RowsRejected);
        Assert.True(source.NeedsReview);
        Assert.Contains("could not be read", source.Reason);
    }

    [Fact]
    public void Event_log_rows_carry_the_logon_target_user_source_address_and_logon_type()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        LakeBuilder.Build(temp.Path, Small);

        using var lake = OpenLake(LakePath(temp));
        var logon = Assert.Single(Rows(lake, "SELECT * FROM logons"));
        Assert.Equal(new DateTime(2026, 11, 1, 9, 15, 30, 123).AddTicks(4560), logon["ts"]);
        Assert.Equal("2026-11-01 09:15:30.1234567", logon["ts_raw"]);
        Assert.Equal("logon_success", logon["action"]);
        Assert.Equal("CORP", logon["user_domain"]);
        Assert.Equal("alice", logon["user_name"]);
        Assert.Equal("10.0.0.5", logon["src_ip"]);
        Assert.Equal("3", logon["logon_type"]);
        Assert.Equal(4624, logon["event_id"]);

        var service = Assert.Single(Rows(lake, "SELECT * FROM timeline WHERE category = 'service'"));
        Assert.Equal("install", service["action"]);
        Assert.Equal(@"C:\Users\alice\AppData\Local\Temp\updater.exe", service["path"]);
        Assert.Equal("updater.exe", service["file_name"]);
        Assert.Equal(".exe", service["extension"]);
        Assert.Equal("S-1-5-21-1000-1000-1000-1001", service["user_sid"]);
        Assert.Equal("windows", service["platform"]);
    }

    [Fact]
    public void Prefetch_rows_drop_the_volume_prefix_and_take_the_path_from_the_files_loaded()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        LakeBuilder.Build(temp.Path, Small);

        using var lake = OpenLake(LakePath(temp));
        var runs = Rows(lake, "SELECT * FROM timeline WHERE kind = 'pecmd.timeline' ORDER BY ts");
        Assert.Equal(2, runs.Count);
        Assert.Equal(@"\WINDOWS\SYSTEM32\CMD.EXE", runs[0]["path"]);
        Assert.Equal("CMD.EXE", runs[0]["file_name"]);
        Assert.Equal("executed", runs[1]["ts_desc"]);
        Assert.Equal("execution", runs[1]["category"]);

        var last = Assert.Single(Rows(lake, "SELECT * FROM timeline WHERE kind = 'pecmd.output'"));
        Assert.Equal(@"\USERS\ALICE\APPDATA\LOCAL\TEMP\UPDATER.EXE", last["path"]);
        Assert.Equal("last_run", last["ts_desc"]);
        Assert.Equal(new DateTime(2026, 11, 1, 9, 21, 0), last["ts"]);

        var executed = Assert.Single(Rows(lake, "SELECT * FROM executions WHERE program = 'updater.exe'"));
        Assert.Equal(2L, executed["events"]);
    }

    [Fact]
    public void MFT_rows_are_created_plus_modified_only_when_it_differs_and_USN_rows_take_their_reason()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        LakeBuilder.Build(temp.Path, Small);

        using var lake = OpenLake(LakePath(temp));
        var mft = Rows(lake, "SELECT * FROM file_events WHERE kind = 'mftecmd.mft' ORDER BY ts");
        Assert.Equal(["created", "created", "modified"], mft.Select(r => (string)r["ts_desc"]!));
        Assert.Equal(@"\Users\alice\AppData\Local\Temp", mft[0]["path"]);
        Assert.Null(mft[0]["extension"]);
        Assert.Equal(@"\Users\alice\AppData\Local\Temp\updater.exe", mft[1]["path"]);
        Assert.Equal(".exe", mft[1]["extension"]);
        Assert.Equal(73728L, mft[1]["size"]);

        var usn = Assert.Single(Rows(lake, "SELECT * FROM file_events WHERE kind = 'mftecmd.usnjournal'"));
        Assert.Equal("rename", usn["action"]);
        Assert.Equal(".lockbit", usn["extension"]);
        Assert.Equal(@"\Users\alice\Documents\report.docx.lockbit", usn["path"]);
    }

    [Fact]
    public void Timeline_rows_lead_back_to_their_source_file_and_row()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        LakeBuilder.Build(temp.Path, Small);

        using var lake = OpenLake(LakePath(temp));
        var row = Assert.Single(Rows(lake,
            "SELECT s.path, t.row_no, r.EventId FROM timeline t JOIN sources s USING (source_id) " +
            "JOIN raw_evtxecmd r ON r.source_id = t.source_id AND r.row_no = t.row_no WHERE t.event_id = 7045"));
        Assert.Equal("EventLogs/EvtxECmd_EventLogs.csv", row["path"]);
        Assert.Equal(2L, row["row_no"]);
        Assert.Equal("7045", row["EventId"]);
    }

    [Fact]
    public void Hosts_are_joined_in_one_timeline()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        WriteArtefactForgeHost(temp, "HOST02");
        temp.Write(@"_Logs\manifest.json", "{}");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(["HOST01", "HOST02"], result.Hosts);
        using var lake = OpenLake(LakePath(temp));
        Assert.Equal(2L, Scalar(lake,
            "SELECT count(DISTINCT host) FROM timeline WHERE lower(file_name) = 'updater.exe' AND kind = 'pecmd.timeline'"));
    }

    [Fact]
    public void A_lake_open_in_another_program_is_left_alone_and_the_new_one_left_beside_it()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        Assert.Equal(LakeOutcome.Built, LakeBuilder.Build(temp.Path, Small).Outcome);
        var before = File.ReadAllBytes(LakePath(temp));

        LakeResult result;
        using (new FileStream(LakePath(temp), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.NotSwapped, result.Outcome);
        Assert.Equal(LakePath(temp) + ".new", result.DatabasePath);
        Assert.True(File.Exists(LakePath(temp) + ".new"));
        Assert.Equal(before, File.ReadAllBytes(LakePath(temp)));
        Assert.Contains("could not be replaced", result.Message);
    }

    [Fact]
    public void A_rebuild_replaces_the_lake_and_removes_the_spill_folder()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        LakeBuilder.Build(temp.Path, Small);
        WriteArtefactForgeHost(temp, "HOST02");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.Built, result.Outcome);
        Assert.False(File.Exists(LakePath(temp) + ".new"));
        Assert.False(Directory.Exists(Path.Combine(temp.Path, "_Lake", "tmp")));
        using var lake = OpenLake(LakePath(temp));
        Assert.Equal(2L, Scalar(lake, "SELECT count(*) FROM hosts"));
    }

    [Fact]
    public void The_build_writes_a_log_and_a_build_record()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");

        var result = LakeBuilder.Build(temp.Path, Small);

        var log = File.ReadAllText(Path.Combine(temp.Path, "_Lake", "lake.log"));
        Assert.Contains("Skipped HOST01/Amcache/AmcacheParser_Output.csv", log);
        Assert.Contains("Mapped evtxecmd", log);
        using var build = JsonDocument.Parse(File.ReadAllText(Path.Combine(temp.Path, "_Lake", "build.json")));
        var root = build.RootElement;
        Assert.Equal("built", root.GetProperty("result").GetString());
        Assert.Equal(result.DuckDbVersion, root.GetProperty("duckDbVersion").GetString());
        Assert.Equal(result.TimelineRows, root.GetProperty("timelineRows").GetInt64());
        Assert.Equal(1, root.GetProperty("sourcesSkipped").GetInt32());
        Assert.Equal(result.Sources.Count, root.GetProperty("sources").GetArrayLength());
    }

    [Fact]
    public void A_folder_with_no_hosts_fails_with_a_reason_and_writes_no_lake()
    {
        using var temp = new TempDirectory();
        temp.Write(@"_Logs\manifest.json", "{}");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.Failed, result.Outcome);
        Assert.Contains("No host folders", result.Message);
        Assert.False(File.Exists(LakePath(temp)));
    }

    [Fact]
    public void An_unreadable_outputs_json_is_reported_and_the_folder_searched_instead()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        temp.Write(@"HOST01\outputs.json", "{ not json");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.BuiltCheckLog, result.Outcome);
        Assert.Contains(result.Warnings, w => w.Contains("outputs.json could not be used"));
        Assert.Equal("pecmd.timeline", Assert.Single(result.Sources).Kind);
    }

    [Fact]
    public void An_empty_file_and_partial_output_are_not_loaded()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        temp.Write(@"HOST01\EventLogs\EvtxECmd_EventLogs.csv", "");
        temp.Write(@"HOST01\_Incomplete\FileSystem\MFTECmd_MFT.csv", MftCsv());

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.DoesNotContain(result.Sources, s => s.Path.StartsWith("_Incomplete", StringComparison.Ordinal));
        var empty = Assert.Single(result.Sources, s => s.Path == "EventLogs/EvtxECmd_EventLogs.csv");
        Assert.Equal(SourceStatus.Skipped, empty.Status);
        Assert.Contains("empty", empty.Reason);
    }
}
