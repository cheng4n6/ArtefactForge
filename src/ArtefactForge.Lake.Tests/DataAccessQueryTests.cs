using ArtefactForge.Lake.Cli;
using ArtefactForge.Lake.Queries;
using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

/// <summary>One small lake with the data access setup run, shared by the tests of its macros.</summary>
public sealed class PreparedDataAccessLake : IDisposable
{
    private readonly TempDirectory _temp = new();
    public LakeQuerySession Session { get; }

    public PreparedDataAccessLake()
    {
        _temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        var result = LakeBuilder.Build(_temp.Path, DataAccessQueryTests.Small with { RunAnalyses = false });
        Session = new LakeQuerySession(result.DatabasePath!, _temp.Path);
        Session.RunToRows(LakeQueryCatalogue.Find("data_access_compromised")!);
    }

    public object? Eval(string expression)
    {
        using var command = Session.CreateCommand();
        command.CommandText = "SELECT " + expression;
        return command.ExecuteScalar();
    }

    public void Dispose()
    {
        Session.Dispose();
        _temp.Dispose();
    }
}

/// <summary>
/// The data access queries and the files: header they rely on. Byte-for-byte parity with the C#
/// DataAccess step is checked in ArtefactForge.Tests (DataAccessLakeParityTests); these check the
/// pieces on their own: which files a pattern takes, the rules the setup query's macros carry, and
/// what a lake build writes. Made-up hosts and users throughout.
/// </summary>
public class DataAccessQueryTests(PreparedDataAccessLake lake) : IClassFixture<PreparedDataAccessLake>
{
    internal static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    private const string LnkHeader =
        "SourceFile,SourceCreated,SourceModified,TargetCreated,TargetModified,TargetAccessed,FileSize,LocalPath,NetworkPath,"
        + "CommonPath,Arguments,MachineID,TargetIDAbsolutePath";

    private static LakeQuery Query(string name) => LakeQueryCatalogue.Find(name)!;

    private static string Lit(string s) => "'" + s.Replace("'", "''") + "'";

    [Theory]
    [InlineData("Registry/*ProfileList*.csv", "Registry/RECmd_SYSTEM_ProfileList.csv", true)]
    [InlineData("Registry/*ProfileList*.csv", "registry/recmd_system_profilelist.CSV", true)]
    [InlineData("Registry/*ProfileList*.csv", "Registry/alice/RECmd_SYSTEM_ProfileList.csv", false)]
    [InlineData("Registry/**/*_RECmd_NTUSER_RecentDocs*.csv", "Registry/alice/alice_RECmd_NTUSER_RecentDocs.csv", true)]
    [InlineData("Registry/**/*_RECmd_NTUSER_RecentDocs*.csv", "Registry/alice_RECmd_NTUSER_RecentDocs.csv", true)]
    [InlineData("Registry/**/*_RECmd_NTUSER_RecentDocs*.csv", "Registry/a/b/x_RECmd_NTUSER_RecentDocs_2.csv", true)]
    [InlineData("Registry/**/*_RECmd_NTUSER_RecentDocs*.csv", "RegistryOld/alice_RECmd_NTUSER_RecentDocs.csv", false)]
    [InlineData("LNKFiles/**/*LECmd_Recent*.csv", "LNKFiles/alice/alice_LECmd_OfficeRecent.csv", false)]
    [InlineData("EventLogs/**/EvtxECmd*.csv", "EventLogs/EvtxECmd_EventLogs_2.csv", true)]
    [InlineData("SystemInfo/SystemInfo.csv", "SystemInfo/SystemInfo.csv.bak", false)]
    public void A_files_pattern_matches_folders_and_names_as_Windows_does(string pattern, string path, bool matches) =>
        Assert.Equal(matches, LakeFilePattern.Matches(pattern, path));

    [Fact]
    public void A_files_line_is_read_from_the_header_and_a_bad_pattern_is_refused()
    {
        var files = LakeQuery.Parse("example", "-- title: x\n-- files: my_rows = Registry/**/*Thing*.csv (A, B)\nSELECT 1").Files.Single();
        Assert.Equal(("my_rows", "Registry/**/*Thing*.csv"), (files.Table, files.Pattern));
        Assert.Equal(["A", "B"], files.Columns);

        foreach (var bad in new[] { "*.csv", "**/x.csv", "Reg*/x.csv", "Registry/**/**/x.csv", "Registry//x.csv" })
            Assert.Throws<InvalidDataException>(() => LakeQuery.Parse("bad", $"-- title: x\n-- files: t = {bad} (A)\nSELECT 1"));
    }

    [Fact]
    public void A_files_view_takes_the_rows_of_every_matching_file_whatever_raw_table_holds_them()
    {
        using var temp = new TempDirectory();
        var row = "C:\\evidence\\Users\\alice\\x.lnk,2026-03-01 10:00:00,2026-03-01 10:00:00,,,,1,C:\\Finance\\Q1.xlsx,,,,,";
        // Mapped as lecmd, a header the lake does not know (an older LECmd), and an empty file.
        temp.Write(@"HOST01\LNKFiles\alice\alice_LECmd_Recent.csv", LnkHeader + "\r\n" + row + "\r\n");
        temp.Write(@"HOST02\LNKFiles\bob\bob_LECmd_Recent.csv", "SourceFile,SourceModified,LocalPath\r\nx,2026-03-02 10:00:00,C:\\B.docx\r\n");
        temp.Write(@"HOST02\LNKFiles\carol\carol_LECmd_Recent.csv", "");
        var result = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false });
        using var session = new LakeQuerySession(result.DatabasePath!, temp.Path);
        session.RunToRows(Query("data_access_compromised"));

        var rows = ThreeColumns(session, "SELECT host, LocalPath, SourceCreated FROM da_lnk_recent ORDER BY host");
        Assert.Equal([("HOST01", @"C:\Finance\Q1.xlsx", "2026-03-01 10:00:00"), ("HOST02", @"C:\B.docx", "")], rows);
        var files = Rows(session, "SELECT host || ':' || path || ':' || status FROM da_lnk_recent_files ORDER BY path");
        Assert.Equal(["HOST01:LNKFiles/alice/alice_LECmd_Recent.csv:loaded", "HOST02:LNKFiles/bob/bob_LECmd_Recent.csv:header_mismatch",
                      "HOST02:LNKFiles/carol/carol_LECmd_Recent.csv:skipped"], files);
    }

    private static List<(string, string, string)> ThreeColumns(LakeQuerySession session, string sql)
    {
        using var command = session.CreateCommand();
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        var rows = new List<(string, string, string)>();
        while (reader.Read()) rows.Add((LakeCsv.Cell(reader, 0), LakeCsv.Cell(reader, 1), LakeCsv.Cell(reader, 2)));
        return rows;
    }

    private static List<string> Rows(LakeQuerySession session, string sql)
    {
        using var command = session.CreateCommand();
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        var rows = new List<string>();
        while (reader.Read()) rows.Add(LakeCsv.Cell(reader, 0));
        return rows;
    }

    [Theory]
    // A SID is compared when both sides have one, so two accounts of one name are told apart.
    [InlineData("alice", "S-1-5-21-1-1-1-1001", "alice", "S-1-5-21-1-1-1-1001", true)]
    [InlineData("alice", "S-1-5-21-1-1-1-1001", "alice", "S-1-5-21-2-2-2-1001", false)]
    [InlineData("", "S-1-5-21-1-1-1-1001", "anyone", "s-1-5-21-1-1-1-1001", true)]
    [InlineData("", "S-1-5-21-1-1-1-1001", "alice", "", false)]
    // Otherwise the names, without the domain and the profile folder suffixes Windows adds.
    [InlineData("alice", "", @"CORP\Alice", "S-1-5-21-1-1-1-1001", true)]
    [InlineData(@"CORP\alice", "", "alice@corp.example", "", true)]
    [InlineData("alice", "", "alice.000", "", true)]
    [InlineData("alice", "", "alice.CORP.001", "", true)]
    [InlineData(@"corp\alice", "", "alice.corp", "", true)]
    [InlineData("alice", "", "alice.corp", "", false)]
    [InlineData("alice", "", "alice.smith", "", false)]
    [InlineData("alice", "", "alice.", "", false)]
    [InlineData("alice", "", "malice", "", false)]
    [InlineData("john.smith", "", "john.smith.CORP", "", true)]
    [InlineData("alice", "", "", "", false)]
    public void A_listed_user_matches_an_account_as_the_CSharp_step_matches_it(string user, string sid, string name, string rowSid,
        bool matches)
    {
        Assert.Equal(matches, lake.Eval($"da_matches({Lit(user)}, {Lit(sid)}, {Lit(name)}, {Lit(rowSid)})"));
    }

    [Theory]
    [InlineData(@"C:\Finance\Q1.xlsx", @"C:\Finance\Q1.xlsx")]
    [InlineData("\t C:\\Finance\\Q1.xlsx \u00A0", @"C:\Finance\Q1.xlsx")]
    [InlineData(@"Desktop\This PC\D:\Projects\plan.docx", @"D:\Projects\plan.docx")]
    [InlineData(@"\\FS01\Share\HR", @"\\FS01\Share\HR")]
    [InlineData("https://intranet.example/page", null)]
    [InlineData("ms-teams:chat", null)]
    [InlineData("::{20D04FE0-3AEA-1069-A2D8-08002B30309D}", null)]
    [InlineData("Internet Folder\\x", null)]
    [InlineData("   ", null)]
    public void Paths_are_cleaned_as_the_client_should_read_them(string path, string? expected)
    {
        Assert.Equal(expected, lake.Eval($"da_clean_path({Lit(path)})") as string);
    }

    [Theory]
    [InlineData("LNKFiles/alice/alice_LECmd_Recent.csv", "_LECmd_Recent", "alice")]
    [InlineData("LNKFiles/dave_LECmd_OfficeRecent.csv", "_LECmd_OfficeRecent", "dave")]
    [InlineData("LNKFiles/LECmd_Recent.csv", "_LECmd_Recent", "")]
    [InlineData("EventLogs/EvtxECmd_EventLogs.csv", "", "")]
    [InlineData("Registry/bob.CORP/bob.CORP_RECmd_NTUSER_RecentDocs.csv", "_RECmd_NTUSER", "bob.CORP")]
    public void A_per_user_file_belongs_to_its_folder_or_the_name_before_the_tool(string path, string marker, string user)
    {
        Assert.Equal(user, lake.Eval($"da_file_user({Lit(path)}, {Lit(marker)})"));
    }

    [Theory]
    [InlineData(@"C:\Users\alice\NTUSER.DAT", "alice")]
    [InlineData(@"C:\evidence\C\Users\bob\AppData\x.lnk", "bob")]
    [InlineData(@"C:\Users\alice", "")]
    [InlineData(@"D:\users\x\Users\carol\file", "carol")]
    [InlineData("", "")]
    public void The_profile_a_path_is_under_follows_the_last_Users_folder(string path, string user)
    {
        Assert.Equal(user, lake.Eval($"da_path_user({Lit(path)})"));
    }

    [Theory]
    [InlineData("2026-03-01 10:00:00.1234567", "2026-03-01 10:00:00")]
    [InlineData("  2026-03-01 10:00:00  ", "2026-03-01 10:00:00")]
    [InlineData("2026-03-01", null)]
    [InlineData("not a time at all, honestly", null)]
    public void Times_are_read_to_the_second_from_their_first_19_characters(string text, string? expected)
    {
        Assert.Equal(expected, lake.Eval($"da_fmt(da_time({Lit(text)}))") as string);
    }

    [Fact]
    public void Security_share_and_file_audit_events_give_the_path_reached_and_how()
    {
        static Dictionary<string, string> Event(string time, string id, string payload, string keywords = "Audit success") => new()
        {
            ["RecordNumber"] = "1", ["EventRecordId"] = "1", ["TimeCreated"] = time + ".1234567", ["EventId"] = id,
            ["Channel"] = "Security", ["Computer"] = "FS01.corp.example", ["Keywords"] = keywords, ["Payload"] = payload
        };
        static string Data(params (string Name, string Text)[] data) =>
            "{\"EventData\":{\"Data\":[" + string.Join(",", data.Select(d =>
                $"{{\"@Name\":\"{d.Name}\",\"#text\":\"{d.Text.Replace("\\", "\\\\")}\"}}")) + "]}}";
        var alice = new[] { ("SubjectUserName", "alice"), ("SubjectDomainName", "CORP"), ("SubjectUserSid", "S-1-5-21-1-1-1-1104") };

        using var temp = new TempDirectory();
        temp.Write(@"HOST01\EventLogs\EvtxECmd_EventLogs.csv", Csv(EvtxHeader,
            Event("2026-03-16 10:00:00", "5140", Data([.. alice, ("ShareName", @"\\*\Finance")])),
            Event("2026-03-16 10:00:01", "5145", Data([.. alice, ("ShareName", @"\\*\Finance\"), ("RelativeTargetName", @"\Q1\r.xlsx")])),
            Event("2026-03-16 10:00:02", "5140", Data([.. alice, ("ShareName", @"\\*\IPC$")])),
            Event("2026-03-16 10:00:03", "5140", Data([.. alice, ("ShareName", @"\\*\Finance")]), "Audit failure"),
            Event("2026-03-16 10:00:04", "5140", Data(("SubjectUserName", "FS01$"), ("ShareName", @"\\*\Finance"))),
            Event("2026-03-16 10:00:05", "4663", Data([.. alice, ("ObjectType", "File"), ("ObjectName", @"D:\F\a.xlsx"), ("AccessList", "%%4417")])),
            Event("2026-03-16 10:00:06", "4663", Data([.. alice, ("ObjectName", @"D:\F\b.xlsx"), ("AccessList", "%%1537 %%4416")])),
            Event("2026-03-16 10:00:07", "4663", Data([.. alice, ("ObjectType", "Key"), ("ObjectName", @"\REGISTRY\X")])),
            Event("2026-03-16 10:00:08", "5140", "{not json")));
        var result = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false });
        using var session = new LakeQuerySession(result.DatabasePath!, temp.Path);
        session.RunToRows(Query("data_access_compromised"));

        var rows = Rows(session, "SELECT da_fmt(ts) || ' ' || row_user || ' ' || row_sid || ' ' || path || ' ' || activity " +
                                 "FROM da_read ORDER BY ts");

        // IPC$, a failure, a computer account, a registry key and a Payload that is not JSON give nothing.
        Assert.Equal(
        [
            @"2026-03-16 10:00:00 CORP\alice S-1-5-21-1-1-1-1104 \\FS01\Finance Share accessed",
            @"2026-03-16 10:00:01 CORP\alice S-1-5-21-1-1-1-1104 \\FS01\Finance\Q1\r.xlsx Accessed over share",
            @"2026-03-16 10:00:05 CORP\alice S-1-5-21-1-1-1-1104 D:\F\a.xlsx Written (file audit)",
            @"2026-03-16 10:00:06 CORP\alice S-1-5-21-1-1-1-1104 D:\F\b.xlsx Deleted (file audit)"
        ], rows);
    }

    [Fact]
    public void A_lake_build_writes_the_data_access_files_beside_the_lake_and_logs_it()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Registry\RECmd_SYSTEM_ProfileList.csv",
            "KeyName,ProfileImagePath\r\nS-1-5-18,C:\\Windows\\system32\\config\\systemprofile\r\nS-1-5-21-1-1-1-1104,C:\\Users\\alice\r\n");
        temp.Write(@"HOST01\LNKFiles\alice\alice_LECmd_Recent.csv",
            LnkHeader + "\r\nC:\\evidence\\Users\\alice\\x.lnk,2026-03-01 10:00:00,2026-03-02 10:00:00,,,,1,C:\\Finance\\Q1.xlsx,,,,,\r\n");
        temp.Write("CompromisedUsers.csv", "Username,SID,Comment\r\nalice,,\r\n");

        var result = LakeBuilder.Build(temp.Path, Small);

        var root = DataAccessResults.OutputRootFor(result.LakeDirectory!);
        Assert.Equal(
        [
            "\uFEFF\"Date/Time (UTC)\",\"System\",\"User\",\"Path\",\"Activity\"",
            "\"2026-03-01 10:00:00\",\"HOST01\",\"alice\",\"C:\\Finance\\Q1.xlsx\",\"Opened\"",
            "\"2026-03-02 10:00:00\",\"HOST01\",\"alice\",\"C:\\Finance\\Q1.xlsx\",\"Opened\""
        ], File.ReadAllLines(Path.Combine(root, DataAccessResults.CaseFileName)));
        Assert.Equal("\"HOST01\",\"alice\",\"S-1-5-21-1-1-1-1104\",\"C:\\Users\\alice\",\"ProfileList; Output folders\"",
                     File.ReadAllLines(Path.Combine(root, "HOST01", "DataAccess", DataAccessResults.UsersFileName))[1]);
        Assert.True(File.Exists(Path.Combine(root, "HOST01", "DataAccess", DataAccessResults.SourcesFileName)));
        Assert.True(File.Exists(Path.Combine(root, DataAccessResults.UserListFileName)));
        Assert.Contains("Data access from the lake's queries", File.ReadAllText(Path.Combine(result.LakeDirectory!, LakeNames.LogFile)));
    }

    [Fact]
    public void With_nobody_listed_the_command_writes_the_account_lists_and_no_activity()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\LNKFiles\alice\alice_LECmd_Recent.csv",
            LnkHeader + "\r\nC:\\evidence\\Users\\alice\\x.lnk,2026-03-01 10:00:00,2026-03-02 10:00:00,,,,1,C:\\Finance\\Q1.xlsx,,,,,\r\n");
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["build", temp.Path, "--memory-gb", "0.5", "--threads", "2"], new StringWriter(), new StringWriter()));

        var output = new StringWriter();
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["data-access", temp.Path], output, new StringWriter()));

        var root = Path.Combine(temp.Path, "_Lake", "results", "DataAccess");
        Assert.Contains("no compromised users listed", output.ToString());
        Assert.True(File.Exists(Path.Combine(root, "HOST01", "DataAccess", DataAccessResults.UsersFileName)));
        Assert.False(File.Exists(Path.Combine(root, "HOST01", "DataAccess", DataAccessResults.ActivityFileName)));
        Assert.False(File.Exists(Path.Combine(root, DataAccessResults.CaseFileName)));

        temp.Write("CompromisedUsers.csv", "Account\r\nalice\r\n");
        var error = new StringWriter();
        Assert.Equal(LakeCli.ExitCheckLog, LakeCli.Run(["data-access", temp.Path], new StringWriter(), error));
        Assert.Contains("needs a Username or SID column", error.ToString());
    }
}
