using System.Text;
using ArtefactForge.Core.DataAccess;
using ArtefactForge.Lake;
using ArtefactForge.Lake.Queries;

namespace ArtefactForge.Tests;

/// <summary>
/// The lake's data access queries against the C# DataAccess step: both run on the same made-up
/// case, and every file the lake writes under _Lake\results\DataAccess must be byte for byte the
/// file the step writes in the case. The case is built to reach each reader and rule: per-user
/// folders and the older user-in-the-file-name layout, paths the client should not see, the
/// shortcut times a copied collection gets wrong, ShellBags that are not folders, Security 5140,
/// 5145 and 4663 (failures, IPC$, computer accounts, this host's own share), a re-run event log,
/// Linux recent files, two collections of one machine, and names matched with and without a
/// domain, a profile folder suffix or a SID.
/// </summary>
public class DataAccessLakeParityTests
{
    private const string LnkHeader =
        "SourceFile,SourceCreated,SourceModified,SourceAccessed,TargetCreated,TargetModified,TargetAccessed,FileSize,"
        + "RelativePath,WorkingDirectory,FileAttributes,HeaderFlags,DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,"
        + "NetworkPath,CommonPath,Arguments,MachineID,TargetIDAbsolutePath";

    private const string JumpListHeader =
        "SourceFile,SourceCreated,SourceModified,SourceAccessed,AppId,AppIdDescription,HasSps,DestListVersion,"
        + "LastUsedEntryNumber,MRU,EntryNumber,CreationTime,LastModified,Hostname,MacAddress,Path,InteractionCount,"
        + "PinStatus,TargetCreated,TargetModified,TargetAccessed,LocalPath,FileSize,Arguments";

    private const string ShellBagsHeader =
        "BagPath,Slot,NodeSlot,MRUPosition,AbsolutePath,ShellType,Value,ChildBags,CreatedOn,ModifiedOn,AccessedOn,"
        + "LastWriteTime,MFTEntry,MFTSequenceNumber,ExtensionBlockCount,FirstInteracted,LastInteracted,HasExplored,"
        + "Miscellaneous,SourceFile";

    private const string RecentDocsHeader =
        "Extension,BatchKeyPath,ValueName,BatchValueName,TargetName,LnkName,MruPosition,OpenedOn,ExtensionLastOpened";

    private const string OpenSaveHeader = "Extension,BatchKeyPath,ValueName,BatchValueName,MruPosition,AbsolutePath,OpenedOn,Details";

    private const string OfficeMruHeader = "ValueName,BatchKeyPath,LastOpened,BatchValueName,LastClosed,FileName";

    private const string ProfileListHeader = "Timestamp,BatchKeyPath,KeyName,BatchValueName,ProfileImagePath,LastLogonTime,LastLogoffTime";

    private const string SamHeader = "ValidUserId,BatchKeyPath,BatchValueName,UserId,InvalidLoginCount,TotalLoginCount,CreatedOn,UserName";

    private const string EvtxHeader =
        "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,ThreadId,Computer,"
        + "ChunkNumber,UserId,MapDescription,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,"
        + "PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,Keywords,"
        + "ExtraDataOffset,Payload";

    private const string Domain = "S-1-5-21-1111111111-2222222222-3333333333";
    private const string AliceSid = Domain + "-1104";
    private const string BobSid = Domain + "-1105";
    private const string LocalAliceSid = "S-1-5-21-9999999999-8888888888-7777777777-1001";

    private static void Write(string path, params string[] lines)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllLines(path, lines, new UTF8Encoding(true));
    }

    private static string Lnk(string user, string created, string modified, string target, string network = "", string common = "",
                              string idPath = "") =>
        $@"C:\evidence\C\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\x.lnk,{created},{modified},2026-04-01 00:00:00,"
        + $"2020-01-01 00:00:00,2020-01-02 00:00:00,2020-01-03 00:00:00,100,,,,,,,,{Q(target)},{Q(network)},{Q(common)},,host01,{Q(idPath)}";

    private static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";

    private static string JsonValue(string text) => text.Replace(@"\", @"\\");

    private static string SecurityEvent(string computer, string time, int id, string keywords, string channel = "Security",
                                        params (string, string)[] data) =>
        $"1,1,{time}.1234567,{id},LogAlways,Microsoft-Windows-Security-Auditing,{channel},4,8,{computer},0,,,,,,,,,,,,False,"
        + $@"C:\x\Security.evtx,{keywords},0,"
        + "\"{\"\"EventData\"\":{\"\"Data\"\":["
        + string.Join(",", data.Select(d => $"{{\"\"@Name\"\":\"\"{d.Item1}\"\",\"\"#text\"\":\"\"{JsonValue(d.Item2)}\"\"}}"))
        + "]}}\"";

    private static string Share(string time, int id, string user, string sid, string share, string relative = "",
                                string keywords = "Audit success", string computer = "FS01.corp.example") =>
        SecurityEvent(computer, time, id, keywords, "Security",
            ("SubjectUserSid", sid), ("SubjectUserName", user), ("SubjectDomainName", "CORP"),
            ("IpAddress", "10.0.0.5"), ("ShareName", share), ("RelativeTargetName", relative));

    private static string FileAudit(string time, string user, string type, string path, string accessList) =>
        SecurityEvent("FS01.corp.example", time, 4663, "Audit success", "Security",
            ("SubjectUserSid", AliceSid), ("SubjectUserName", user), ("SubjectDomainName", "CORP"),
            ("ObjectType", type), ("ObjectName", path), ("AccessList", accessList));

    /// <summary>A Windows collection: system summary, ProfileList, the SAM, and every Windows artefact.</summary>
    private static void WindowsHost(string caseDir, string collection, string hostname)
    {
        var host = Path.Combine(caseDir, collection);
        Write(Path.Combine(host, "SystemInfo", "SystemInfo.csv"),
              "\"Category\",\"Item\",\"Value\",\"Source\"", $"\"Identity\",\"Hostname\",\"{hostname}\",\"SYSTEM\"");
        Write(Path.Combine(host, "Registry", "RECmd_SYSTEM_ProfileList.csv"), ProfileListHeader,
              @"2026-01-01 00:00:00,ROOT\ProfileList\S-1-5-18,S-1-5-18,Multiple,%systemroot%\system32\config\systemprofile,,",
              $@"2026-01-01 00:00:00,ROOT\ProfileList\{AliceSid},{AliceSid},Multiple,C:\Users\alice,2026-03-01 09:00:00,",
              $@"2026-01-01 00:00:00,ROOT\ProfileList\{BobSid},{BobSid},Multiple,C:\Users\bob.CORP\,,",
              $@"2026-01-01 00:00:00,ROOT\ProfileList\{AliceSid},{AliceSid},Multiple,C:\Users\alice.OLD,,",
              $@"2026-01-01 00:00:00,ROOT\ProfileList\{Domain}-500,{Domain}-500,Multiple,C:\Users\Administrator,,");
        Write(Path.Combine(host, "Registry", "RECmd_SYSTEM_UserAccounts.csv"), SamHeader,
              @"True,ROOT\SAM\Users\000001F4,V,500,0,3,2025-01-01 00:00:00,Administrator",
              @"True,ROOT\SAM\Users\000001F5,V,501,0,0,2025-01-01 00:00:00,Guest",
              @"True,ROOT\SAM\Users\000003E9,V,1001,0,9,2025-01-01 00:00:00, alice ");

        Write(Path.Combine(host, "LNKFiles", "alice", "alice_LECmd_Recent.csv"), LnkHeader,
              Lnk("alice", "2026-03-01 09:00:00.1111111", "2026-03-02 10:00:00.2222222", @"C:\Finance\Q1.xlsx"),
              // A copied collection: created later than modified, so only modified is the user's.
              Lnk("alice", "2026-05-01 12:00:00", "2026-03-03 10:00:00", @"C:\Finance\Q2.xlsx"),
              Lnk("alice", "", "2026-03-04 10:00:00", "", @"\\FS01\Share\", @"\HR\salaries.xlsx"),
              Lnk("alice", "2026-03-05 10:00:00", "", "", @"\\FS01\Share", ""),
              Lnk("alice", "2026-03-06 10:00:00", "2026-03-06 10:00:00", "", "", "", @"Desktop\This PC\D:\Projects\plan.docx"),
              Lnk("alice", "2026-03-07 10:00:00", "2026-03-07 10:00:00", "https://intranet.example/page"),
              Lnk("alice", "2026-03-08 10:00:00", "2026-03-08 10:00:00", "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"),
              Lnk("alice", "2026-03-09 10:00:00", "2026-03-09 10:00:00", "\t C:\\Finance\\Trimmed.xlsx "),
              Lnk("alice", "bad time", "2026-03-10", @"C:\Finance\BadTimes.xlsx"));
        Write(Path.Combine(host, "LNKFiles", "bob.CORP", "bob.CORP_LECmd_Recent.csv"), LnkHeader,
              Lnk("bob.CORP", "2026-03-02 10:00:00", "2026-03-02 10:00:00", @"C:\Finance\Q1.xlsx"));
        // Output from before per-user folders: the user is in front of the tool's name.
        Write(Path.Combine(host, "LNKFiles", "dave_LECmd_OfficeRecent.csv"), LnkHeader,
              Lnk("dave", "2026-03-11 10:00:00", "2026-03-11 10:00:00", @"C:\Users\dave\Documents\Board.pptx"));

        Write(Path.Combine(host, "JumpLists", "alice", "alice_JLECmd_AutomaticDestinations.csv"), JumpListHeader,
              @"C:\evidence\C\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\a.automaticDestinations-ms,"
              + @"2026-01-01 00:00:00,2026-01-01 00:00:00,2026-01-01 00:00:00,1b4dd67f29cb1962,Windows Explorer,True,4,9,0,1,"
              + @"2026-03-02 10:00:00,2026-03-02 10:00:00.5,HOST01,00:00,C:\Finance\Q1.xlsx,1,Unpinned,,,,,0,",
              @"C:\evidence\C\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\a.automaticDestinations-ms,"
              + @"2026-01-01 00:00:00,2026-01-01 00:00:00,2026-01-01 00:00:00,1b4dd67f29cb1962,Windows Explorer,True,4,9,1,2,"
              + @"2026-03-12 10:00:00,2026-03-12 10:00:00,HOST01,00:00,,1,Unpinned,,,,C:\Finance\FromLocalPath.xlsx,0,");

        Write(Path.Combine(host, "ShellBags", "alice", "alice_SBECmd_Deduplicated.csv"), ShellBagsHeader,
              @"BagMRU\0,1,0,0,This PC,Root folder,This PC,1,,,,2026-03-01 09:00:00,,,0,2026-03-01 09:00:00,2026-03-02 09:00:00,True,,C:\evidence\C\Users\alice\NTUSER.DAT",
              @"BagMRU\0\0,2,0,0,C:\Finance,Directory,Finance,0,,,,2026-03-01 09:00:00,,,0,2026-03-01 09:00:00,2026-03-02 09:00:00,True,,C:\evidence\C\Users\alice\NTUSER.DAT",
              @"BagMRU\0\1,3,0,0,Desktop\Downloads\Tools,Directory,Tools,0,,,,2026-03-01 09:00:00,,,0,2026-03-13 09:00:00,2026-03-13 09:00:00,True,,C:\evidence\C\Users\alice\NTUSER.DAT",
              @"BagMRU\0\2,4,0,0,\\FS01\Share\HR,Directory,HR,0,,,,2026-03-01 09:00:00,,,0,,2026-03-14 09:00:00,True,,C:\evidence\C\Users\alice\NTUSER.DAT");

        Write(Path.Combine(host, "Registry", "alice", "alice_RECmd_NTUSER_RecentDocs.csv"), RecentDocsHeader,
              @".xlsx,Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs,0,RecentDocs,Q1.xlsx,Q1.lnk,0,2026-03-02 10:00:00,",
              @".docx,Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs,1,RecentDocs,notes.docx,notes.lnk,1,,");
        Write(Path.Combine(host, "Registry", "alice", "alice_RECmd_NTUSER_OpenSavePidlMRU.csv"), OpenSaveHeader,
              @"xlsx,Software\...\OpenSavePidlMRU,0,OpenSavePidlMRU,0,This PC\C:\Finance\Q1.xlsx,2026-03-02 10:00:00,");
        Write(Path.Combine(host, "Registry", "alice", "alice_RECmd_NTUSER_OfficeMRU.csv"), OfficeMruHeader,
              @"Item 1,Software\Microsoft\Office\16.0\Excel\File MRU,2026-03-15 10:00:00,File MRU,,C:\Finance\Budget.xlsx");

        var events = Path.Combine(host, "EventLogs");
        Write(Path.Combine(events, "EvtxECmd_EventLogs.csv"), EvtxHeader,
              Share("2026-03-16 10:00:00", 5140, "alice", AliceSid, @"\\*\Finance"),
              Share("2026-03-16 10:00:01", 5145, "alice", AliceSid, @"\\*\Finance\", @"\Q1\report.xlsx"),
              Share("2026-03-16 10:00:02", 5145, "bob", BobSid, @"\\FS02\Data", "plans.docx"),
              Share("2026-03-16 10:00:03", 5140, "alice", AliceSid, @"\\*\IPC$"),
              Share("2026-03-16 10:00:04", 5140, "FS01$", "S-1-5-18", @"\\*\Finance"),
              Share("2026-03-16 10:00:05", 5140, "alice", AliceSid, @"\\*\Finance", keywords: "Audit failure"),
              Share("2026-03-16 10:00:06", 5145, "alice", AliceSid, @"\\*\Finance", computer: ""),
              FileAudit("2026-03-17 10:00:00", "alice", "File", @"D:\Shares\Finance\Q1.xlsx", "%%4416"),
              FileAudit("2026-03-17 10:00:01", "alice", "File", @"D:\Shares\Finance\Q2.xlsx", "%%4417 %%4418"),
              FileAudit("2026-03-17 10:00:02", "alice", "File", @"D:\Shares\Finance\Old.xlsx", "%%1537"),
              FileAudit("2026-03-17 10:00:03", "alice", "File", @"D:\Shares\Finance\Meta.xlsx", "%%1538"),
              FileAudit("2026-03-17 10:00:04", "alice", "Key", @"\REGISTRY\MACHINE\SOFTWARE", "%%4416"),
              SecurityEvent("HOST01", "2026-03-17 10:00:05", 4663, "Audit success", "Microsoft-Windows-Sysmon/Operational",
                  ("SubjectUserName", "alice"), ("ObjectName", @"C:\x.txt")),
              // Not JSON: nothing can be read from it, as in the C# step.
              $"1,1,2026-03-17 10:00:06.0000000,5140,LogAlways,Microsoft-Windows-Security-Auditing,Security,4,8,HOST01,0,,,,,,,,,,,,False,C:\\x\\Security.evtx,Audit success,0,\"{{not json\"",
              // One Data element is an object rather than a list.
              $"1,1,2026-03-17 10:00:07.0000000,5140,LogAlways,Microsoft-Windows-Security-Auditing,Security,4,8,HOST01,0,,,,,,,,,,,,False,C:\\x\\Security.evtx,Audit success,0,"
              + "\"{\"\"EventData\"\":{\"\"Data\"\":{\"\"@Name\"\":\"\"SubjectUserName\"\",\"\"#text\"\":\"\"alice\"\"}}}\"");
        // An older run of the same module: only the newest file is read.
        Write(Path.Combine(events, "EvtxECmd_EventLogs_2.csv"), EvtxHeader,
              Share("2026-03-18 10:00:00", 5140, "alice", AliceSid, @"\\*\Old"));
        File.SetLastWriteTimeUtc(Path.Combine(events, "EvtxECmd_EventLogs_2.csv"), new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        File.SetLastWriteTimeUtc(Path.Combine(events, "EvtxECmd_EventLogs.csv"), new DateTime(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc));
    }

    private static void LinuxHost(string caseDir, string collection)
    {
        var host = Path.Combine(caseDir, collection);
        Write(Path.Combine(host, "Users", "LinuxUsers_passwd.csv"),
              "\"Username\",\"UID\",\"GID\",\"Description\",\"HomeDir\",\"Shell\",\"IsRootEquiv\",\"IsSystem\",\"CanLogin\",\"PasswdField\"",
              "\"root\",\"0\",\"0\",\"root\",\"/root\",\"/bin/bash\",\"\",\"yes\",\"yes\",\"x\"",
              "\"daemon\",\"1\",\"1\",\"\",\"/usr/sbin\",\"/usr/sbin/nologin\",\"\",\"yes\",\"\",\"x\"",
              "\"erin\",\"1000\",\"1000\",\"\",\"/home/erin\",\"/bin/bash\",\"\",\"\",\" YES \",\"x\"");
        Write(Path.Combine(host, "UserFiles", "erin", "erin_LinuxUserFiles_OtherHistory.csv"),
              "\"User\",\"Source\",\"Type\",\"Line\",\"Entry\",\"TimeUtc\"",
              "\"erin\",\"recently-used.xbel\",\"recent file (desktop)\",\"1\",\"file:///home/erin/Finance/Q1 report.ods\",\"2026-03-01 10:00:00\"",
              "\"erin\",\"recently-used.xbel\",\"recent file (desktop)\",\"2\",\"sftp://fs01/share/x.txt\",\"2026-03-01 10:05:00\"",
              "\"erin\",\".viminfo\",\"vim file mark\",\"20\",\"~/notes.txt\",\"2026-03-02 11:00:00\"",
              "\"erin\",\".viminfo\",\"vim file mark\",\"21\",\"/etc/shadow\",\"2026-03-02 11:00:00.5\"",
              "\"erin\",\".viminfo\",\"vim file edited\",\"22\",\"/etc/passwd\",\"\"");
    }

    /// <summary>Runs both, checks every file is the same, and returns the case's DataAccess.csv lines.</summary>
    private static string[] RunBoth(string caseDir)
    {
        DataAccessReport.Build(caseDir);
        var result = LakeBuilder.Build(caseDir, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30 });
        Assert.NotEqual(LakeOutcome.Failed, result.Outcome);
        Assert.DoesNotContain(result.Warnings, w => w.Contains("data access", StringComparison.OrdinalIgnoreCase));

        var lakeRoot = DataAccessResults.OutputRootFor(Path.Combine(caseDir, LakeNames.LakeFolder));
        var expected = FilesUnder(caseDir);
        var actual = FilesUnder(lakeRoot);
        Assert.Equal(expected.Keys.Order(), actual.Keys.Order());
        foreach (var (relative, path) in expected)
        {
            var want = File.ReadAllBytes(path);
            var got = File.ReadAllBytes(actual[relative]);
            if (want.SequenceEqual(got)) continue;
            var wantLines = Encoding.UTF8.GetString(want).Split("\r\n");
            var gotLines = Encoding.UTF8.GetString(got).Split("\r\n");
            var at = Enumerable.Range(0, Math.Max(wantLines.Length, gotLines.Length))
                               .First(i => wantLines.ElementAtOrDefault(i) != gotLines.ElementAtOrDefault(i));
            Assert.Fail($"{relative} differs at line {at + 1}:\n  C#:   {wantLines.ElementAtOrDefault(at)}\n  lake: {gotLines.ElementAtOrDefault(at)}");
        }
        var report = DataAccessReport.PathFor(caseDir);
        return File.Exists(report) ? File.ReadAllLines(report) : [];
    }

    /// <summary>The data access files under a case-shaped root, by path relative to it.</summary>
    private static Dictionary<string, string> FilesUnder(string root)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in new[] { DataAccessResults.CaseFileName, DataAccessResults.UserListFileName })
            if (File.Exists(Path.Combine(root, name))) files[name] = Path.Combine(root, name);
        foreach (var host in Directory.EnumerateDirectories(root).Where(d => !Path.GetFileName(d).StartsWith('_')))
        {
            var folder = Path.Combine(host, DataAccessReport.Folder);
            if (!Directory.Exists(folder)) continue;
            foreach (var file in Directory.EnumerateFiles(folder))
                files[Path.GetRelativePath(root, file)] = file;
        }
        return files;
    }

    private static void Compromised(string caseDir, params string[] rows) =>
        Write(Path.Combine(caseDir, CaseUsers.CompromisedFileName), ["Username,SID,Comment", .. rows]);

    private static void WholeCase(string caseDir)
    {
        WindowsHost(caseDir, "HOST01", "HOST01");
        // A second collection of the same machine: what both hold is one row in DataAccess.csv.
        WindowsHost(caseDir, "HOST01-again", "HOST01");
        LinuxHost(caseDir, "lnx01");
        // A folder with nothing either reads.
        Write(Path.Combine(caseDir, "WS-EMPTY", "Prefetch", "PECmd_Output.csv"), "A,B", "1,2");
    }

    [Fact]
    public void Every_reader_and_rule_gives_the_files_the_CSharp_step_writes()
    {
        using var dir = new TempDirectory();
        WholeCase(dir.Path);
        Compromised(dir.Path,
            "alice,,by name, so the domain account's rows count too",
            $",{BobSid},by SID only",
            @"CORP\dave,,with a domain",
            "erin@corp.example,,",
            "nobody,,not on any host",
            ",,");

        var lines = RunBoth(dir.Path);

        Assert.Contains(lines, l => l.Contains(@"\\FS01\Finance\Q1\report.xlsx") && l.Contains(AccessRow.AccessedOverShare));
        Assert.Contains(lines, l => l.Contains(@"D:\Projects\plan.docx"));
        Assert.Contains(lines, l => l.Contains(@"""bob.CORP"""));
        Assert.Contains(lines, l => l.Contains(@"""dave"""));
        Assert.Contains(lines, l => l.Contains("/home/erin/Finance/Q1 report.ods"));
        Assert.DoesNotContain(lines, l => l.Contains("intranet") || l.Contains("IPC$") || l.Contains(@"\\*\Old") || l.Contains("FS01$"));
        Assert.Single(lines, l => l.StartsWith("\"2026-03-02 10:00:00\",\"HOST01\",\"alice\",\"C:\\Finance\\Q1.xlsx\",\"Opened\""));
    }

    [Fact]
    public void A_local_account_and_a_domain_account_of_one_name_are_told_apart_by_SID()
    {
        using var dir = new TempDirectory();
        WholeCase(dir.Path);
        Compromised(dir.Path, $"alice,{LocalAliceSid},the local alice only", "alice.OLD,,a suffix on the wanted name is not peeled");

        var lines = RunBoth(dir.Path);

        // The domain alice's rows have her domain SID, so the local alice's SID matches none of them.
        Assert.DoesNotContain(lines.Skip(1), l => l.Contains(@"""alice"""));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Username,SID,Comment")]
    public void With_nobody_listed_only_the_account_lists_are_written(string? header)
    {
        using var dir = new TempDirectory();
        WholeCase(dir.Path);
        if (header is not null) Write(Path.Combine(dir.Path, CaseUsers.CompromisedFileName), header);

        Assert.Empty(RunBoth(dir.Path));
        Assert.True(File.Exists(CaseUsers.UserListPathFor(dir.Path)));
    }

    [Fact]
    public void The_lake_matches_listed_users_to_accounts_exactly_as_CaseUsers_Matches_does()
    {
        string[] names = ["alice", "Alice", @"CORP\alice", @"corp\ALICE", "alice@corp.example", "alice.000", "alice.CORP",
                          "alice.corp", "alice.CORP.001", "alice.CORP.x", "alice.", ".alice", "alice.smith", "malice",
                          "john.smith", "john.smith.CORP", @"CORP\john.smith", "alice.A-1", " alice ", "", @"\alice", "alice@"];
        string[] sids = ["", AliceSid, BobSid, AliceSid.ToLowerInvariant()];
        using var dir = new TempDirectory();
        Write(Path.Combine(dir.Path, "HOST01", "Prefetch", "PECmd_Output.csv"), "A,B", "1,2");
        var lake = LakeBuilder.Build(dir.Path, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30, RunAnalyses = false });
        using var session = new LakeQuerySession(lake.DatabasePath!, dir.Path);
        session.RunToRows(LakeQueryCatalogue.Find("data_access_compromised")!);

        static string Lit(string s) => "'" + s.Replace("'", "''") + "'";
        var cases = (from wanted in names from wantedSid in sids from name in names from sid in sids.Take(3)
                     select (Wanted: wanted.Trim(), WantedSid: wantedSid, Name: name, Sid: sid)).ToList();
        using var command = session.CreateCommand();
        command.CommandText = "SELECT da_matches(w, ws, n, s) FROM (VALUES " +
                              string.Join(", ", cases.Select((c, i) => $"({i}, {Lit(c.Wanted)}, {Lit(c.WantedSid)}, {Lit(c.Name)}, {Lit(c.Sid)})")) +
                              ") AS t(i, w, ws, n, s) ORDER BY i";
        using var reader = command.ExecuteReader();
        var at = 0;
        while (reader.Read())
        {
            var c = cases[at++];
            var expected = CaseUsers.Matches(new CompromisedUser(c.Wanted, c.WantedSid), c.Name, c.Sid);
            Assert.True(expected == reader.GetBoolean(0), $"'{c.Wanted}' ({c.WantedSid}) against '{c.Name}' ({c.Sid}): C# says {expected}");
        }
        Assert.Equal(cases.Count, at);
    }

    [Fact]
    public void A_list_without_its_columns_lists_nobody_in_both_and_the_lake_build_says_so()
    {
        using var dir = new TempDirectory();
        WholeCase(dir.Path);
        File.WriteAllLines(Path.Combine(dir.Path, CaseUsers.CompromisedFileName), ["Account,Note", "alice,x"]);

        var csharp = DataAccessReport.Build(dir.Path);
        var lake = LakeBuilder.Build(dir.Path, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30 });

        Assert.Contains(csharp, r => r.Status == Core.WorkStatus.Failed);
        Assert.Equal(LakeOutcome.BuiltCheckLog, lake.Outcome);
        Assert.Contains(lake.Warnings, w => w.Contains("data access") && w.Contains(CaseUsers.CompromisedFileName));
        var root = DataAccessResults.OutputRootFor(lake.LakeDirectory!);
        Assert.False(File.Exists(Path.Combine(root, DataAccessResults.CaseFileName)));
        Assert.Equal(File.ReadAllBytes(CaseUsers.UserListPathFor(dir.Path)),
                     File.ReadAllBytes(Path.Combine(root, DataAccessResults.UserListFileName)));
    }
}
