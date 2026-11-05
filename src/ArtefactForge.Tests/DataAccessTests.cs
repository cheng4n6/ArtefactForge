using System.Text;
using ArtefactForge.Core;
using ArtefactForge.Core.DataAccess;

namespace ArtefactForge.Tests;

/// <summary>
/// The data access report: the case's accounts, the analyst's compromised users, and the files and
/// folders they opened, from module output written with each tool's own headers. Made-up hosts,
/// users and files throughout.
/// </summary>
public class DataAccessTests
{
    private const string LnkHeader =
        "SourceFile,SourceCreated,SourceModified,SourceAccessed,TargetCreated,TargetModified,TargetAccessed,FileSize,"
        + "RelativePath,WorkingDirectory,FileAttributes,HeaderFlags,DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,"
        + "NetworkPath,CommonPath,Arguments,TargetIDAbsolutePath";

    private const string JumpListHeader =
        "SourceFile,SourceCreated,SourceModified,SourceAccessed,AppId,AppIdDescription,HasSps,DestListVersion,"
        + "LastUsedEntryNumber,MRU,EntryNumber,CreationTime,LastModified,Hostname,MacAddress,Path,InteractionCount,"
        + "PinStatus,TargetCreated,TargetModified,TargetAccessed,LocalPath";

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

    private const string AliceSid = "S-1-5-21-1111111111-2222222222-3333333333-1104";
    private const string BobSid = "S-1-5-21-1111111111-2222222222-3333333333-1105";

    private static void Write(string path, params string[] lines)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllLines(path, lines, new UTF8Encoding(true));
    }

    /// <summary>A Windows host with SystemInfo, ProfileList and the SAM.</summary>
    private static string Host(TempDirectory dir, string name)
    {
        var host = dir.Dir(name);
        Write(Path.Combine(host, "SystemInfo", "SystemInfo.csv"),
              "\"Category\",\"Item\",\"Value\",\"Source\"", $"\"Identity\",\"Hostname\",\"{name}\",\"SYSTEM\"");
        Write(Path.Combine(host, "Registry", "RECmd_SYSTEM_ProfileList.csv"), ProfileListHeader,
              @"2026-01-01 00:00:00,ROOT\ProfileList\S-1-5-18,S-1-5-18,Multiple,%systemroot%\system32\config\systemprofile,,",
              $@"2026-01-01 00:00:00,ROOT\ProfileList\{AliceSid},{AliceSid},Multiple,C:\Users\alice,2026-03-01 09:00:00,",
              $@"2026-01-01 00:00:00,ROOT\ProfileList\{BobSid},{BobSid},Multiple,C:\Users\bob.CORP,,");
        Write(Path.Combine(host, "Registry", "RECmd_SYSTEM_UserAccounts.csv"), SamHeader,
              @"True,ROOT\SAM\Users\000001F4,V,500,0,3,2025-01-01 00:00:00,Administrator");
        return host;
    }

    private static string Lnk(string user, string created, string modified, string target, string network = "", string common = "") =>
        $@"C:\evidence\C\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\x.lnk,{created},{modified},2026-04-01 00:00:00,"
        + $"2020-01-01 00:00:00,2020-01-02 00:00:00,2020-01-03 00:00:00,100,,,,,,,,{target},{network},{common},,";

    private static string JsonValue(string text) => text.Replace(@"\", @"\\");

    private static string SecurityEvent(string computer, string time, int id, string keywords, params (string, string)[] data) =>
        $"1,1,{time}.0000000,{id},LogAlways,Microsoft-Windows-Security-Auditing,Security,4,8,{computer},0,,,,,,,,,,,,False,"
        + $@"C:\x\Security.evtx,{keywords},0,"
        + "\"{\"\"EventData\"\":{\"\"Data\"\":["
        + string.Join(",", data.Select(d => $"{{\"\"@Name\"\":\"\"{d.Item1}\"\",\"\"#text\"\":\"\"{JsonValue(d.Item2)}\"\"}}"))
        + "]}}\"";

    private static string ShareEvent(string computer, string time, int id, string user, string share, string relative, string keywords = "Audit success") =>
        SecurityEvent(computer, time, id, keywords,
            ("SubjectUserSid", user == "bob" ? BobSid : AliceSid), ("SubjectUserName", user), ("SubjectDomainName", "CORP"),
            ("IpAddress", "10.0.0.5"), ("ShareName", share), ("ShareLocalPath", @"\??\D:\Shares"), ("RelativeTargetName", relative));

    private static string FileAudit(string time, string user, string type, string path, string accessList) =>
        SecurityEvent("FS01.corp.example", time, 4663, "Audit success",
            ("SubjectUserSid", AliceSid), ("SubjectUserName", user), ("SubjectDomainName", "CORP"),
            ("ObjectType", type), ("ObjectName", path), ("AccessList", accessList), ("AccessMask", "0x1"));

    private static List<Dictionary<string, string>> ReadCsv(string path)
    {
        var lines = File.ReadAllLines(path);
        var header = Core.Ioc.CsvText.Split(lines[0].TrimStart('\uFEFF'));
        return lines.Skip(1).Select(l => Core.Ioc.CsvText.Split(l))
                    .Select(f => header.Select((h, i) => (h, v: i < f.Length ? f[i] : "")).ToDictionary(p => p.h, p => p.v))
                    .ToList();
    }

    // --- accounts ---------------------------------------------------------------------------------

    [Fact]
    public void Accounts_join_profile_list_sam_and_output_folders_with_sids_filled_in()
    {
        using var dir = new TempDirectory();
        var host = Host(dir, "HOST01");
        dir.Dir(Path.Combine("HOST01", "LNKFiles", "alice"));
        dir.Dir(Path.Combine("HOST01", "Registry", "Default"));
        dir.Dir(Path.Combine("HOST01", "JumpLists", "carol"));

        var accounts = CaseUsers.ReadHost(host, "HOST01");

        var alice = Assert.Single(accounts, a => a.Username == "alice");
        Assert.Equal(AliceSid, alice.Sid);
        Assert.Equal(@"C:\Users\alice", alice.ProfilePath);
        Assert.Equal("ProfileList; Output folders", alice.Source);
        Assert.Equal(BobSid, Assert.Single(accounts, a => a.Username == "bob.CORP").Sid);
        Assert.Equal("", Assert.Single(accounts, a => a.Username == "carol").Sid);
        Assert.Equal("SAM", Assert.Single(accounts, a => a.Username == "Administrator").Source);
        Assert.DoesNotContain(accounts, a => a.Username is "Default" or "systemprofile");
    }

    [Fact]
    public void Linux_accounts_that_can_log_on_come_from_passwd()
    {
        using var dir = new TempDirectory();
        Write(Path.Combine(dir.Path, "LNX01", "Users", "LinuxUsers_passwd.csv"),
              "\"Username\",\"UID\",\"GID\",\"Description\",\"HomeDir\",\"Shell\",\"IsRootEquiv\",\"IsSystem\",\"CanLogin\",\"PasswdField\"",
              "\"root\",\"0\",\"0\",\"root\",\"/root\",\"/bin/bash\",\"\",\"yes\",\"yes\",\"x\"",
              "\"daemon\",\"1\",\"1\",\"\",\"/usr/sbin\",\"/usr/sbin/nologin\",\"\",\"yes\",\"\",\"x\"",
              "\"dave\",\"1000\",\"1000\",\"\",\"/home/dave\",\"/bin/bash\",\"\",\"\",\"yes\",\"x\"");

        DataAccessReport.Build(dir.Path);

        var list = CaseUsers.LoadUserList(dir.Path);
        Assert.Equal(["root", "dave"], list.Select(a => a.Username).OrderByDescending(n => n));
        Assert.All(list, a => Assert.Equal("passwd", a.Source));
    }

    // --- matching ---------------------------------------------------------------------------------

    [Theory]
    [InlineData("alice", "", "alice", "", true)]
    [InlineData("ALICE", "", "alice", "", true)]
    [InlineData(@"CORP\alice", "", "alice", "", true)]
    [InlineData("alice@corp.example", "", @"CORP\alice", "", true)]
    [InlineData("alice", "", "alice.CORP", "", true)]
    [InlineData("alice", "", "alice.000", "", true)]
    [InlineData("alice", "", "alice.CORP.001", "", true)]
    [InlineData(@"CORP\alice", "", "alice.corp", "", true)]
    [InlineData("alice", "", "alice.smith", "", false)]
    [InlineData("john", "", "john.smith", "", false)]
    [InlineData("alice", "", "malice", "", false)]
    [InlineData("", AliceSid, "anything", AliceSid, true)]
    [InlineData("alice", AliceSid, "alice", BobSid, false)]
    [InlineData("alice", AliceSid, "alice", "", true)]
    [InlineData("", AliceSid, "alice", "", false)]
    public void Compromised_users_match_by_sid_when_both_have_one_else_by_name(string user, string sid, string name, string rowSid, bool expected) =>
        Assert.Equal(expected, CaseUsers.Matches(new CompromisedUser(user, sid), name, rowSid));

    // --- grouping ---------------------------------------------------------------------------------

    [Fact]
    public void Accounts_group_into_one_entry_each_by_sid_or_else_by_name()
    {
        const string Admin1 = "S-1-5-21-1-1-1-500", Admin2 = "S-1-5-21-2-2-2-500";
        var groups = CaseUsers.Group(
        [
            new UserAccount("WS01", "alice", AliceSid, @"C:\Users\alice", "ProfileList"),
            new UserAccount("WS02", "alice", AliceSid, @"C:\Users\alice", "ProfileList"),
            new UserAccount("FS01", "alice.CORP", "", "", "Output folders"),
            new UserAccount("WS01", "Administrator", Admin1, "", "SAM"),
            new UserAccount("WS02", "Administrator", Admin2, "", "SAM"),
            new UserAccount("WS02", "Administrator.000", "", "", "Output folders"),
            new UserAccount("LNX01", "dave", "", "/home/dave", "LinuxUsers"),
            new UserAccount("LNX02", "dave", "", "/home/dave", "LinuxUsers"),
        ]);

        Assert.Equal(
            [("Administrator", Admin1, "WS01"), ("Administrator", Admin2, "WS02, WS02"), ("alice", AliceSid, "FS01, WS01, WS02"), ("dave", "", "LNX01, LNX02")],
            groups.OrderBy(g => g.Username, StringComparer.OrdinalIgnoreCase).ThenBy(g => g.Sid)
                  .Select(g => (g.Username, g.Sid, string.Join(", ", g.Accounts.Select(a => a.System)))));
    }

    [Fact]
    public void A_group_is_listed_when_any_of_its_accounts_matches()
    {
        var group = CaseUsers.Group(
        [
            new UserAccount("WS01", "alice", AliceSid, "", "ProfileList"),
            new UserAccount("FS01", "alice.CORP", "", "", "Output folders"),
        ]).Single();

        Assert.True(group.IsListed([new CompromisedUser("alice", "")]));
        Assert.True(group.IsListed([new CompromisedUser("", AliceSid)]));
        Assert.False(group.IsListed([new CompromisedUser("", BobSid)]));
        Assert.True(new AccountGroup("eve", "", []).IsListed([new CompromisedUser("EVE", "")]));
    }

    [Fact]
    public void Ticking_and_unticking_users_keeps_every_other_row_and_column_as_it_was()
    {
        using var dir = new TempDirectory();
        var path = CaseUsers.CompromisedPathFor(dir.Path);
        File.WriteAllText(path, "Username,SID,Comment,Analyst\r\nbob,,\"phished, 1 March\",AN\r\n");

        CaseUsers.AddCompromised(dir.Path, new CompromisedUser("alice", AliceSid));
        CaseUsers.AddCompromised(dir.Path, new CompromisedUser("alice", AliceSid));   // already there
        Assert.Equal(["Username,SID,Comment,Analyst", "bob,,\"phished, 1 March\",AN", $"alice,{AliceSid},,"],
                     File.ReadAllLines(path).Select(l => l.TrimStart('\uFEFF')));

        CaseUsers.RemoveCompromised(dir.Path, new CompromisedUser("alice", AliceSid));
        Assert.Equal(["Username,SID,Comment,Analyst", "bob,,\"phished, 1 March\",AN"], File.ReadAllLines(path).Select(l => l.TrimStart('\uFEFF')));
        Assert.Equal([new CompromisedUser("bob", "")], CaseUsers.ReadCompromised(dir.Path));
    }

    [Fact]
    public void A_compromised_list_without_its_columns_is_reported_not_read_as_empty()
    {
        using var dir = new TempDirectory();
        Host(dir, "HOST01");
        File.WriteAllText(CaseUsers.CompromisedPathFor(dir.Path), "Name,Note\r\nalice,x\r\n");

        var results = DataAccessReport.Build(dir.Path);

        Assert.Contains(results, r => r.Status == WorkStatus.Failed && r.Reason!.Contains("Username or SID"));
    }

    // --- artefacts --------------------------------------------------------------------------------

    [Fact]
    public void Lnk_files_give_last_opened_and_first_opened_unless_created_was_set_by_a_copy()
    {
        using var dir = new TempDirectory();
        var file = Path.Combine(dir.Path, "alice_LECmd_Recent.csv");
        Write(file, LnkHeader,
              Lnk("alice", "2026-02-01 10:00:00", "2026-02-03 11:00:00", @"D:\Finance\Budget.xlsx"),
              // Created after modified: the collection was copied without creation times.
              Lnk("alice", "2026-04-01 08:00:00", "2026-02-04 12:00:00", @"D:\Finance\Payroll.xlsx"),
              Lnk("alice", "", "2026-02-05 09:00:00", "", @"\\FS01\HR", @"Reviews\2026.docx"),
              Lnk("alice", "", "2026-02-06 09:00:00", "", "", ""));

        var rows = DataAccessReport.ReadLnk(file, default).ToList();

        Assert.Equal(
            [
                ("2026-02-03 11:00:00", @"D:\Finance\Budget.xlsx"), ("2026-02-01 10:00:00", @"D:\Finance\Budget.xlsx"),
                ("2026-02-04 12:00:00", @"D:\Finance\Payroll.xlsx"), ("2026-02-05 09:00:00", @"\\FS01\HR\Reviews\2026.docx")
            ],
            rows.Select(r => (r.TimeUtc.ToString("yyyy-MM-dd HH:mm:ss"), r.Path)));
        Assert.All(rows, r => Assert.Equal(AccessRow.Opened, r.Activity));
        Assert.DoesNotContain(rows, r => r.TimeUtc.Year == 2020);   // the target's own times
    }

    [Fact]
    public void Jump_lists_use_the_destlist_time_and_leave_out_app_links()
    {
        using var dir = new TempDirectory();
        var file = Path.Combine(dir.Path, "alice_JLECmd_AutomaticDestinations.csv");
        Write(file, JumpListHeader,
              @"C:\e\x.automaticDestinations-ms,,,,abc,Word,False,6,1,0,1,2025-01-01 00:00:00,2026-02-10 14:00:00,,,D:\Finance\Plan.docx,1,False,2020-01-01 00:00:00,,,",
              @"C:\e\y.automaticDestinations-ms,,,,def,Teams,False,6,1,0,2,,2026-02-11 14:00:00,,,ms-teams:quit,1,False,,,,",
              @"C:\e\y.automaticDestinations-ms,,,,def,Teams,False,6,1,0,3,,,,,D:\Finance\Undated.docx,1,False,,,,");

        var row = Assert.Single(DataAccessReport.ReadJumpList(file, default));

        Assert.Equal((new DateTime(2026, 2, 10, 14, 0, 0), @"D:\Finance\Plan.docx"), (row.TimeUtc, row.Path));
    }

    [Fact]
    public void Shellbags_give_folders_on_drives_and_shares_with_first_and_last_interacted()
    {
        using var dir = new TempDirectory();
        var file = Path.Combine(dir.Path, "alice_SBECmd_Deduplicated.csv");
        Write(file, ShellBagsHeader,
              @"BagMRU\0,0,0,0,Desktop\This PC,Root folder: GUID,This PC,1,,,,2026-02-01 00:00:00,,,0,,2026-02-01 00:00:00,False,,C:\e\UsrClass.dat",
              @"BagMRU\0\1,1,0,0,Desktop\This PC\D:\Finance,Directory,Finance,0,,,,2026-02-02 00:00:00,,,1,2026-01-20 08:00:00,2026-02-02 09:30:00,True,,C:\e\UsrClass.dat",
              @"BagMRU\2,2,0,1,\\FS01\HR,Network location,HR,0,,,,,,,0,,2026-02-03 10:00:00,False,,C:\e\UsrClass.dat",
              @"BagMRU\3,3,0,2,D:\Old,Directory,Old,0,,,,,,,0,,,False,,C:\e\UsrClass.dat");

        var rows = DataAccessReport.ReadShellBags(file, default).ToList();

        Assert.Equal(
            [("2026-01-20 08:00", @"D:\Finance"), ("2026-02-02 09:30", @"D:\Finance"), ("2026-02-03 10:00", @"\\FS01\HR")],
            rows.Select(r => (r.TimeUtc.ToString("yyyy-MM-dd HH:mm"), r.Path)));
        Assert.All(rows, r => Assert.Equal(AccessRow.FolderBrowsed, r.Activity));
    }

    [Fact]
    public void Registry_mrus_give_only_their_dated_entries()
    {
        using var dir = new TempDirectory();
        var recent = Path.Combine(dir.Path, "alice_RECmd_NTUSER_RecentDocs.csv");
        Write(recent, RecentDocsHeader,
              @"RecentDocs,ROOT\RecentDocs,3,3,Budget.xlsx,Budget.lnk,0,2026-02-12 08:00:00.1234567,",
              @"RecentDocs,ROOT\RecentDocs,2,2,Older.xlsx,Older.lnk,1,,");
        var openSave = Path.Combine(dir.Path, "alice_RECmd_NTUSER_OpenSavePidlMRU.csv");
        Write(openSave, OpenSaveHeader,
              @"*,ROOT\OpenSavePidlMRU\*,4,4,0,Desktop\This PC\D:\Finance\Export.zip,2026-02-13 09:00:00.0000000,x",
              @"*,ROOT\OpenSavePidlMRU\*,5,5,1,Downloads\tool.zip,,x");
        var office = Path.Combine(dir.Path, "alice_RECmd_NTUSER_OfficeMRU.csv");
        Write(office, OfficeMruHeader,
              @"Item 1,ROOT\Excel\File MRU,2026-02-14 10:00:00.0000000,Item 1,,D:\Finance\Q1.xlsx",
              @"FOLDERID_Desktop,ROOT\Excel\File MRU,,FOLDERID_Desktop,,C:\Users\alice\Desktop\");

        Assert.Equal(("Budget.xlsx", AccessRow.Opened), DataAccessReport.ReadRecentDocs(recent, default).Select(r => (r.Path, r.Activity)).Single());
        Assert.Equal((@"D:\Finance\Export.zip", AccessRow.OpenedOrSaved), DataAccessReport.ReadOpenSave(openSave, default).Select(r => (r.Path, r.Activity)).Single());
        Assert.Equal(@"D:\Finance\Q1.xlsx", DataAccessReport.ReadOfficeMru(office, default).Single().Path);
    }

    [Fact]
    public void Share_events_name_the_file_on_the_host_and_leave_out_failures_machines_and_ipc()
    {
        using var dir = new TempDirectory();
        var file = Path.Combine(dir.Path, "EvtxECmd_EventLogs.csv");
        Write(file, EvtxHeader,
              ShareEvent("FS01.corp.example", "2026-02-20 10:00:00", 5145, "alice", @"\\*\Finance", @"Payroll\March.xlsx"),
              ShareEvent("FS01.corp.example", "2026-02-20 10:00:01", 5140, "alice", @"\\*\Finance", ""),
              ShareEvent("FS01.corp.example", "2026-02-20 10:00:02", 5145, "alice", @"\\*\Finance", @"Secret.docx", "Audit failure"),
              ShareEvent("FS01.corp.example", "2026-02-20 10:00:03", 5145, "WS01$", @"\\*\Finance", @"x.txt"),
              ShareEvent("FS01.corp.example", "2026-02-20 10:00:04", 5145, "alice", @"\\*\IPC$", @"srvsvc"));

        var rows = DataAccessReport.ReadSecurityEvents(file, default).ToList();

        Assert.Equal(
            [(@"\\FS01\Finance\Payroll\March.xlsx", AccessRow.AccessedOverShare), (@"\\FS01\Finance", AccessRow.ShareAccessed)],
            rows.Select(r => (r.Path, r.Activity)));
        Assert.All(rows, r => Assert.Equal((@"CORP\alice", AliceSid), (r.User, r.Sid)));
    }

    [Fact]
    public void File_audit_events_say_whether_a_file_was_read_written_or_deleted()
    {
        using var dir = new TempDirectory();
        var file = Path.Combine(dir.Path, "EvtxECmd_EventLogs.csv");
        Write(file, EvtxHeader,
              FileAudit("2026-02-21 09:00:00", "alice", "File", @"D:\Finance\Payroll.xlsx", "%%4416 "),
              FileAudit("2026-02-21 09:00:01", "alice", "File", @"D:\Finance\Payroll.xlsx", "%%4417 %%4416"),
              FileAudit("2026-02-21 09:00:02", "alice", "File", @"D:\Finance\Old.xlsx", "%%1537"),
              FileAudit("2026-02-21 09:00:03", "alice", "File", @"D:\Finance\Old.xlsx", "%%4423"),
              FileAudit("2026-02-21 09:00:04", "alice", "Key", @"\REGISTRY\MACHINE\SOFTWARE\x", "%%4416"),
              FileAudit("2026-02-21 09:00:05", "WS01$", "File", @"D:\Finance\x.txt", "%%4416"));

        var rows = DataAccessReport.ReadSecurityEvents(file, default).ToList();

        Assert.Equal(
            [
                (@"D:\Finance\Payroll.xlsx", AccessRow.Read), (@"D:\Finance\Payroll.xlsx", AccessRow.Written),
                (@"D:\Finance\Old.xlsx", AccessRow.Deleted), (@"D:\Finance\Old.xlsx", AccessRow.Accessed)
            ],
            rows.Select(r => (r.Path, r.Activity)));
        Assert.All(rows, r => Assert.Equal((@"CORP\alice", AliceSid), (r.User, r.Sid)));
    }

    [Fact]
    public void Linux_recent_files_and_vim_marks_are_read_with_their_times()
    {
        using var dir = new TempDirectory();
        var file = Path.Combine(dir.Path, "dave_LinuxUserFiles_OtherHistory.csv");
        Write(file, "\"User\",\"Source\",\"Type\",\"Line\",\"Entry\",\"TimeUtc\"",
              "\"dave\",\"recently-used.xbel\",\"recent file (desktop)\",\"1\",\"file:///home/dave/Finance/Q1 report.ods\",\"2026-03-01 10:00:00\"",
              "\"dave\",\"recently-used.xbel\",\"recent file (desktop)\",\"2\",\"sftp://fs01/share/x.txt\",\"2026-03-01 10:05:00\"",
              "\"dave\",\".viminfo\",\"vim file mark\",\"20\",\"/etc/shadow\",\"2026-03-02 11:00:00\"",
              "\"dave\",\".viminfo\",\"vim file edited\",\"21\",\"/etc/passwd\",\"\"",
              "\"dave\",\".viminfo\",\"vim command\",\"3\",\"wq\",\"2026-03-02 11:01:00\"");

        var rows = DataAccessReport.ReadLinuxRecent(file, default).ToList();

        Assert.Equal(
            [("/home/dave/Finance/Q1 report.ods", AccessRow.Opened), ("/etc/shadow", AccessRow.OpenedInVim)],
            rows.Select(r => (r.Path, r.Activity)));
        Assert.All(rows, r => Assert.Equal("dave", r.User));
    }

    [Fact]
    public void The_case_report_has_a_data_access_section_per_account_and_host()
    {
        using var dir = new TempDirectory();
        HostWithActivity(dir, "HOST01");
        CaseUsers.AddCompromised(dir.Path, new CompromisedUser("alice", ""));
        DataAccessReport.Build(dir.Path);

        var html = File.ReadAllText(Core.Report.CaseReport.Rebuild(dir.Path).Path!);

        Assert.Contains("id=\"dataaccess\"", html);
        Assert.Contains("2026-02-01 09:00:00", html);
        Assert.Contains("Opened 2", html);
    }

    // --- the case ---------------------------------------------------------------------------------

    /// <summary>A host with LNK output for alice and bob in their own folders, and one shared event for each.</summary>
    private static string HostWithActivity(TempDirectory dir, string name)
    {
        var host = Host(dir, name);
        Write(Path.Combine(host, "LNKFiles", "alice", "alice_LECmd_Recent.csv"), LnkHeader,
              Lnk("alice", "", "2026-02-03 11:00:00", @"D:\Finance\Budget.xlsx"),
              Lnk("alice", "", "2026-02-01 09:00:00", @"D:\Finance\Plan.xlsx"));
        Write(Path.Combine(host, "LNKFiles", "bob.CORP", "bob.CORP_LECmd_Recent.csv"), LnkHeader,
              Lnk("bob.CORP", "", "2026-02-02 11:00:00", @"D:\Bob\Notes.txt"));
        Write(Path.Combine(host, "JumpLists", "alice", "alice_JLECmd_AutomaticDestinations.csv"), JumpListHeader,
              // The same open the LNK gives: one row in the report.
              @"C:\e\x.automaticDestinations-ms,,,,abc,Excel,False,6,1,0,1,,2026-02-03 11:00:00,,,D:\Finance\Budget.xlsx,1,False,,,,");
        return host;
    }

    [Fact]
    public void The_report_has_only_the_compromised_users_rows_sorted_and_without_repeats()
    {
        using var dir = new TempDirectory();
        HostWithActivity(dir, "HOST01");
        HostWithActivity(dir, "HOST02");
        CaseUsers.AddCompromised(dir.Path, new CompromisedUser(@"CORP\alice", ""));

        var results = DataAccessReport.Build(dir.Path);

        Assert.Equal(2, results.Count(r => r.Status == WorkStatus.Completed));
        var rows = ReadCsv(DataAccessReport.PathFor(dir.Path));
        Assert.Equal(AccessRow.CaseColumns, rows[0].Keys);
        Assert.Equal(
            [
                ("2026-02-01 09:00:00", "HOST01", @"D:\Finance\Plan.xlsx"), ("2026-02-01 09:00:00", "HOST02", @"D:\Finance\Plan.xlsx"),
                ("2026-02-03 11:00:00", "HOST01", @"D:\Finance\Budget.xlsx"), ("2026-02-03 11:00:00", "HOST02", @"D:\Finance\Budget.xlsx")
            ],
            rows.Select(r => (r["Date/Time (UTC)"], r["System"], r["Path"])));
        Assert.All(rows, r => Assert.Equal(("alice", "Opened"), (r["User"], r["Activity"])));
    }

    [Fact]
    public void A_sid_on_the_list_finds_a_profile_folder_with_another_name()
    {
        using var dir = new TempDirectory();
        HostWithActivity(dir, "HOST01");
        CaseUsers.AddCompromised(dir.Path, new CompromisedUser("", BobSid));

        DataAccessReport.Build(dir.Path);

        var row = Assert.Single(ReadCsv(DataAccessReport.PathFor(dir.Path)));
        Assert.Equal(("bob.CORP", @"D:\Bob\Notes.txt"), (row["User"], row["Path"]));
    }

    [Fact]
    public void Activity_is_read_again_only_when_its_output_changed_and_an_empty_list_removes_the_report()
    {
        using var dir = new TempDirectory();
        var host = HostWithActivity(dir, "HOST01");
        CaseUsers.AddCompromised(dir.Path, new CompromisedUser("alice", ""));
        Assert.Single(DataAccessReport.Build(dir.Path));
        Assert.Empty(DataAccessReport.Build(dir.Path));

        File.SetLastWriteTimeUtc(Path.Combine(host, "LNKFiles", "alice", "alice_LECmd_Recent.csv"), DateTime.UtcNow.AddMinutes(5));
        Assert.Single(DataAccessReport.Build(dir.Path));

        CaseUsers.RemoveCompromised(dir.Path, new CompromisedUser("alice", ""));
        DataAccessReport.Build(dir.Path);
        Assert.False(File.Exists(DataAccessReport.PathFor(dir.Path)));
        Assert.True(File.Exists(CaseUsers.UserListPathFor(dir.Path)));
    }

    [Fact]
    public void Without_a_compromised_list_only_the_accounts_are_built()
    {
        using var dir = new TempDirectory();
        var host = HostWithActivity(dir, "HOST01");

        Assert.Empty(DataAccessReport.Build(dir.Path));

        Assert.False(File.Exists(Path.Combine(host, DataAccessReport.Folder, DataAccessReport.ActivityFileName)));
        Assert.Contains(CaseUsers.LoadUserList(dir.Path), a => a.Username == "alice" && a.Sid == AliceSid);
    }

    [Fact]
    public void The_summary_says_which_artefacts_each_host_had()
    {
        using var dir = new TempDirectory();
        HostWithActivity(dir, "HOST01");
        CaseUsers.AddCompromised(dir.Path, new CompromisedUser("alice", ""));
        DataAccessReport.Build(dir.Path);

        var summary = DataAccessReport.Summarise(dir.Path);

        Assert.Equal((2, 1, 1), (summary.Rows, summary.Users, summary.Hosts));
        Assert.Equal((1, 3), summary.Sources.Where(s => s.Source == DataAccessReport.LnkRecent).Select(s => (s.Hosts, s.Rows)).Single());
        Assert.Equal(0, summary.Sources.Single(s => s.Source == DataAccessReport.SecurityEvents).Hosts);
    }

    [Theory]
    [InlineData(@"Desktop\This PC\C:\Finance", @"C:\Finance")]
    [InlineData(@"\\FS01\HR\x.docx", @"\\FS01\HR\x.docx")]
    [InlineData("https://example.com/a", null)]
    [InlineData("ms-teams:quit", null)]
    [InlineData(@"Internet Folder\http://10.0.0.1/", null)]
    [InlineData("::{20D04FE0-3AEA-1069-A2D8-08002B30309D}", null)]
    [InlineData("  ", null)]
    public void Paths_start_at_the_drive_and_links_that_are_not_files_are_left_out(string text, string? expected) =>
        Assert.Equal(expected, DataAccessReport.CleanPath(text));
}
