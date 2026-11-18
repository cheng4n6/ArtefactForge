using System.Text;
using ArtefactForge.Core.Windows;
using ArtefactForge.Lake;
using ArtefactForge.Lake.Queries;

namespace ArtefactForge.Tests;

/// <summary>
/// The lake's ransomware queries against the C# Ransomware step: both run on the same made-up
/// cases, and every file the lake writes under _Lake\results\Ransomware must be byte for byte the
/// file the step writes in the case. The cases are built to reach each rule and each line of
/// Detail: overrides (confirmed, overridden, none, swept, by machine name), the journal and the
/// MFT, notes saved from the collection, from the MFT or not at all, and hosts not checked.
/// </summary>
public class RansomwareLakeParityTests
{
    private const string MftHeader =
        "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,"
        + "ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,"
        + "Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,"
        + "LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,"
        + "ZoneIdContents,SourceFile,ResidentDataBase64,ResidentDataHex,ResidentDataASCII";

    private const string UsnHeader =
        "Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,UpdateSequenceNumber,"
        + "UpdateTimestamp,UpdateReasons,FileAttributes,OffsetToData,SourceFile";

    private static readonly string[] Types = ["docx", "xlsx", "pdf", "jpg", "png", "txt", "pptx", "csv"];
    private static readonly DateTime Start = new(2026, 9, 1, 2, 0, 0, DateTimeKind.Utc);

    private static string Time(DateTime t) => t.ToString("yyyy-MM-dd HH:mm:ss") + ".1234567";

    private sealed record FileRow(string Folder, string Name, long Size, DateTime Created, DateTime Changed,
                                  string Resident = "", bool InUse = true, bool Directory = false, string NameType = "Windows");

    private sealed record RenameRow(int Entry, string Folder, string OldName, string NewName, DateTime Time);

    private static string Quote(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";

    private static string MftLine(int entry, FileRow f, string sourceFile) =>
        $"{entry},1,{f.InUse},5,5,{Quote(f.Folder)},{Quote(f.Name)},{Path.GetExtension(f.Name)},{f.Size},1,,{f.Directory},False,False,"
        + $"False,False,False,Archive,{f.NameType},{Time(f.Created)},,{Time(f.Changed)},,{Time(f.Changed)},,{Time(f.Changed)},,"
        + $"0,0,256,,,,{Quote(sourceFile)},{f.Resident},,";

    private static void WriteHost(string caseDir, string collection, IEnumerable<FileRow>? files,
                                  IEnumerable<RenameRow>? renames = null, DateTime? journalStart = null,
                                  string? evidenceRoot = null, string? hostname = null)
    {
        var hostDir = Directory.CreateDirectory(Path.Combine(caseDir, collection)).FullName;
        if (hostname is not null)
        {
            Directory.CreateDirectory(Path.Combine(hostDir, "SystemInfo"));
            File.WriteAllLines(Path.Combine(hostDir, "SystemInfo", "SystemInfo.csv"),
                ["\"Category\",\"Item\",\"Value\",\"Source\"", $"\"Identity\",\"Hostname\",\"{hostname}\",\"SYSTEM\""],
                new UTF8Encoding(true));
        }
        if (files is null && renames is null)
        {
            // Some other output, so the folder is a host with nothing for the ransomware check.
            Directory.CreateDirectory(Path.Combine(hostDir, "EventLogs"));
            File.WriteAllLines(Path.Combine(hostDir, "EventLogs", "Other.csv"), ["A,B", "1,2"]);
            return;
        }
        var fileSystem = Directory.CreateDirectory(Path.Combine(hostDir, "FileSystem")).FullName;
        if (files is not null)
        {
            var source = Path.Combine(evidenceRoot ?? @"C:\evidence\C", "$MFT");
            var lines = new List<string> { MftHeader };
            var entry = 100;
            foreach (var f in files) lines.Add(MftLine(entry++, f, source));
            File.WriteAllLines(Path.Combine(fileSystem, "MFTECmd_MFT.csv"), lines, new UTF8Encoding(true));
        }
        if (renames is null) return;
        var usn = new List<string> { UsnHeader };
        var first = journalStart ?? Start.AddDays(-3);
        usn.Add($"pagefile.sys,.sys,1,1,5,5,.,1,{Time(first)},DataOverwrite,Archive,0,x");
        foreach (var r in renames)
        {
            usn.Add($"{Quote(r.OldName)},,{r.Entry},2,5,5,{Quote(r.Folder)},2,{Time(r.Time)},RenameOldName,Archive,0,x");
            usn.Add($"{Quote(r.NewName)},,{r.Entry},2,5,5,{Quote(r.Folder)},3,{Time(r.Time)},RenameNewName|Close,Archive,0,x");
        }
        File.WriteAllLines(Path.Combine(fileSystem, "MFTECmd_USNJournal.csv"), usn, new UTF8Encoding(true));
    }

    private static (List<FileRow> Files, List<RenameRow> Renames) Encrypt(
        string extension, int folders, int perFolder, DateTime start, string folderRoot = @".\Users\alice\Documents\Work",
        int entry = 5000)
    {
        var files = new List<FileRow>();
        var renames = new List<RenameRow>();
        var t = start;
        for (var f = 0; f < folders; f++)
        for (var i = 0; i < perFolder; i++)
        {
            var folder = $@"{folderRoot}{f:00}";
            var name = $"file{f:00}_{i:00}.{Types[(f + i) % Types.Length]}";
            files.Add(new FileRow(folder, name + extension, 40960, Start.AddYears(-1), t));
            renames.Add(new RenameRow(entry++, folder, name, name + extension, t));
            t = t.AddSeconds(3);
        }
        return (files, renames);
    }

    private static List<FileRow> Notes(string name, int folders, long size, DateTime at,
                                       string folderRoot = @".\Users\alice\Documents\Work") =>
        Enumerable.Range(0, folders)
                  .Select(f => new FileRow($@"{folderRoot}{f:00}", name, size, at.AddSeconds(f), at.AddSeconds(f)))
                  .ToList();

    /// <summary>What software does in bulk that must not read as ransomware.</summary>
    private static (List<FileRow> Files, List<RenameRow> Renames) Noise()
    {
        var files = new List<FileRow>();
        var renames = new List<RenameRow>();
        var entry = 1;
        for (var f = 0; f < 30; f++)
        for (var i = 0; i < 10; i++)
        {
            files.Add(new FileRow($@".\Users\alice\src\pkg{f}\types", $"mod{i}.d.ts", 900, Start, Start));
            files.Add(new FileRow($@".\Users\alice\tools\lang{f}", $"tool{i}.dll.mui", 900, Start, Start));
            renames.Add(new RenameRow(entry++, $@".\Users\alice\tools\v{f}", $"lib{i}.dll", $"lib{i}.dll.old", Start));
            var name = $"res{i}.{Types[(f + i) % Types.Length]}";
            files.Add(new FileRow($@".\Program Files (x86)\Vendor\App\{f}\Links", name + ".DATA", 900, Start, Start));
            renames.Add(new RenameRow(entry++, $@".\Users\alice\AppData\Local\App\cache{f}", name, name + ".bin", Start));
            // A browser's resilience copies: varied types and many folders, but over months.
            files.Add(new FileRow($@".\Users\alice\Pictures\set{f}", $"pic{i}.{Types[(f + i) % Types.Length]}.bak2",
                                  900, Start, Start.AddDays(-f * 7)));
        }
        for (var f = 0; f < 40; f++)
            files.Add(new FileRow($@".\Users\alice\envs\env{f}\Lib\site-packages\pkg", "readme.html", 3766, Start, Start));
        // Folders and 8.3 names are not files.
        files.Add(new FileRow(@".\Users\alice", "Documents.crypt", 0, Start, Start, Directory: true));
        files.Add(new FileRow(@".\Users\alice", "DOCUME~1.CRY", 10, Start, Start, NameType: "Dos"));
        return (files, renames);
    }

    private static void Overrides(string caseDir, params string[] rows) =>
        File.WriteAllLines(Path.Combine(caseDir, Ransomware.OverridesFileName),
                           ["Collection,Extension,NoteName,Comment", .. rows], new UTF8Encoding(true));

    /// <summary>Runs both, then compares every file. Returns the case's rows, for a check that the case reached what it meant to.</summary>
    private static List<RansomwareFinding> RunBoth(string caseDir)
    {
        Ransomware.Build(caseDir);
        var result = LakeBuilder.Build(caseDir, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30 });
        Assert.NotEqual(LakeOutcome.Failed, result.Outcome);
        Assert.DoesNotContain(result.Warnings, w => w.Contains("ransomware", StringComparison.OrdinalIgnoreCase));

        var lakeRoot = RansomwareResults.OutputRootFor(Path.Combine(caseDir, LakeNames.LakeFolder));
        var expected = FilesUnder(caseDir, caseDir);
        var actual = FilesUnder(lakeRoot, lakeRoot);
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
        return Ransomware.Load(caseDir);
    }

    /// <summary>The ransomware files under a case-shaped root, by path relative to it.</summary>
    private static Dictionary<string, string> FilesUnder(string root, string caseDir)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var caseFile = Path.Combine(root, Ransomware.FileName);
        if (File.Exists(caseFile)) files[Ransomware.FileName] = caseFile;
        foreach (var host in Directory.EnumerateDirectories(root).Where(d => !Path.GetFileName(d).StartsWith('_')))
        {
            var folder = Path.Combine(host, Ransomware.Folder);
            if (!Directory.Exists(folder)) continue;
            foreach (var file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
                files[Path.GetRelativePath(root, file)] = file;
        }
        return files;
    }

    [Fact]
    public void Overrides_sweeps_notes_and_differences_across_hosts_match_the_CSharp_step()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Path;

        // Confirmed by the analyst, with the note resident in the MFT.
        var (files1, renames1) = Encrypt(".crypt", 12, 10, Start);
        var bytes = Encoding.ASCII.GetBytes("Your files are locked\r\n");
        files1.AddRange(Notes("DECRYPT.txt", 12, bytes.Length, Start.AddMinutes(1))
                        .Select(n => n with { Resident = Convert.ToBase64String(bytes) }));
        WriteHost(caseDir, "HOST01", files1, renames1);

        // Too few to call alone: swept for, extension and note.
        var (files2, renames2) = Encrypt(".crypt", 1, 3, Start.AddMinutes(5));
        files2.Add(new FileRow(@".\Users\bob\Desktop", "DECRYPT.txt", bytes.Length, Start.AddMinutes(5), Start.AddMinutes(5)));
        WriteHost(caseDir, "HOST02", files2, renames2);

        // No journal, an extension in upper case, and a note read from the collection.
        var evidence = Path.Combine(caseDir, "_evidence", "HOST03");
        var (files3, _) = Encrypt(".LOCKED", 12, 10, Start.AddHours(1));
        var note = "All your files are encrypted.\r\n";
        files3.AddRange(Notes("README_FILES.hta", 12, note.Length, Start.AddHours(1)));
        var notePath = Path.Combine(evidence, @"Users\alice\Documents\Work00", "README_FILES.hta");
        Directory.CreateDirectory(Path.GetDirectoryName(notePath)!);
        File.WriteAllText(notePath, note, Encoding.ASCII);
        WriteHost(caseDir, "HOST03", files3, evidenceRoot: evidence);

        // Nothing but what software does.
        var (files4, renames4) = Noise();
        WriteHost(caseDir, "HOST04", files4, renames4);

        // No MFTECmd output.
        WriteHost(caseDir, "HOST05", null);

        // Settled as none by the machine's own name, though it has encrypted files.
        var (files6, renames6) = Encrypt(".crypt", 12, 10, Start, entry: 9000);
        WriteHost(caseDir, "HOST06", files6, renames6, hostname: "WS-ALPHA");

        Overrides(caseDir,
            "HOST01,crypt,DECRYPT.txt,checked by hand",
            "ws-alpha,none,-,settled",
            "*,.other,,sweep only",
            ",,,blank",
            "HOST01,,DECRYPT.txt,a later row for the same host");

        var rows = RunBoth(caseDir);

        Assert.Equal((".crypt", RansomwareFinding.Confirmed), (rows[0].Extension, rows[0].ExtensionBasis));
        Assert.NotEqual("", rows[0].NoteSha256);
        Assert.Equal((".crypt", RansomwareFinding.Swept), (rows[1].Extension, rows[1].ExtensionBasis));
        Assert.Equal(RansomwareFinding.Swept, rows[1].NoteBasis);
        Assert.Equal(".LOCKED", rows[2].Extension);
        Assert.NotEqual("", rows[2].NoteCopy);
        Assert.NotEqual("", rows[2].Differences);
        Assert.Equal(RansomwareFinding.NoneFound, rows[3].Status);
        Assert.Equal(RansomwareFinding.NotChecked, rows[4].Status);
        Assert.Equal(("WS-ALPHA", ""), (rows[5].Host, rows[5].Extension));
        Assert.Contains("no extension, as set in Ransomware-Overrides.csv", rows[5].Detail);
    }

    [Fact]
    public void Journal_gaps_other_candidates_note_only_hosts_and_unfound_overrides_match_the_CSharp_step()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Path;

        // The journal wrapped during encryption; the MFT still holds every file.
        var (files1, renames1) = Encrypt(".crypt", 12, 10, Start);
        WriteHost(caseDir, "HOST01", files1, renames1.Skip(60), journalStart: Start.AddSeconds(3 * 59));

        // Two extensions that both pass, one deleted file, and the journal holding far fewer than the MFT.
        var (files2, renames2) = Encrypt(".crypt", 12, 10, Start);
        var (more, moreRenames) = Encrypt(".enc", 12, 6, Start.AddHours(2), @".\Users\carol\Files", entry: 20000);
        files2.AddRange(more);
        files2.Add(new FileRow(@".\Users\alice\Documents\Work00", "gone.docx.crypt", 40960, Start, Start.AddSeconds(1), InUse: false));
        var (older, _) = Encrypt(".crypt", 12, 5, Start.AddDays(-1), @".\Users\dave\Old", entry: 30000);
        files2.AddRange(older);
        WriteHost(caseDir, "HOST02", files2, renames2.Concat(moreRenames));

        // A note and no extension: the times are the note's.
        WriteHost(caseDir, "HOST03", Notes("HOW_TO_RESTORE.txt", 15, 640, Start.AddMinutes(30)), []);

        // The analyst's extension, found nowhere, and no note.
        var (files4, renames4) = Encrypt(".crypt", 12, 10, Start, entry: 40000);
        WriteHost(caseDir, "HOST04", files4, renames4);

        // A note name confirmed elsewhere, here at another size and only twice.
        WriteHost(caseDir, "HOST05",
            [new FileRow(@".\Users\erin", "HOW_TO_RESTORE.txt", 5, Start, Start),
             new FileRow(@".\Users\erin\Desktop", "HOW_TO_RESTORE.txt", 3_000_000, Start, Start)]);

        Overrides(caseDir, "HOST04,.other,none,", "HOST03,,HOW_TO_RESTORE.txt,");

        var rows = RunBoth(caseDir);

        Assert.True(rows[0].StartIsEarliestSeen);
        Assert.Contains("other candidate extensions", rows[1].Detail);
        Assert.Contains("the MFT holds", rows[1].Detail);
        Assert.Contains("when the note's copies were created", rows[2].Detail);
        Assert.Equal((".other", RansomwareFinding.Override), (rows[3].Extension, rows[3].ExtensionBasis));
        Assert.Equal(RansomwareFinding.Swept, rows[4].NoteBasis);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Cases_with_no_overrides_or_only_their_header_match_the_CSharp_step(bool headerOnly)
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Path;
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        files.AddRange(Notes("DECRYPT.txt", 12, 5000, Start.AddMinutes(1)));   // not resident, not collected
        WriteHost(caseDir, "HOST01", files, renames);
        var (noise, noiseRenames) = Noise();
        WriteHost(caseDir, "HOST02", noise, noiseRenames);
        if (headerOnly) Ransomware.EnsureOverridesFile(caseDir);

        var rows = RunBoth(caseDir);

        Assert.Contains("pull a copy from", rows[0].Detail);
        Assert.Equal(RansomwareFinding.NoneFound, rows[1].Status);
    }

    [Fact]
    public void Overrides_that_are_not_an_overrides_file_stop_both_rather_than_being_ignored()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        WriteHost(dir.Path, "HOST01", files, renames);
        File.WriteAllLines(Path.Combine(dir.Path, Ransomware.OverridesFileName), ["Host,Ext", "HOST01,crypt"]);

        var csharp = Ransomware.Build(dir.Path);
        var lake = LakeBuilder.Build(dir.Path, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30 });

        Assert.Contains(csharp, r => r.Status == Core.WorkStatus.Failed);
        Assert.Equal(LakeOutcome.BuiltCheckLog, lake.Outcome);
        Assert.Contains(lake.Warnings, w => w.Contains("ransomware queries failed") && w.Contains(Ransomware.OverridesFileName));
        Assert.False(File.Exists(Path.Combine(RansomwareResults.OutputRootFor(Path.Combine(dir.Path, LakeNames.LakeFolder)),
                                              Ransomware.FileName)));
    }
}
