using System.Security.Cryptography;
using System.Text;
using ArtefactForge.Core;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Tests;

/// <summary>
/// Ransomware detection from MFTECmd output. Rows are written with MFTECmd's own headers, with
/// made-up users, folders and files.
/// </summary>
public class RansomwareTests
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
                                  string Resident = "", bool InUse = true);

    private sealed record RenameRow(int Entry, string Folder, string OldName, string NewName, DateTime Time);

    private static string MftLine(int entry, FileRow f, string sourceFile) =>
        $"{entry},1,{f.InUse},5,5,\"{f.Folder}\",\"{f.Name}\",{Path.GetExtension(f.Name)},{f.Size},1,,False,False,False,"
        + $"False,False,False,Archive,Windows,{Time(f.Created)},,{Time(f.Changed)},,{Time(f.Changed)},,{Time(f.Changed)},,"
        + $"0,0,256,,,,\"{sourceFile}\",{f.Resident},,";

    /// <summary>A host folder with MFTECmd output. Renames go in the journal, and their files in the MFT unless told otherwise.</summary>
    private static string WriteHost(TempDirectory dir, string collection, IEnumerable<FileRow> files,
                                    IEnumerable<RenameRow>? renames = null, DateTime? journalStart = null, string? evidenceRoot = null)
    {
        var fileSystem = dir.Dir(Path.Combine(collection, "FileSystem"));
        var source = Path.Combine(evidenceRoot ?? @"C:\evidence\C", "$MFT");
        var lines = new List<string> { MftHeader };
        var entry = 100;
        foreach (var f in files) lines.Add(MftLine(entry++, f, source));
        File.WriteAllLines(Path.Combine(fileSystem, "MFTECmd_MFT.csv"), lines, new UTF8Encoding(true));

        if (renames is null) return Path.Combine(dir.Path, collection);
        var usn = new List<string> { UsnHeader };
        var first = journalStart ?? Start.AddDays(-3);
        usn.Add($"pagefile.sys,.sys,1,1,5,5,.,1,{Time(first)},DataOverwrite,Archive,0,x");
        foreach (var r in renames)
        {
            usn.Add($"\"{r.OldName}\",,{r.Entry},2,5,5,\"{r.Folder}\",2,{Time(r.Time)},RenameOldName,Archive,0,x");
            usn.Add($"\"{r.NewName}\",,{r.Entry},2,5,5,\"{r.Folder}\",3,{Time(r.Time)},RenameNewName|Close,Archive,0,x");
        }
        File.WriteAllLines(Path.Combine(fileSystem, "MFTECmd_USNJournal.csv"), usn, new UTF8Encoding(true));
        return Path.Combine(dir.Path, collection);
    }

    /// <summary>Files encrypted in place: count of them across folders, one every few seconds from start.</summary>
    private static (List<FileRow> Files, List<RenameRow> Renames) Encrypt(
        string extension, int folders, int perFolder, DateTime start, string folderRoot = @".\Users\alice\Documents\Work")
    {
        var files = new List<FileRow>();
        var renames = new List<RenameRow>();
        var t = start;
        var entry = 5000;
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

    private static List<FileRow> Notes(string name, int folders, long size, DateTime at, string folderRoot = @".\Users\alice\Documents\Work") =>
        Enumerable.Range(0, folders)
                  .Select(f => new FileRow($@"{folderRoot}{f:00}", name, size, at.AddSeconds(f), at.AddSeconds(f)))
                  .ToList();

    private static RansomwareFinding Summary(string collectionDir) =>
        RansomwareFinding.Read(Path.Combine(collectionDir, Ransomware.Folder, Ransomware.SummaryFileName)).Single();

    [Fact]
    public void Extension_added_to_many_files_in_the_journal_is_found_with_its_start_finish_and_rate()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".lockbit", 12, 10, Start);
        var host = WriteHost(dir, "HOST01", files, renames);

        var result = Ransomware.BuildCollection(host, RansomwareHints.None);

        Assert.Equal(WorkStatus.Completed, result!.Status);
        var finding = Summary(host);
        Assert.Equal(RansomwareFinding.Found, finding.Status);
        Assert.Equal(".lockbit", finding.Extension);
        Assert.Equal(RansomwareFinding.Detected, finding.ExtensionBasis);
        Assert.Equal(Start, finding.StartUtc);
        Assert.Equal(Start.AddSeconds(3 * 119), finding.FinishUtc);
        Assert.False(finding.StartIsEarliestSeen);
        Assert.Equal(120, finding.FilesAffected);
        Assert.Equal(20, finding.PeakPerMinute);
        Assert.Equal("USN", finding.Source);

        var evidence = RansomwareEvidence.Read(Path.Combine(host, Ransomware.Folder, Ransomware.EvidenceFileName));
        Assert.Equal(120, evidence.Count(e => e.Kind == RansomwareEvidence.Renamed));
        Assert.Contains(evidence, e => e is { Kind: RansomwareEvidence.Renamed, PreviousName: "file00_00.docx", Name: "file00_00.docx.lockbit" });
    }

    [Fact]
    public void Second_extensions_that_software_adds_in_bulk_are_not_reported()
    {
        using var dir = new TempDirectory();
        var files = new List<FileRow>();
        var renames = new List<RenameRow>();
        var entry = 1;
        for (var f = 0; f < 30; f++)
        for (var i = 0; i < 10; i++)
        {
            // One type behind the added extension, however many folders: .d.ts, .dll.mui, .dll.old.
            files.Add(new FileRow($@".\Users\alice\src\pkg{f}\types", $"mod{i}.d.ts", 900, Start, Start));
            files.Add(new FileRow($@".\Users\alice\tools\lang{f}", $"tool{i}.dll.mui", 900, Start, Start));
            renames.Add(new RenameRow(entry++, $@".\Users\alice\tools\v{f}", $"lib{i}.dll", $"lib{i}.dll.old", Start));
            // Varied types, but where software keeps its own files.
            var name = $"res{i}.{Types[(f + i) % Types.Length]}";
            files.Add(new FileRow($@".\Program Files (x86)\Vendor\App\{f}\Links", name + ".DATA", 900, Start, Start));
            renames.Add(new RenameRow(entry++, $@".\Users\alice\AppData\Local\App\cache{f}", name, name + ".bin", Start));
        }
        // A package's read-me, the same size in many folders of one name.
        for (var f = 0; f < 40; f++)
            files.Add(new FileRow($@".\Users\alice\envs\env{f}\Lib\site-packages\pkg", "readme.html", 3766, Start, Start));
        var host = WriteHost(dir, "HOST01", files, renames);

        Ransomware.BuildCollection(host, RansomwareHints.None);

        var finding = Summary(host);
        Assert.Equal(RansomwareFinding.NoneFound, finding.Status);
        Assert.Equal("", finding.Extension);
        Assert.Equal("", finding.NoteName);
    }

    [Fact]
    public void Ransom_note_beside_the_encrypted_files_is_found_and_a_copy_saved_with_its_hash()
    {
        using var dir = new TempDirectory();
        var evidenceRoot = dir.Dir("evidence");
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        var text = "Your files are encrypted. Contact us.\r\n";
        var size = Encoding.ASCII.GetByteCount(text);
        files.AddRange(Notes("README_FILES.hta", 12, size, Start.AddMinutes(1)));
        // The first copy is in the collection, as a collector picked it up.
        var notePath = Path.Combine(evidenceRoot, @"Users\alice\Documents\Work00", "README_FILES.hta");
        Directory.CreateDirectory(Path.GetDirectoryName(notePath)!);
        File.WriteAllText(notePath, text, Encoding.ASCII);
        var host = WriteHost(dir, "HOST01", files, renames, evidenceRoot: evidenceRoot);

        Ransomware.BuildCollection(host, RansomwareHints.None);

        var finding = Summary(host);
        Assert.Equal("README_FILES.hta", finding.NoteName);
        Assert.Equal(size, finding.NoteSize);
        Assert.Equal(12, finding.NoteFolders);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(text))), finding.NoteSha256);
        // Saved as text, so opening it from the case cannot run it.
        Assert.Equal(Path.Combine("HOST01", Ransomware.Folder, Ransomware.NoteFolder, "README_FILES.hta.txt"), finding.NoteCopy);
        Assert.Equal(text, File.ReadAllText(Path.Combine(dir.Path, finding.NoteCopy)));
        Assert.Equal(text, File.ReadAllText(notePath));   // the evidence is only read
    }

    [Fact]
    public void Note_missing_from_the_collection_is_read_from_the_MFT_when_resident_or_listed_to_pull()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        var bytes = Encoding.ASCII.GetBytes("Your files are locked\r\n");
        files.AddRange(Notes("DECRYPT.txt", 12, bytes.Length, Start.AddMinutes(1))
                       .Select(n => n with { Resident = Convert.ToBase64String(bytes) }));
        var resident = WriteHost(dir, "HOST01", files, renames);
        var (files2, renames2) = Encrypt(".crypt", 12, 10, Start);
        files2.AddRange(Notes("DECRYPT.txt", 12, 5000, Start.AddMinutes(1)));
        var missing = WriteHost(dir, "HOST02", files2, renames2);

        Ransomware.BuildCollection(resident, RansomwareHints.None);
        Ransomware.BuildCollection(missing, RansomwareHints.None);

        Assert.Equal("Your files are locked\r\n", File.ReadAllText(Path.Combine(dir.Path, Summary(resident).NoteCopy)));
        var notCopied = Summary(missing);
        Assert.Equal("", notCopied.NoteCopy);
        Assert.Contains(@"pull a copy from .\Users\alice\Documents\Work00\DECRYPT.txt", notCopied.Detail);
    }

    [Fact]
    public void Without_the_journal_the_MFT_finds_the_extension_and_the_start_is_only_the_earliest_seen()
    {
        using var dir = new TempDirectory();
        var (files, _) = Encrypt(".crypt", 12, 10, Start);
        var host = WriteHost(dir, "HOST01", files);

        Ransomware.BuildCollection(host, RansomwareHints.None);

        var finding = Summary(host);
        Assert.Equal(".crypt", finding.Extension);
        Assert.Equal("MFT", finding.Source);
        Assert.True(finding.StartIsEarliestSeen);
        Assert.Equal(Start, finding.StartUtc);
        Assert.Contains("no USN journal output", finding.Detail);
    }

    [Fact]
    public void A_journal_that_starts_during_encryption_marks_the_start_as_earliest_seen()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        // The journal wrapped: only the second half of the renames are still in it.
        var host = WriteHost(dir, "HOST01", files, renames.Skip(60), journalStart: Start.AddSeconds(3 * 59));

        Ransomware.BuildCollection(host, RansomwareHints.None);

        var finding = Summary(host);
        Assert.True(finding.StartIsEarliestSeen);
        Assert.Equal(Start, finding.StartUtc);   // from the MFT, which still holds every file
        Assert.Equal(120, finding.FilesAffected);
        Assert.Equal("USN and MFT", finding.Source);
    }

    [Fact]
    public void Confirmed_extension_and_note_are_swept_across_the_other_hosts()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        files.AddRange(Notes("DECRYPT.txt", 12, 300, Start.AddMinutes(1)));
        WriteHost(dir, "HOST01", files, renames);
        // Too few to call on its own: caught as it started.
        var (few, fewRenames) = Encrypt(".crypt", 1, 3, Start.AddMinutes(5));
        few.Add(new FileRow(@".\Users\bob\Desktop", "DECRYPT.txt", 300, Start.AddMinutes(5), Start.AddMinutes(5)));
        var second = WriteHost(dir, "HOST02", few, fewRenames);
        File.WriteAllLines(Ransomware.OverridesPathFor(dir.Path),
            ["Collection,Extension,NoteName,Comment", "HOST01,crypt,DECRYPT.txt,checked by hand"]);

        Ransomware.Build(dir.Path);

        var rows = Ransomware.Load(dir.Path);
        var first = rows.Single(r => r.Collection == "HOST01");
        Assert.Equal(RansomwareFinding.Confirmed, first.ExtensionBasis);
        Assert.Equal(RansomwareFinding.Confirmed, first.NoteBasis);
        var swept = rows.Single(r => r.Collection == "HOST02");
        Assert.Equal(RansomwareFinding.Found, swept.Status);
        Assert.Equal((".crypt", RansomwareFinding.Swept), (swept.Extension, swept.ExtensionBasis));
        Assert.Equal(("DECRYPT.txt", RansomwareFinding.Swept), (swept.NoteName, swept.NoteBasis));
        Assert.Equal(3, swept.FilesAffected);
        Assert.Equal(Start.AddMinutes(5), Summary(second).StartUtc);
    }

    [Fact]
    public void The_analysts_value_overrides_what_was_detected_and_none_clears_it()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        files.AddRange(Notes("DECRYPT.txt", 12, 300, Start.AddMinutes(1)));
        var host = WriteHost(dir, "HOST01", files, renames);

        Ransomware.BuildCollection(host, new RansomwareHints(".other", "", new HashSet<string>(), new HashSet<string>()));

        var finding = Summary(host);
        Assert.Equal((".other", RansomwareFinding.Override), (finding.Extension, finding.ExtensionBasis));
        Assert.Equal("", finding.NoteName);
        Assert.Contains("no ransom note, as set in Ransomware-Overrides.csv", finding.Detail);
    }

    [Fact]
    public void Overrides_are_never_written_over_and_their_header_is_made_only_when_missing()
    {
        using var dir = new TempDirectory();
        var path = Ransomware.EnsureOverridesFile(dir.Path);
        Assert.Equal("Collection,Extension,NoteName,Comment",
                     File.ReadAllLines(path)[0].Replace("\"", ""));

        File.WriteAllText(path, "Collection,Extension,NoteName,Comment\r\nHOST01,.crypt,,mine\r\n");
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        WriteHost(dir, "HOST01", files, renames);
        Ransomware.EnsureOverridesFile(dir.Path);
        Ransomware.Build(dir.Path);

        Assert.Equal("Collection,Extension,NoteName,Comment\r\nHOST01,.crypt,,mine\r\n", File.ReadAllText(path));
    }

    [Fact]
    public void Unreadable_overrides_stop_the_build_rather_than_being_ignored()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        WriteHost(dir, "HOST01", files, renames);
        File.WriteAllText(Ransomware.OverridesPathFor(dir.Path), "Host;Ext\r\nHOST01;.crypt\r\n");

        var results = Ransomware.Build(dir.Path);

        var failed = Assert.Single(results);
        Assert.Equal(WorkStatus.Failed, failed.Status);
        Assert.Contains(Ransomware.OverridesFileName, failed.Reason);
        Assert.False(File.Exists(Ransomware.PathFor(dir.Path)));
    }

    [Fact]
    public void Only_a_host_whose_input_or_overrides_changed_is_built_again()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        WriteHost(dir, "HOST01", files, renames);
        var (files2, renames2) = Encrypt(".crypt", 12, 10, Start);
        WriteHost(dir, "HOST02", files2, renames2);

        Assert.Equal(2, Ransomware.Build(dir.Path).Count);
        Assert.Empty(Ransomware.Build(dir.Path));

        // Says only that HOST01 has no note: nothing to sweep for, so HOST02 is left as it is.
        File.WriteAllLines(Ransomware.OverridesPathFor(dir.Path), ["Collection,Extension,NoteName,Comment", "HOST01,,none,"]);
        Assert.Equal("HOST01", Assert.Single(Ransomware.Build(dir.Path)).Collection);

        // A confirmed extension is swept for on every host, so every host is checked for it.
        File.WriteAllLines(Ransomware.OverridesPathFor(dir.Path), ["Collection,Extension,NoteName,Comment", "HOST01,.crypt,none,"]);
        Assert.Equal(2, Ransomware.Build(dir.Path).Count);
        Assert.Empty(Ransomware.Build(dir.Path));
    }

    [Fact]
    public void Hosts_that_differ_from_the_rest_of_the_case_are_flagged()
    {
        using var dir = new TempDirectory();
        foreach (var (host, ext) in new[] { ("HOST01", ".crypt"), ("HOST02", ".crypt"), ("HOST03", ".other") })
        {
            var (files, renames) = Encrypt(ext, 12, 10, Start);
            WriteHost(dir, host, files, renames);
        }
        WriteHost(dir, "HOST04", [new FileRow(@".\Users\carol\Documents", "notes.docx", 100, Start, Start)]);
        dir.Dir(Path.Combine("LINUX01", "Linux"));

        Ransomware.Build(dir.Path);

        var rows = Ransomware.Load(dir.Path).ToDictionary(r => r.Collection);
        Assert.Equal("", rows["HOST01"].Differences);
        Assert.Equal("extension .other differs from .crypt on 2 hosts", rows["HOST03"].Differences);
        Assert.Equal("nothing found here, unlike 3 other hosts", rows["HOST04"].Differences);
        Assert.Equal(RansomwareFinding.NotChecked, rows["LINUX01"].Status);
    }

    [Fact]
    public void The_case_report_shows_each_hosts_window_and_raises_ransomware_as_critical()
    {
        using var dir = new TempDirectory();
        var (files, renames) = Encrypt(".crypt", 12, 10, Start);
        WriteHost(dir, "HOST01", files, renames);
        WriteHost(dir, "HOST02", [new FileRow(@".\Users\carol\Documents", "notes.docx", 100, Start, Start)]);
        Ransomware.Build(dir.Path);

        var result = Core.Report.CaseReport.Rebuild(dir.Path);

        Assert.True(result.Written, result.Message);
        var html = File.ReadAllText(result.Path!);
        Assert.Contains("id=\"ransomware\"", html);
        Assert.Contains("Ransomware on 1 of 2 hosts checked", html);
        Assert.Contains("2026-09-01 02:00:00", html);
        Assert.Contains("nothing found here, unlike 1 other host", html);
    }

    [Fact]
    public void A_case_with_no_MFT_output_gets_no_ransomware_file()
    {
        using var dir = new TempDirectory();
        dir.Dir(Path.Combine("HOST01", "EventLogs"));

        Assert.Empty(Ransomware.Build(dir.Path));
        Assert.False(File.Exists(Ransomware.PathFor(dir.Path)));
    }
}
