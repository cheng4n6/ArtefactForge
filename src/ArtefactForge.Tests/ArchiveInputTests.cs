using System.IO.Compression;
using System.Text;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Zipped collections: recognising them from the entry list, extracting them with every entry
/// checked, and the engine's extract - parse - optionally delete cycle.
/// </summary>
public class ArchiveInputTests
{
    private static readonly string Cmd = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private static LayoutProfile CollectionFolder() => new()
    {
        Name = "Collection folder (drive-letter root)",
        Id = "collection-folder",
        Priority = 20,
        Platform = Platform.Windows,
        Detect = new LayoutDetectRules
        {
            Markers = [@"?\Windows\System32\config\SYSTEM", @"?\$MFT"],
            MatchMode = MarkerMatchMode.Any,
            DriveLetterFolder = true
        },
        Resolve = new LayoutResolveRules { RootOffset = "?" }
    };

    private static LayoutProfile[] Layouts() => [CollectionFolder()];

    /// <summary>Writes a zip holding the given entries; null content makes a directory entry.</summary>
    private static string Zip(string path, params (string Name, string? Content)[] entries)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (name, content) in entries)
        {
            var entry = zip.CreateEntry(name, CompressionLevel.NoCompression);
            if (content is null) continue;
            using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            writer.Write(content);
        }
        return path;
    }

    /// <summary>The shape a CyLR zip has: the drive folder at the root, named after nothing but the zip.</summary>
    private static string CylrZip(string path, params (string Name, string? Content)[] extra) =>
        Zip(path, [("C/Windows/System32/config/SYSTEM", "hive"), ("C/$MFT", "mft"), .. extra]);

    [Fact]
    public void A_cylr_shaped_zip_is_recognised_and_named_after_the_zip()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"));

        var (targets, reason) = EvidenceDiscovery.InspectArchive(zip, Layouts());

        var target = Assert.Single(targets);
        Assert.Null(reason);
        Assert.Equal("HOST01", target.CollectionName);
        Assert.Equal("C", target.DriveLetter);
        Assert.Equal(zip, target.ArchivePath);
        Assert.Equal("collection-folder", target.Layout.Id);
    }

    [Fact]
    public void A_velociraptor_zip_with_no_drive_says_what_is_missing()
    {
        using var dir = new TempDirectory();
        var zip = Zip(Path.Combine(dir.Path, "Collection-HOST01.zip"),
            ("client_info.json", "{}"),
            ("uploads/auto/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/Windows/x.txt", "x"));

        var (targets, reason) = EvidenceDiscovery.InspectArchive(zip, Layouts());

        Assert.Empty(targets);
        Assert.Contains("no Windows drive", reason);
    }

    [Fact]
    public void A_zip_without_a_collection_says_so()
    {
        using var dir = new TempDirectory();
        var zip = Zip(Path.Combine(dir.Path, "photos.zip"), ("holiday.jpg", "x"));

        var (targets, reason) = EvidenceDiscovery.InspectArchive(zip, Layouts());

        Assert.Empty(targets);
        Assert.Equal("no recognised collection inside", reason);
    }

    [Fact]
    public void A_file_that_is_not_a_zip_is_reported_not_thrown()
    {
        using var dir = new TempDirectory();
        var fake = Path.Combine(dir.Path, "broken.zip");
        File.WriteAllText(fake, "not a zip");

        var (targets, reason) = EvidenceDiscovery.InspectArchive(fake, Layouts());

        Assert.Empty(targets);
        Assert.StartsWith("could not be read as a zip", reason);
    }

    [Fact]
    public void Batch_takes_both_collection_folders_and_collection_zips()
    {
        using var dir = new TempDirectory();
        dir.File(@"batch\HOST01\C\Windows\System32\config\SYSTEM");
        CylrZip(Path.Combine(dir.Path, "batch", "HOST02.zip"));
        Zip(Path.Combine(dir.Path, "batch", "notes.zip"), ("readme.txt", "x"));

        var result = EvidenceDiscovery.Discover(Path.Combine(dir.Path, "batch"), batch: true, Layouts());

        Assert.Equal(["HOST01", "HOST02"], result.Targets.Select(t => t.CollectionName));
        Assert.False(result.Targets[0].IsArchive);
        Assert.True(result.Targets[1].IsArchive);
        Assert.Equal("notes.zip", Path.GetFileName(Assert.Single(result.Unmatched).Path));
    }

    [Fact]
    public void Batch_processes_the_zip_and_passes_over_its_extracted_copy()
    {
        using var dir = new TempDirectory();
        dir.File(@"batch\HOST01\C\Windows\System32\config\SYSTEM");
        CylrZip(Path.Combine(dir.Path, "batch", "HOST01.zip"));

        var result = EvidenceDiscovery.Discover(Path.Combine(dir.Path, "batch"), batch: true, Layouts());

        var target = Assert.Single(result.Targets);
        Assert.True(target.IsArchive);
        var skipped = Assert.Single(result.Unmatched);
        Assert.Equal("HOST01", Path.GetFileName(skipped.Path));
        Assert.Contains("extracted copy of HOST01.zip", skipped.Reason);
    }

    [Fact]
    public void A_folder_is_kept_when_the_zip_beside_it_is_not_a_collection()
    {
        using var dir = new TempDirectory();
        dir.File(@"batch\HOST01\C\Windows\System32\config\SYSTEM");
        Zip(Path.Combine(dir.Path, "batch", "HOST01.zip"), ("notes.txt", "x"));

        var result = EvidenceDiscovery.Discover(Path.Combine(dir.Path, "batch"), batch: true, Layouts());

        Assert.False(Assert.Single(result.Targets).IsArchive);
    }

    [Fact]
    public async Task Extraction_writes_every_entry_and_marks_the_folder_complete()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"), ("C/Users/alice/NTUSER.DAT", "user hive"));
        var to = Path.Combine(dir.Path, "out", "HOST01");

        var record = await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);

        Assert.Null(record.Error);
        Assert.Empty(record.Problems);
        Assert.Equal(3, record.Files);
        Assert.Equal("user hive", File.ReadAllText(Path.Combine(to, "C", "Users", "alice", "NTUSER.DAT")));
        Assert.True(File.Exists(Path.Combine(to, CollectionExtractor.MarkerName)));
        Assert.Equal(64, record.ArchiveSha256!.Length);
    }

    [Fact]
    public async Task A_zip_extracts_to_a_network_share()
    {
        // Free space was read with DriveInfo, which takes only a drive letter, so a share as the
        // output folder failed with "Object must be a root directory ("C:\") or a drive letter".
        // The admin share for the temp folder's drive stands in for a share on another machine.
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"), ("C/Users/alice/NTUSER.DAT", "user hive"));
        var local = Path.Combine(dir.Path, "out", "HOST01");
        var shareRoot = $@"\\localhost\{local[0]}$";
        if (!Directory.Exists(shareRoot + dir.Path[2..])) return; // no admin share on this machine
        var share = shareRoot + local[2..];

        var record = await CollectionExtractor.ExtractAsync(zip, share, null, null, CancellationToken.None);

        Assert.Null(record.Error);
        Assert.DoesNotContain(record.Notes, n => n.Contains("free space"));
        Assert.Equal("user hive", File.ReadAllText(Path.Combine(local, "C", "Users", "alice", "NTUSER.DAT")));
    }

    [Fact]
    public void Free_space_is_read_for_a_folder_that_does_not_exist_yet()
    {
        using var dir = new TempDirectory();

        Assert.True(DiskSpace.Available(Path.Combine(dir.Path, "not", "made", "yet")) > 0);
    }

    [Fact]
    public async Task A_complete_extraction_of_the_same_zip_is_reused()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"));
        var to = Path.Combine(dir.Path, "out", "HOST01");

        await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);
        var second = await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);

        Assert.True(second.Reused);
        Assert.Equal(2, second.Files);
    }

    [Fact]
    public async Task The_recorded_hash_is_the_sha256_of_the_whole_zip()
    {
        // The hash is read beside the extraction now, not before it; it must be the same value.
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"), ("C/Users/alice/NTUSER.DAT", new string('x', 3 << 20)));

        var record = await CollectionExtractor.ExtractAsync(
            zip, Path.Combine(dir.Path, "out", "HOST01"), null, null, CancellationToken.None);

        Assert.Null(record.Error);
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(zip))),
                     record.ArchiveSha256);
    }

    [Fact]
    public async Task A_zip_refused_before_extracting_still_has_its_hash_recorded()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"));
        dir.File(@"out\HOST01\case-notes.txt");

        var record = await CollectionExtractor.ExtractAsync(
            zip, Path.Combine(dir.Path, "out", "HOST01"), null, null, CancellationToken.None);

        Assert.NotNull(record.Error);
        Assert.Equal(64, record.ArchiveSha256!.Length);
    }

    [Fact]
    public async Task A_zip_replaced_since_its_extraction_is_extracted_again()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "HOST01.zip");
        var to = Path.Combine(dir.Path, "out", "HOST01");
        await CollectionExtractor.ExtractAsync(CylrZip(path), to, null, null, CancellationToken.None);

        File.Delete(path);
        CylrZip(path, ("C/Windows/new.txt", "added since"));
        var second = await CollectionExtractor.ExtractAsync(path, to, null, null, CancellationToken.None);

        Assert.False(second.Reused);
        Assert.Equal("added since", File.ReadAllText(Path.Combine(to, "C", "Windows", "new.txt")));
    }

    [Fact]
    public async Task A_partial_extraction_is_discarded_and_redone()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"));
        var to = Path.Combine(dir.Path, "out", "HOST01");

        await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);
        // What a crash mid-extract leaves: our marker, not marked complete, and a stray file.
        var marker = Path.Combine(to, CollectionExtractor.MarkerName);
        File.WriteAllText(marker, File.ReadAllText(marker).Replace("\"Completed\": true", "\"Completed\": false"));
        File.WriteAllText(Path.Combine(to, "leftover.tmp"), "x");

        var record = await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);

        Assert.False(record.Reused);
        Assert.False(File.Exists(Path.Combine(to, "leftover.tmp")));
    }

    [Fact]
    public async Task A_folder_not_made_by_ArtefactForge_is_never_overwritten()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"));
        var precious = dir.File(@"out\HOST01\case-notes.txt");

        var record = await CollectionExtractor.ExtractAsync(
            zip, Path.Combine(dir.Path, "out", "HOST01"), null, null, CancellationToken.None);

        Assert.Contains("was not created by ArtefactForge", record.Error);
        Assert.True(File.Exists(precious));
    }

    [Fact]
    public async Task An_entry_that_climbs_out_of_the_folder_is_refused_and_reported()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"), ("C/../../escaped.txt", "x"));
        var to = Path.Combine(dir.Path, "out", "HOST01");

        var record = await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);

        Assert.Contains(record.Problems, p => p.Contains("climbs out"));
        Assert.False(File.Exists(Path.Combine(dir.Path, "escaped.txt")));
        Assert.False(File.Exists(Path.Combine(dir.Path, "out", "escaped.txt")));
    }

    [Fact]
    public async Task A_corrupt_entry_is_removed_and_reported_rather_than_parsed()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"), ("C/Windows/evidence.txt", "ORIGINAL-CONTENT"));

        // Stored, not compressed, so the content sits in the file as written and can be damaged
        // without breaking the zip's structure - only the CRC can catch it.
        var bytes = File.ReadAllBytes(zip);
        var at = IndexOf(bytes, Encoding.ASCII.GetBytes("ORIGINAL-CONTENT"));
        bytes[at] = (byte)'X';
        File.WriteAllBytes(zip, bytes);

        var to = Path.Combine(dir.Path, "out", "HOST01");
        var record = await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);

        Assert.Contains(record.Problems, p => p.StartsWith("C/Windows/evidence.txt"));
        Assert.False(File.Exists(Path.Combine(to, "C", "Windows", "evidence.txt")));
        Assert.True(File.Exists(Path.Combine(to, "C", "$MFT")));
    }

    [Fact]
    public async Task A_zip_of_many_compressed_files_extracts_every_one_intact_in_parallel()
    {
        // Several readers inflate at once; every file must still match, byte for byte, and the
        // log must list them in the zip's order as a one-at-a-time run did.
        using var dir = new TempDirectory();
        var zipPath = Path.Combine(dir.Path, "HOST01.zip");
        var expected = new Dictionary<string, byte[]>();
        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var random = new Random(7);
            foreach (var name in new[] { "C/Windows/System32/config/SYSTEM", "C/$MFT" }
                         .Concat(Enumerable.Range(0, 20).Select(i => $"C/Logs/file{i:D2}.evtx")))
            {
                // Sizes from a few bytes to a few MB, half random (incompressible), half repetitive.
                var data = new byte[random.Next(1, 3) == 1 ? random.Next(1, 4096) : random.Next(1 << 20, 3 << 20)];
                if (expected.Count % 2 == 0) random.NextBytes(data);
                else for (var i = 0; i < data.Length; i++) data[i] = (byte)(i % 251);
                expected[name] = data;
                using var stream = zip.CreateEntry(name, CompressionLevel.Optimal).Open();
                stream.Write(data);
            }
        }
        var to = Path.Combine(dir.Path, "out", "HOST01");
        var log = Path.Combine(dir.Path, "extract.csv");
        long reported = 0;
        var gate = new object();

        var record = await CollectionExtractor.ExtractAsync(zipPath, to, log,
            new SyncProgress(p => { lock (gate) reported = Math.Max(reported, p.Done); }), CancellationToken.None);

        Assert.Null(record.Error);
        Assert.Empty(record.Problems);
        Assert.Equal(expected.Count, record.Files);
        Assert.Equal(expected.Values.Sum(v => (long)v.Length), record.Bytes);
        Assert.Equal(record.Bytes, reported);
        foreach (var (name, data) in expected)
            Assert.Equal(data, File.ReadAllBytes(Path.Combine(new[] { to }.Concat(name.Split('/')).ToArray())));
        Assert.Equal(expected.Keys, File.ReadLines(log).Skip(1).Select(l => l[..l.IndexOf(',')]));
    }

    [Fact]
    public async Task Of_two_entries_landing_on_one_file_the_first_in_the_zip_is_kept()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"),
            ("C/Windows/notes.txt", "first"), ("C/Windows/NOTES.TXT", "second"));
        var to = Path.Combine(dir.Path, "out", "HOST01");

        var record = await CollectionExtractor.ExtractAsync(zip, to, null, null, CancellationToken.None);

        Assert.Equal("first", File.ReadAllText(Path.Combine(to, "C", "Windows", "notes.txt")));
        Assert.Contains(record.Problems, p => p.StartsWith("C/Windows/NOTES.TXT") && p.Contains("already wrote"));
    }

    /// <summary>Reports on the calling thread, unlike Progress, so the test sees every report before the end.</summary>
    private sealed class SyncProgress(Action<(long Done, long Total)> report) : IProgress<(long Done, long Total)>
    {
        public void Report((long Done, long Total) value) => report(value);
    }

    [Fact]
    public async Task A_name_Windows_cannot_hold_is_made_safe_and_logged()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "HOST01.zip"), ("C/odd:name.txt", "x"));
        var to = Path.Combine(dir.Path, "out", "HOST01");
        var log = Path.Combine(dir.Path, "extract.csv");

        await CollectionExtractor.ExtractAsync(zip, to, log, null, CancellationToken.None);

        Assert.True(File.Exists(Path.Combine(to, "C", "odd_name.txt")));
        Assert.Contains(File.ReadLines(log), l => l.StartsWith("C/odd:name.txt") && l.Contains("renamed"));
    }

    // ------------------------------------------------------------------ engine

    private static ModuleDefinition Writer() => new()
    {
        Description = "Writer",
        Category = "Test",
        SourcePath = @"C:\modules\Writer.forge",
        Requires = [@"%root%\Windows\System32\config\SYSTEM"],
        Processors = [new ProcessorDefinition
        {
            Executable = Cmd,
            CommandLine = @"/c type ""%root%\Windows\System32\config\SYSTEM"" > ""%destinationDirectory%\result.txt"""
        }]
    };

    private static RunConfiguration Config(TempDirectory dir, string zip, bool cleanup) => new()
    {
        CaseName = "CASE",
        OutputRoot = dir.Dir("out"),
        ToolRoots = [dir.Path],
        Targets = EvidenceDiscovery.InspectArchive(zip, Layouts()).Targets,
        Modules = [Writer()],
        Layouts = Layouts(),
        CleanupExtracted = cleanup
    };

    [Fact]
    public async Task A_zip_is_extracted_parsed_and_kept_by_default()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"));

        var report = await new RunEngine().RunAsync(Config(dir, zip, cleanup: false));

        var extract = Assert.Single(report.Results, r => r.Module == "Extract");
        Assert.Equal(WorkStatus.Completed, extract.Status);
        var module = Assert.Single(report.Results, r => r.Module == "Writer");
        Assert.Equal(WorkStatus.Completed, module.Status);
        Assert.Equal("hive", File.ReadAllText(Path.Combine(report.CaseDirectory, "HOST01", "Test", "Writer_result.txt")).Trim());
        Assert.True(Directory.Exists(Path.Combine(report.CaseDirectory, "_Extracted", "HOST01", "C")));
        Assert.Equal(0, report.NeedsReview);
    }

    [Fact]
    public async Task Cleanup_deletes_the_extracted_data_once_the_modules_have_finished()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"));

        var report = await new RunEngine().RunAsync(Config(dir, zip, cleanup: true));

        Assert.Equal(WorkStatus.Completed, Assert.Single(report.Results, r => r.Module == "Writer").Status);
        Assert.False(Directory.Exists(Path.Combine(report.CaseDirectory, "_Extracted")));
        Assert.True(Assert.Single(report.Extractions).CleanedUp);
        // The output stays; only the working copy of the evidence goes.
        Assert.True(File.Exists(Path.Combine(report.CaseDirectory, "HOST01", "Test", "Writer_result.txt")));
    }

    [Fact]
    public void Deleting_one_extraction_leaves_the_folder_other_zips_extract_into()
    {
        // Two zips finishing at once both saw it empty and both removed it; the second was
        // reported as a failed cleanup. The engine removes it once every zip is done.
        using var dir = new TempDirectory();
        var extracted = Path.Combine(dir.Path, "_Extracted");
        Directory.CreateDirectory(Path.Combine(extracted, "HOST01"));

        Assert.Null(CollectionExtractor.Delete(Path.Combine(extracted, "HOST01")));

        Assert.False(Directory.Exists(Path.Combine(extracted, "HOST01")));
        Assert.True(Directory.Exists(extracted));
    }

    [Fact]
    public async Task Cleanup_keeps_the_data_when_extraction_reported_problems()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"), ("C/../../escaped.txt", "x"));

        var report = await new RunEngine().RunAsync(Config(dir, zip, cleanup: true));

        Assert.Equal(WorkStatus.CheckLog, Assert.Single(report.Results, r => r.Module == "Extract").Status);
        Assert.True(Directory.Exists(Path.Combine(report.CaseDirectory, "_Extracted", "HOST01")));
        Assert.False(Assert.Single(report.Extractions).CleanedUp);
    }

    [Fact]
    public async Task Several_zips_run_at_once_and_each_is_processed_and_cleaned_up()
    {
        using var dir = new TempDirectory();
        var zips = Enumerable.Range(1, 4)
            .Select(i => CylrZip(Path.Combine(dir.Path, "evidence", $"HOST0{i}.zip")))
            .ToList();
        var config = new RunConfiguration
        {
            CaseName = "CASE",
            OutputRoot = dir.Dir("out"),
            ToolRoots = [dir.Path],
            Targets = zips.SelectMany(z => EvidenceDiscovery.InspectArchive(z, Layouts()).Targets).ToList(),
            Modules = [Writer()],
            Layouts = Layouts(),
            CleanupExtracted = true,
            ArchivesAtOnce = 2
        };

        var report = await new RunEngine().RunAsync(config);

        Assert.Equal(4, report.Results.Count(r => r.Module == "Writer" && r.Status == WorkStatus.Completed));
        Assert.Equal(4, report.Extractions.Count(x => x.CleanedUp));
        Assert.False(Directory.Exists(Path.Combine(report.CaseDirectory, "_Extracted")));
        foreach (var host in new[] { "HOST01", "HOST02", "HOST03", "HOST04" })
            Assert.True(File.Exists(Path.Combine(report.CaseDirectory, host, "Test", "Writer_result.txt")));
    }

    [Fact]
    public async Task A_rerun_skips_a_finished_zip_without_extracting_it_again()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"));
        await new RunEngine().RunAsync(Config(dir, zip, cleanup: true));

        var engine = new RunEngine();
        var stages = new List<ExtractionStage>();
        engine.Extraction += e => stages.Add(e.Stage);
        var report = await engine.RunAsync(Config(dir, zip, cleanup: true));

        Assert.Equal([ExtractionStage.Skipped], stages);
        Assert.Empty(report.Extractions);
        Assert.Equal(WorkStatus.Skipped, Assert.Single(report.Results).Status);
    }

    private static ModuleDefinition Quiet() => new()
    {
        // The dirty-SRUM case: the tool runs, reads the evidence, and writes nothing.
        Description = "Quiet",
        Category = "Test",
        SourcePath = @"C:\modules\Quiet.forge",
        Processors = [new ProcessorDefinition { Executable = Cmd, CommandLine = "/c exit 0" }]
    };

    private static ModuleDefinition Broken() => new()
    {
        Description = "Broken",
        Category = "Test",
        SourcePath = @"C:\modules\Broken.forge",
        Processors = [new ProcessorDefinition { Executable = Cmd, CommandLine = "/c exit 3" }]
    };

    private static RunConfiguration Config(TempDirectory dir, string zip, bool cleanup, params ModuleDefinition[] modules) => new()
    {
        CaseName = "CASE",
        OutputRoot = Path.Combine(dir.Path, "out"),
        ToolRoots = [dir.Path],
        Targets = EvidenceDiscovery.InspectArchive(zip, Layouts()).Targets,
        Modules = modules,
        Layouts = Layouts(),
        CleanupExtracted = cleanup
    };

    [Fact]
    public async Task A_zip_whose_only_gap_is_no_output_is_not_extracted_again()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"));
        var first = await new RunEngine().RunAsync(Config(dir, zip, true, Writer(), Quiet()));
        Assert.Equal(WorkStatus.NoOutput, Assert.Single(first.Results, r => r.Module == "Quiet").Status);

        var second = await new RunEngine().RunAsync(Config(dir, zip, true, Writer(), Quiet()));

        Assert.Empty(second.Extractions);
        Assert.Equal(WorkStatus.Skipped, Assert.Single(second.Results).Status);
    }

    [Fact]
    public async Task A_zip_with_failed_work_reuses_its_extraction_and_retries_only_the_failure()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"));
        await new RunEngine().RunAsync(Config(dir, zip, false, Writer(), Broken()));

        var second = await new RunEngine().RunAsync(Config(dir, zip, false, Writer(), Broken()));

        Assert.True(Assert.Single(second.Extractions).Reused);
        Assert.Equal(WorkStatus.Skipped, Assert.Single(second.Results, r => r.Module == "Writer").Status);
        Assert.Equal(WorkStatus.Failed, Assert.Single(second.Results, r => r.Module == "Broken").Status);
    }

    [Fact]
    public async Task Cleanup_on_a_rerun_deletes_an_extraction_an_earlier_run_kept()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"));
        var first = await new RunEngine().RunAsync(Config(dir, zip, false, Writer()));
        var kept = Path.Combine(first.CaseDirectory, "_Extracted", "HOST01");
        Assert.True(Directory.Exists(kept));

        var second = await new RunEngine().RunAsync(Config(dir, zip, true, Writer()));

        var extract = Assert.Single(second.Results);
        Assert.Equal(WorkStatus.Skipped, extract.Status);
        Assert.Contains("deleted its extracted data", extract.Reason);
        Assert.False(Directory.Exists(kept));
    }

    [Fact]
    public async Task A_zip_that_cannot_be_extracted_fails_its_collection_without_stopping_the_run()
    {
        using var dir = new TempDirectory();
        var zip = CylrZip(Path.Combine(dir.Path, "evidence", "HOST01.zip"));
        var config = Config(dir, zip, cleanup: false);
        // Someone else's folder where the extraction should go.
        dir.File(@"out\CASE\_Extracted\HOST01\keep-me.txt");

        var report = await new RunEngine().RunAsync(config);

        var extract = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Failed, extract.Status);
        Assert.Contains("was not created by ArtefactForge", extract.Reason);
        Assert.False(report.Cancelled);
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle)) return i;
        throw new InvalidOperationException("content not found in the zip");
    }
}
