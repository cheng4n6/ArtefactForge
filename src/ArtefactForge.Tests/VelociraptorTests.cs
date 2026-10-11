using System.IO.Compression;
using System.Text;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Velociraptor offline collections, converted on extraction into the drive-letter-folder shape.
/// The zips here are synthetic but follow the layout of a real v0.77.3 collector: accessor roots,
/// percent-encoded components, ':' stream names and sparse files stored with an .idx.
/// </summary>
public class VelociraptorTests
{
    private const string Auto = "uploads/auto/C%3A/";
    private const string Ntfs = "uploads/ntfs/%5C%5C.%5CC%3A/";

    private static LayoutProfile[] Layouts() =>
    [
        new()
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
        }
    ];

    private const string Complete =
        """{"state":2,"total_expected_uploaded_bytes":100,"total_uploaded_bytes":100}""";

    private static string Zip(string path, params (string Name, byte[] Content)[] entries)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (name, content) in entries)
        {
            using var stream = zip.CreateEntry(name, CompressionLevel.Fastest).Open();
            stream.Write(content);
        }
        return path;
    }

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>A minimal collection: metadata, a hive through auto and $MFT through ntfs.</summary>
    private static (string, byte[])[] Basics(string context = Complete) =>
    [
        ("client_info.json", Text("""{"Hostname":"HOST01","OS":"windows"}""")),
        ("collection_context.json", Text(context)),
        ("log.json", Text("""{"level":"DEFAULT","message":"Collecting file"}""" + "\n")),
        (Auto + "Windows/System32/config/SYSTEM", Text("hive")),
        (Ntfs + "$MFT", Text("mft"))
    ];

    private static async Task<(ExtractionRecord Record, string Root)> Extract(TempDirectory dir, params (string, byte[])[] extra)
    {
        var zip = Zip(Path.Combine(dir.Path, "Collection-HOST01.zip"), [.. Basics(), .. extra]);
        var root = Path.Combine(dir.Path, "out", "HOST01");
        var record = await CollectionExtractor.ExtractAsync(zip, root, Path.Combine(dir.Path, "extract.csv"), null, CancellationToken.None);
        Assert.Null(record.Error);
        return (record, root);
    }

    [Theory]
    [InlineData("C%3A", "C:")]
    [InlineData("Budget%252C+2026.lnk", "Budget%2C+2026.lnk")]
    [InlineData("caf%C3%A9.txt", "café.txt")]
    [InlineData("no-escapes", "no-escapes")]
    [InlineData("100%", "100%")]
    public void Each_component_is_decoded_exactly_once(string stored, string expected) =>
        Assert.Equal(expected, VelociraptorCollection.Decode(stored));

    [Theory]
    [InlineData(Auto + "Users/alice/NTUSER.DAT", @"C\Users\alice\NTUSER.DAT")]
    [InlineData(Ntfs + "$MFT", @"C\$MFT")]
    [InlineData(Ntfs + "$Extend/$UsnJrnl%3A$J", @"C\$Extend\$J")]
    [InlineData(Ntfs + "$Secure%3A$SDS", @"C\$Secure:$SDS")]
    [InlineData("uploads/auto/%5C%5C.%5CC%3A/Windows/x.etl", @"C\Windows\x.etl")]
    [InlineData("uploads/auto/D%3A/data.txt", @"D\data.txt")]
    [InlineData("client_info.json", @"_Velociraptor\client_info.json")]
    public void Every_accessor_root_maps_onto_its_drive_letter(string entry, string expected) =>
        Assert.Equal(expected, VelociraptorCollection.MapEntry(entry, out _));

    [Fact]
    public void A_shadow_copy_is_left_out_with_a_reason()
    {
        var mapped = VelociraptorCollection.MapEntry(
            "uploads/ntfs/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy3/Windows/x", out var reason);

        Assert.Null(mapped);
        Assert.Contains("shadow copies", reason);
    }

    [Fact]
    public void A_velociraptor_zip_is_recognised_and_named_after_the_host()
    {
        using var dir = new TempDirectory();
        var zip = Zip(Path.Combine(dir.Path, "Collection-HOST01-2026-10-10T10_07_46Z.zip"), Basics());

        var (targets, reason) = EvidenceDiscovery.InspectArchive(zip, Layouts());

        var target = Assert.Single(targets);
        Assert.Null(reason);
        Assert.Equal("HOST01", target.CollectionName);
        Assert.Equal("C", target.DriveLetter);
    }

    [Fact]
    public async Task Accessor_roots_are_merged_into_one_drive_folder()
    {
        using var dir = new TempDirectory();
        var (record, root) = await Extract(dir);

        Assert.Empty(record.Problems);
        Assert.Equal("hive", File.ReadAllText(Path.Combine(root, "C", "Windows", "System32", "config", "SYSTEM")));
        Assert.Equal("mft", File.ReadAllText(Path.Combine(root, "C", "$MFT")));
        Assert.True(File.Exists(Path.Combine(root, VelociraptorCollection.MetadataFolder, "client_info.json")));
        Assert.Equal(["C", VelociraptorCollection.MetadataFolder],
                     Directory.GetDirectories(root).Select(Path.GetFileName).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task A_literal_percent_in_a_name_survives()
    {
        using var dir = new TempDirectory();
        var (_, root) = await Extract(dir, (Auto + "Users/alice/Recent/Budget%252C+2026.lnk", Text("lnk")));

        Assert.True(File.Exists(Path.Combine(root, "C", "Users", "alice", "Recent", "Budget%2C+2026.lnk")));
    }

    [Fact]
    public async Task The_usn_journal_lands_where_the_module_looks_for_it()
    {
        using var dir = new TempDirectory();
        var (_, root) = await Extract(dir, (Ntfs + "$Extend/$UsnJrnl%3A$J", Text("usn")));

        Assert.Equal("usn", File.ReadAllText(Path.Combine(root, "C", "$Extend", "$J")));
        // Never as an alternate data stream on a file called $UsnJrnl.
        Assert.False(File.Exists(Path.Combine(root, "C", "$Extend", "$UsnJrnl")));
    }

    [Fact]
    public async Task A_sparse_file_is_written_back_at_its_original_size_and_offsets()
    {
        // Original 40 bytes: 8 zero, "AAAA", 8 zero, "BBBB", 16 zero. Stored: "AAAABBBB".
        const string index = """
            {"ranges":[
              {"length":8},
              {"original_offset":8,"file_length":4,"length":4},
              {"original_offset":12,"length":8},
              {"original_offset":20,"file_offset":4,"file_length":4,"length":4},
              {"original_offset":24,"length":16}]}
            """;
        using var dir = new TempDirectory();
        var (record, root) = await Extract(dir,
            (Auto + "Users/alice/NTUSER.DAT", Text("AAAABBBB")),
            (Auto + "Users/alice/NTUSER.DAT.idx", Text(index)));

        Assert.Empty(record.Problems);
        var bytes = File.ReadAllBytes(Path.Combine(root, "C", "Users", "alice", "NTUSER.DAT"));
        Assert.Equal(40, bytes.Length);
        Assert.Equal("AAAA", Encoding.ASCII.GetString(bytes, 8, 4));
        Assert.Equal("BBBB", Encoding.ASCII.GetString(bytes, 20, 4));
        Assert.All(bytes[..8].Concat(bytes[12..20]).Concat(bytes[24..]), b => Assert.Equal(0, b));
        Assert.False(File.Exists(Path.Combine(root, "C", "Users", "alice", "NTUSER.DAT.idx")));
    }

    [Fact]
    public async Task The_usn_journal_keeps_its_data_without_expanding_the_hole()
    {
        const string index = """{"ranges":[{"length":1000000000000},{"original_offset":1000000000000,"file_length":3,"length":3}]}""";
        using var dir = new TempDirectory();
        var (record, root) = await Extract(dir,
            (Ntfs + "$Extend/$UsnJrnl%3A$J", Text("usn")),
            (Ntfs + "$Extend/$UsnJrnl%3A$J.idx", Text(index)));

        Assert.Equal(3, new FileInfo(Path.Combine(root, "C", "$Extend", "$J")).Length);
        Assert.Contains(record.Notes, n => n.Contains("$J") && n.Contains("not expanded"));
    }

    [Fact]
    public async Task A_sparse_index_that_disagrees_with_the_data_is_reported()
    {
        const string index = """{"ranges":[{"file_length":99,"length":99}]}""";
        using var dir = new TempDirectory();
        var (record, root) = await Extract(dir,
            (Auto + "Windows/System32/config/SOFTWARE", Text("short")),
            (Auto + "Windows/System32/config/SOFTWARE.idx", Text(index)));

        Assert.Contains(record.Problems, p => p.Contains("SOFTWARE") && p.Contains("sparse index"));
        Assert.False(File.Exists(Path.Combine(root, "C", "Windows", "System32", "config", "SOFTWARE")));
    }

    [Fact]
    public async Task The_raw_ntfs_copy_wins_when_two_accessors_upload_one_file()
    {
        using var dir = new TempDirectory();
        var (record, root) = await Extract(dir,
            (Auto + "Windows/System32/config/SAM", Text("auto copy")),
            (Ntfs + "Windows/System32/config/SAM", Text("raw copy")));

        Assert.Equal("raw copy", File.ReadAllText(Path.Combine(root, "C", "Windows", "System32", "config", "SAM")));
        Assert.Contains(record.Problems, p => p.StartsWith(Auto + "Windows/System32/config/SAM"));
    }

    [Fact]
    public async Task An_unfinished_collection_is_flagged_for_review()
    {
        using var dir = new TempDirectory();
        var zip = Zip(Path.Combine(dir.Path, "evidence", "Collection-HOST01.zip"),
            Basics("""{"state":2,"total_expected_uploaded_bytes":3000000000,"total_uploaded_bytes":1000000000}"""));
        var config = new RunConfiguration
        {
            CaseName = "CASE",
            OutputRoot = dir.Dir("out"),
            ToolRoots = [dir.Path],
            Targets = EvidenceDiscovery.InspectArchive(zip, Layouts()).Targets,
            Modules = [],
            Layouts = Layouts()
        };

        var report = await new RunEngine().RunAsync(config);

        var extract = Assert.Single(report.Results, r => r.Module == "Extract");
        Assert.Equal(WorkStatus.CheckLog, extract.Status);
        Assert.StartsWith(CollectionExtractor.IncompletePrefix + "the collector uploaded", extract.Reason);
    }

    // ---------------------------------------------- a collection already unzipped

    /// <summary>What Explorer leaves after unzipping a collector's zip: the same encoded names, as files.</summary>
    private static string Unzipped(string folder, params (string Name, byte[] Content)[] entries)
    {
        foreach (var (name, content) in entries)
        {
            var path = Path.Combine([folder, .. name.Split('/')]);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, content);
        }
        return folder;
    }

    private static Dictionary<string, string> Snapshot(string folder) =>
        Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories).ToDictionary(
            f => f,
            f => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(f)))
                 + File.GetLastWriteTimeUtc(f).Ticks);

    [Fact]
    public void An_unzipped_collection_is_recognised_as_one_to_convert()
    {
        using var dir = new TempDirectory();
        var folder = Unzipped(Path.Combine(dir.Path, "Collection-HOST01"), Basics());

        var result = EvidenceDiscovery.Discover(folder, batch: false, Layouts());

        var target = Assert.Single(result.Targets);
        Assert.Equal("HOST01", target.CollectionName);
        Assert.Equal(folder, target.ArchivePath);
        Assert.Contains("to convert", target.Kind);
    }

    [Fact]
    public void Batch_takes_an_unzipped_collection_beside_zips()
    {
        using var dir = new TempDirectory();
        Unzipped(Path.Combine(dir.Path, "batch", "Collection-HOST01"), Basics());
        Zip(Path.Combine(dir.Path, "batch", "Collection-HOST02.zip"),
            [.. Basics().Select(e => e.Item1 == "client_info.json" ? (e.Item1, Text("""{"Hostname":"HOST02"}""")) : e)]);

        var result = EvidenceDiscovery.Discover(Path.Combine(dir.Path, "batch"), batch: true, Layouts());

        Assert.Equal(["HOST01", "HOST02"], result.Targets.Select(t => t.CollectionName));
        Assert.All(result.Targets, t => Assert.True(t.IsArchive));
        Assert.Empty(result.Unmatched);
    }

    [Fact]
    public async Task An_unzipped_collection_is_converted_like_the_zip_and_left_untouched()
    {
        const string index = """{"ranges":[{"length":4},{"original_offset":4,"file_length":4,"length":4}]}""";
        using var dir = new TempDirectory();
        var folder = Unzipped(Path.Combine(dir.Path, "evidence", "Collection-HOST01"),
            [.. Basics(),
             (Ntfs + "$Extend/$UsnJrnl%3A$J", Text("usn")),
             (Auto + "Users/alice/NTUSER.DAT", Text("DATA")),
             (Auto + "Users/alice/NTUSER.DAT.idx", Text(index))]);
        var before = Snapshot(folder);
        var root = Path.Combine(dir.Path, "out", "HOST01");

        var record = await CollectionExtractor.ExtractAsync(folder, root, null, null, CancellationToken.None);

        Assert.Null(record.Error);
        Assert.Empty(record.Problems);
        Assert.Null(record.ArchiveSha256);
        Assert.Equal("hive", File.ReadAllText(Path.Combine(root, "C", "Windows", "System32", "config", "SYSTEM")));
        Assert.Equal("usn", File.ReadAllText(Path.Combine(root, "C", "$Extend", "$J")));
        Assert.Equal("\0\0\0\0DATA", File.ReadAllText(Path.Combine(root, "C", "Users", "alice", "NTUSER.DAT")));
        Assert.Equal(before, Snapshot(folder));
    }

    [Fact]
    public async Task A_conversion_is_never_written_inside_the_collection_it_reads()
    {
        using var dir = new TempDirectory();
        var folder = Unzipped(Path.Combine(dir.Path, "Collection-HOST01"), Basics());

        var record = await CollectionExtractor.ExtractAsync(
            folder, Path.Combine(folder, "_Extracted", "HOST01"), null, null, CancellationToken.None);

        Assert.Contains("inside the collection", record.Error);
        Assert.False(Directory.Exists(Path.Combine(folder, "_Extracted")));
    }

    [Fact]
    public async Task An_unzipped_collection_runs_end_to_end_and_cleanup_leaves_the_source()
    {
        using var dir = new TempDirectory();
        var folder = Unzipped(Path.Combine(dir.Path, "evidence", "Collection-HOST01"), Basics());
        var before = Snapshot(folder);
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var config = new RunConfiguration
        {
            CaseName = "CASE",
            OutputRoot = dir.Dir("out"),
            ToolRoots = [dir.Path],
            Targets = EvidenceDiscovery.Discover(folder, batch: false, Layouts()).Targets,
            Modules =
            [
                new ModuleDefinition
                {
                    Description = "Writer",
                    Category = "Test",
                    SourcePath = @"C:\modules\Writer.forge",
                    Requires = [@"%root%\Windows\System32\config\SYSTEM"],
                    Processors = [new ProcessorDefinition
                    {
                        Executable = cmd,
                        CommandLine = @"/c type ""%root%\Windows\System32\config\SYSTEM"" > ""%destinationDirectory%\result.txt"""
                    }]
                }
            ],
            Layouts = Layouts(),
            CleanupExtracted = true
        };

        var report = await new RunEngine().RunAsync(config);

        Assert.Equal(WorkStatus.Completed, Assert.Single(report.Results, r => r.Module == "Writer").Status);
        Assert.Equal("hive", File.ReadAllText(Path.Combine(report.CaseDirectory, "HOST01", "Test", "Writer_result.txt")).Trim());
        Assert.True(Assert.Single(report.Extractions).CleanedUp);
        Assert.Equal(before, Snapshot(folder));
    }
}
