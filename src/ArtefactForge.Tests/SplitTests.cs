using System.Text;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// A Split step runs a tool as several processes over a share of its input each and joins their
/// CSVs (EvtxECmd over the event logs). The joined file must hold every part's rows exactly once,
/// and anything short of that must not pass for it.
/// </summary>
public class SplitTests
{
    private static readonly string Cmd = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private static readonly UTF8Encoding Utf8Bom = new(encoderShouldEmitUTF8Identifier: true);

    // --- Sharing the files out ---

    [Fact]
    public void Files_are_shared_out_largest_first_into_the_lightest_part()
    {
        var groups = InputSplit.Group(
            [("a.evtx", 100), ("b.evtx", 60), ("c.evtx", 50), ("d.evtx", 40), ("e.evtx", 10)], 2);

        Assert.Equal(2, groups.Count);
        Assert.Equal(["a.evtx", "d.evtx"], groups[0]);              // 140
        Assert.Equal(["b.evtx", "c.evtx", "e.evtx"], groups[1]);    // 120
    }

    [Fact]
    public void The_same_files_land_in_the_same_parts_whatever_order_they_are_listed_in()
    {
        (string, long)[] files = [("Security.evtx", 20), ("System.evtx", 20), ("Setup.evtx", 1), ("App.evtx", 5)];
        Assert.Equal(InputSplit.Group(files, 3), InputSplit.Group(files.Reverse().ToList(), 3));
    }

    [Theory]
    [InlineData("auto", 265, 400L << 20, 4)]
    [InlineData("auto", 265, 10L << 20, 1)]     // under 50 MB: starting more processes costs more
    [InlineData(null, 265, 400L << 20, 4)]
    [InlineData("8", 265, 10L << 20, 8)]        // asked for, so honoured even for a small set
    [InlineData("8", 3, 400L << 20, 3)]         // never more parts than files
    [InlineData("1", 265, 400L << 20, 1)]
    public void Parts_follow_the_setting_and_never_exceed_the_files(string? setting, int files, long bytes, int expected)
    {
        Assert.Equal(expected, InputSplit.Parts(setting, files, bytes));
    }

    [Fact]
    public void Each_part_folder_holds_hard_links_and_the_evidence_is_left_as_it_was()
    {
        using var dir = new TempDirectory();
        var a = Write(dir, @"evidence\a.evtx", "AAAA");
        var b = Write(dir, @"evidence\b.evtx", "BB");

        var error = InputSplit.Link([[a], [b]], dir.Dir("split"), out var folders);

        Assert.Null(error);
        Assert.Equal(2, folders.Count);
        Assert.Equal("AAAA", File.ReadAllText(Path.Combine(folders[0], "a.evtx")));
        Directory.Delete(dir.Dir("split"), recursive: true);
        Assert.Equal("AAAA", File.ReadAllText(a));
        Assert.Equal("BB", File.ReadAllText(b));
    }

    [Fact]
    public void A_link_that_cannot_be_made_is_reported_and_nothing_is_left_behind()
    {
        using var dir = new TempDirectory();
        var a = Write(dir, @"evidence\a.evtx", "AAAA");

        var error = InputSplit.Link([[a], [Path.Combine(dir.Path, "missing.evtx")]], dir.Dir("split"), out var folders);

        Assert.NotNull(error);
        Assert.Contains("missing.evtx", error);
        Assert.Empty(folders);
        Assert.Empty(Directory.GetDirectories(Path.Combine(dir.Path, "split")));
    }

    // --- Joining the parts ---

    [Fact]
    public async Task The_header_is_written_once_and_later_byte_order_marks_are_dropped()
    {
        using var dir = new TempDirectory();
        var parts = new[]
        {
            Write(dir, "p1.csv", "Id,Payload\r\n1,a\r\n2,b\r\n", Utf8Bom),
            Write(dir, "p2.csv", "Id,Payload\r\n3,c\r\n", Utf8Bom)
        };
        var merged = Path.Combine(dir.Path, "merged.csv");

        Assert.Null(await InputSplit.MergeAsync(parts, merged, CancellationToken.None));

        var bytes = File.ReadAllBytes(merged);
        Assert.Equal(1, Count(bytes, Utf8Bom.GetPreamble()));
        Assert.Equal("Id,Payload\r\n1,a\r\n2,b\r\n3,c\r\n", Utf8Bom.GetString(bytes).TrimStart('\uFEFF'));
    }

    [Fact]
    public async Task Quoted_fields_that_run_over_several_lines_come_through_intact()
    {
        using var dir = new TempDirectory();
        const string row = "7,\"{\r\n  \"\"EventData\"\": 1\r\n}\"\r\n";
        var parts = new[] { Write(dir, "p1.csv", "Id,Payload\r\n"), Write(dir, "p2.csv", "Id,Payload\r\n" + row) };
        var merged = Path.Combine(dir.Path, "merged.csv");

        Assert.Null(await InputSplit.MergeAsync(parts, merged, CancellationToken.None));
        Assert.Equal("Id,Payload\r\n" + row, File.ReadAllText(merged));
    }

    [Fact]
    public async Task Each_part_folder_is_written_as_the_evidence_folder_even_across_a_read_boundary()
    {
        // EvtxECmd's SourceFile names the link in _Staging the part read, which is gone after the run.
        using var dir = new TempDirectory();
        const string part = @"C:\case\_Staging\split1\part2";
        const string evidence = @"C:\case\_Extracted\HOST01\C\Windows\System32\winevt\Logs";
        // Long enough that a path lands across the 1 MB reads the copy is made in.
        var rows = new StringBuilder("SourceFile,Payload\r\n");
        for (var i = 0; rows.Length < 3 << 20; i++)
            rows.Append(part).Append(@"\Security.evtx,").Append(new string('x', i % 97)).Append("\r\n");
        var merged = Path.Combine(dir.Path, "merged.csv");

        Assert.Null(await InputSplit.MergeAsync([Write(dir, "p2.csv", rows.ToString())], merged,
                                                CancellationToken.None, [(part, evidence)]));

        var text = File.ReadAllText(merged);
        Assert.DoesNotContain("_Staging", text);
        Assert.Equal(rows.ToString().Replace(part + @"\", evidence + @"\"), text);
    }

    [Fact]
    public async Task Parts_whose_headers_differ_are_not_joined()
    {
        using var dir = new TempDirectory();
        var parts = new[] { Write(dir, "p1.csv", "Id,Payload\r\n1,a\r\n"), Write(dir, "p2.csv", "Id,Channel\r\n2,b\r\n") };
        var merged = Path.Combine(dir.Path, "merged.csv");

        var error = await InputSplit.MergeAsync(parts, merged, CancellationToken.None);

        Assert.NotNull(error);
        Assert.Contains("different header", error);
    }

    [Fact]
    public async Task A_part_that_wrote_no_file_is_passed_over_and_a_missing_last_newline_is_added()
    {
        using var dir = new TempDirectory();
        var parts = new[]
        {
            Write(dir, "p1.csv", "Id\r\n1"),
            Path.Combine(dir.Path, "p2.csv"),
            Write(dir, "p3.csv", "Id\r\n3\r\n")
        };
        var merged = Path.Combine(dir.Path, "merged.csv");

        Assert.Null(await InputSplit.MergeAsync(parts, merged, CancellationToken.None));
        Assert.Equal("Id\r\n1\r\n3\r\n", File.ReadAllText(merged));
    }

    [Fact]
    public async Task Parts_that_wrote_only_empty_files_join_into_an_empty_file_and_none_into_no_file()
    {
        // An empty file is what the engine reports as a tool that never got going; it must stay one.
        using var dir = new TempDirectory();
        var empty = Path.Combine(dir.Path, "empty.csv");
        Assert.Null(await InputSplit.MergeAsync([Write(dir, "p1.csv", ""), Write(dir, "p2.csv", "")], empty, CancellationToken.None));
        Assert.Equal(0, new FileInfo(empty).Length);

        var none = Path.Combine(dir.Path, "none.csv");
        Assert.Null(await InputSplit.MergeAsync([Path.Combine(dir.Path, "x.csv")], none, CancellationToken.None));
        Assert.False(File.Exists(none));
    }

    // --- Loading a module ---

    [Fact]
    public void The_parts_option_needs_no_Expand_and_adds_nothing_to_the_command_line()
    {
        using var dir = new TempDirectory();
        var module = ModuleLoader.LoadFile(Write(dir, "Split.forge", ForgeFile("Option: Parts")));

        Assert.Equal("Parts", module.Processors[0].Split!.Option);
        Assert.Equal("", ModuleOptions.Expand(module));
    }

    [Fact]
    public void A_Split_naming_an_undeclared_option_does_not_load()
    {
        using var dir = new TempDirectory();
        var error = Assert.Throws<FormatException>(() =>
            ModuleLoader.LoadFile(Write(dir, "Split.forge", ForgeFile("Option: Count"))));
        Assert.Contains("'Count'", error.Message);
    }

    // --- Running a module ---

    [Fact]
    public async Task A_split_step_runs_in_parts_and_delivers_one_joined_file_with_every_row()
    {
        using var dir = new TempDirectory();
        var names = Evidence(dir, 7);

        var report = await new RunEngine().RunAsync(Config(dir, Module(ListLogs), parts: "3"));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Contains("ran as 3 processes over 7 files", result.Reason);
        Assert.Equal(3, result.Processors.Count);
        Assert.All(result.Processors, p => Assert.Contains("_part", p.Arguments));

        var delivered = Assert.Single(Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "Test")));
        var lines = File.ReadAllLines(delivered);
        Assert.Equal("Name", lines[0]);
        // Every row once, under the evidence folder rather than the links the parts read.
        var logs = Path.Combine(dir.Path, "evidence", "Logs");
        Assert.Equal(names.Select(n => Path.Combine(logs, n)).Order(StringComparer.OrdinalIgnoreCase),
                     lines.Skip(1).Order(StringComparer.OrdinalIgnoreCase));
        Assert.False(Directory.Exists(Path.Combine(report.CaseDirectory, "_Staging")));
        Assert.Equal(7, Directory.GetFiles(Path.Combine(dir.Path, "evidence", "Logs")).Length);
    }

    [Fact]
    public async Task One_part_runs_the_step_over_the_whole_folder_as_before()
    {
        using var dir = new TempDirectory();
        var names = Evidence(dir, 4);

        var report = await new RunEngine().RunAsync(Config(dir, Module(ListLogs), parts: "1"));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Null(result.Reason);
        var processor = Assert.Single(result.Processors);
        Assert.DoesNotContain("_part", processor.Arguments);
        var delivered = Assert.Single(Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "Test")));
        Assert.Equal(names.Length + 1, File.ReadAllLines(delivered).Length);
    }

    [Fact]
    public async Task A_live_system_runs_as_one_process_and_says_why_when_parts_were_asked_for()
    {
        using var dir = new TempDirectory();
        Evidence(dir, 4);

        var report = await new RunEngine().RunAsync(Config(dir, Module(ListLogs), parts: "4", live: true));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Single(result.Processors);
        Assert.Contains("run as one process", result.Reason);
    }

    [Fact]
    public async Task A_failed_part_fails_the_module_and_the_unjoined_parts_go_to_Incomplete()
    {
        using var dir = new TempDirectory();
        Evidence(dir, 6);

        var report = await new RunEngine().RunAsync(
            Config(dir, Module(ListLogs + " & if \"%splitPart%\"==\"_part2\" exit 3"), parts: "3"));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Failed, result.Status);
        Assert.StartsWith("part 2: exit code 3", result.Reason);
        Assert.Contains("not joined", result.Reason);
        Assert.False(Directory.Exists(Path.Combine(report.CaseDirectory, "TESTCOL", "Test"))
                     && Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "Test")).Length > 0);
        Assert.Equal(3, Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "_Incomplete", "Test")).Length);
    }

    [Fact]
    public async Task Parts_whose_headers_differ_fail_the_module_rather_than_being_joined()
    {
        using var dir = new TempDirectory();
        Evidence(dir, 4);

        var report = await new RunEngine().RunAsync(
            Config(dir, Module(@"/c (echo Name%splitPart%& dir /b ""%splitDir%"") > ""%destinationDirectory%\Logs%splitPart%.csv"""),
                   parts: "2"));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Failed, result.Status);
        Assert.Contains("different header", result.Reason);
        Assert.Equal(2, Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "_Incomplete", "Test")).Length);
    }

    [Fact]
    public async Task Extra_parts_wait_for_a_worker_so_a_pool_of_one_still_finishes()
    {
        // Each part beyond the first takes a worker of its own. With one worker they run one after
        // another rather than waiting on each other for ever.
        using var dir = new TempDirectory();
        Evidence(dir, 4);

        var report = await new RunEngine().RunAsync(Config(dir, Module(ListLogs), parts: "4", workers: 1));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Equal(4, result.Processors.Count);
    }

    // --- Helpers ---

    // Writes each log's full path, as EvtxECmd's SourceFile column does.
    private const string ListLogs = @"/c (echo Name& dir /b /s ""%splitDir%"") > ""%destinationDirectory%\Logs%splitPart%.csv""";

    private static ModuleDefinition Module(string commandLine) => new()
    {
        Description = "Split",
        Category = "Test",
        SourcePath = @"C:\modules\Split.forge",
        Options = [new ModuleOption { Name = "Parts", Kind = OptionKind.Choice, Default = "auto", Expand = "",
                                      Choices = ["auto", "1", "2", "3", "4"] }],
        Processors =
        [
            new ProcessorDefinition
            {
                Executable = Cmd,
                CommandLine = commandLine,
                Split = new SplitDefinition
                {
                    Folder = @"%root%\Logs", Pattern = "*.evtx", MergeInto = "Logs.csv", Option = "Parts"
                }
            }
        ]
    };

    private static RunConfiguration Config(TempDirectory dir, ModuleDefinition module, string parts,
                                           bool live = false, int workers = 4) => new()
    {
        CaseName = "CASE",
        OutputRoot = dir.Dir("out"),
        ToolRoots = [dir.Path],
        Targets =
        [
            new ResolvedTarget
            {
                SelectionPath = dir.Dir("evidence"),
                Root = dir.Dir("evidence"),
                CollectionName = "TESTCOL",
                IsLive = live,
                Layout = new LayoutProfile
                {
                    Id = "test", Name = "test",
                    Detect = new LayoutDetectRules { RootIsSelection = true, Markers = ["x"] },
                    Resolve = new LayoutResolveRules()
                }
            }
        ],
        Modules = [module],
        OptionOverrides = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            [module.Name] = new Dictionary<string, string> { ["Parts"] = parts }
        },
        MaxWorkers = workers
    };

    /// <summary>Made-up logs of different sizes under evidence\Logs. Returns their names.</summary>
    private static string[] Evidence(TempDirectory dir, int count) =>
        Enumerable.Range(1, count)
            .Select(i => Path.GetFileName(Write(dir, Path.Combine("evidence", "Logs", $"Log{i}.evtx"), new string('x', i * 100))))
            .ToArray()!;

    private static string ForgeFile(string optionLine) => $"""
        Description: Split
        Category: Test
        Options:
          -
            Name: Parts
            Kind: choice
            Choices: [auto, '1', '4']
            Default: auto
        Processors:
          -
            Executable: tool.exe
            CommandLine: -d "%splitDir%" --csvf Out%splitPart%.csv %options%
            Split:
              Folder: '%root%\Logs'
              Pattern: '*.evtx'
              MergeInto: Out.csv
              {optionLine}
        """;

    private static string Write(TempDirectory dir, string relativePath, string content, Encoding? encoding = null)
    {
        var path = dir.File(relativePath);
        File.WriteAllText(path, content, encoding ?? new UTF8Encoding(false));
        return path;
    }

    private static int Count(byte[] haystack, byte[] needle)
    {
        var count = 0;
        for (var i = 0; i + needle.Length <= haystack.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle)) count++;
        return count;
    }
}
