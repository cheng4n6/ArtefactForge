using System.Diagnostics;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Failure handling, driven end to end through the real engine with cmd.exe standing in for a
/// forensic tool. These paths never ran during the build - a tool that hangs, times out, exits
/// non-zero or is missing entirely is exactly when the engine has to behave.
/// </summary>
public class RunEngineTests
{
    private static readonly string Cmd = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private static ModuleDefinition Module(
        string name, string commandLine, string? executable = null,
        IterationMode iterate = IterationMode.None, int? timeout = null,
        IoWeight io = IoWeight.Light, TargetScope scope = TargetScope.Any,
        bool supportsVss = false, ElevationRequirement elevation = ElevationRequirement.None,
        string category = "Test", params string[] requires) => new()
    {
        Description = name,
        Category = category,
        SourcePath = $@"C:\modules\{name}.forge",
        Iterate = iterate,
        Timeout = timeout,
        IoWeight = io,
        Scope = scope,
        SupportsVss = supportsVss,
        Elevation = elevation,
        Requires = requires,
        Processors = [new ProcessorDefinition { Executable = executable ?? Cmd, CommandLine = commandLine }]
    };

    private static ResolvedTarget Target(string root, bool rootIsSelection = false, bool live = false) => new()
    {
        SelectionPath = root,
        IsLive = live,
        Root = root,
        CollectionName = "TESTCOL",
        Layout = new LayoutProfile
        {
            Id = "test",
            Name = "test",
            Detect = new LayoutDetectRules { RootIsSelection = rootIsSelection, Markers = ["x"] },
            Resolve = new LayoutResolveRules()
        }
    };

    private static RunConfiguration Config(TempDirectory dir, ModuleDefinition[] modules,
        bool vss = false, bool rootIsSelection = false, int workers = 4, int heavy = 2,
        bool skipCompleted = true, bool live = false) => new()
    {
        CaseName = "CASE",
        OutputRoot = dir.Dir("out"),
        ToolRoots = [dir.Path],
        Targets = [Target(dir.Dir("evidence"), rootIsSelection, live)],
        Modules = modules,
        MaxWorkers = workers,
        MaxHeavyWorkers = heavy,
        Vss = vss,
        SkipCompleted = skipCompleted
    };

    /// <summary>cmd.exe parses its own command line, so redirection inside /c works.</summary>
    private const string WritesAFile = @"/c echo hello> ""%destinationDirectory%\result.txt""";
    private const string Sleeps = "/c ping -n 12 127.0.0.1 >nul";

    [Fact]
    public async Task Missing_executable_is_reported_not_thrown()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("Ghost", "/c echo x", executable: "no-such-tool.exe")]));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.ToolMissing, result.Status);
        Assert.Contains("no-such-tool.exe", result.Reason);
    }

    [Fact]
    public async Task Non_zero_exit_is_a_failure()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Boom", "/c exit 3")]));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Failed, result.Status);
        Assert.Contains("exit code 3", result.Reason);
    }

    [Fact]
    public async Task Exit_zero_with_no_output_is_flagged_rather_than_trusted()
    {
        // The RECmd case: a tool can return success and write nothing at all.
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Quiet", "/c exit 0")]));

        Assert.Equal(WorkStatus.NoOutput, Assert.Single(report.Results).Status);
        Assert.Equal(1, report.NeedsReview);
    }

    [Fact]
    public async Task Output_is_harvested_and_renamed()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Writer", WritesAFile)]));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Equal(0, report.NeedsReview);

        var delivered = Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "Test"));
        Assert.Equal("Writer_result.txt", Path.GetFileName(Assert.Single(delivered)));
        Assert.Contains("result.txt => Writer_result.txt", result.Processors[0].OutputFiles);
    }

    [Fact]
    public async Task Staging_is_cleaned_up()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Writer", WritesAFile)]));
        Assert.False(Directory.Exists(Path.Combine(report.CaseDirectory, "_Staging")));
    }

    [Fact]
    public async Task Output_that_cannot_be_moved_into_place_fails_the_module_and_is_kept()
    {
        // A folder where the output file should go makes the move fail. The module used to count
        // the failed move as delivered output, pass as Completed, and delete the only copy.
        using var dir = new TempDirectory();
        var config = Config(dir, [Module("Writer", WritesAFile)]);
        Directory.CreateDirectory(Path.Combine(config.OutputRoot, "CASE", "TESTCOL", "Test", "Writer_result.txt"));

        var report = await new RunEngine().RunAsync(config);

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Failed, result.Status);
        Assert.Contains("could not be moved", result.Reason);
        Assert.Contains("FAILED", Assert.Single(result.Processors[0].OutputFiles));
        Assert.Single(Directory.GetFiles(Path.Combine(report.CaseDirectory, "_Staging"), "result.txt",
            SearchOption.AllDirectories));
    }

    [Fact]
    public async Task A_module_that_cannot_make_its_folder_fails_alone_and_the_run_finishes()
    {
        // A file where the category folder should be: the engine itself throws for this module.
        using var dir = new TempDirectory();
        var config = Config(dir, [Module("Blocked", WritesAFile), Module("Writer", WritesAFile, category: "Other")]);
        Directory.CreateDirectory(Path.Combine(config.OutputRoot, "CASE", "TESTCOL"));
        File.WriteAllText(Path.Combine(config.OutputRoot, "CASE", "TESTCOL", "Test"), "");

        var report = await new RunEngine().RunAsync(config);

        Assert.Equal(WorkStatus.Failed, report.Results.Single(r => r.Module == "Blocked").Status);
        Assert.Contains("could not run the module", report.Results.Single(r => r.Module == "Blocked").Reason);
        Assert.Equal(WorkStatus.Completed, report.Results.Single(r => r.Module == "Writer").Status);
        Assert.True(File.Exists(Path.Combine(report.LogDirectory, "manifest.csv")));
    }

    [Fact]
    public async Task A_hung_tool_is_killed_at_its_timeout()
    {
        using var dir = new TempDirectory();
        var stopwatch = Stopwatch.StartNew();

        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("Hang", Sleeps, timeout: 2)]));

        stopwatch.Stop();
        Assert.Equal(WorkStatus.TimedOut, Assert.Single(report.Results).Status);
        // The command would run for ~11s; proves it was killed rather than waited out.
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(9), $"took {stopwatch.Elapsed}");
    }

    [Fact]
    public async Task Output_from_a_timed_out_tool_is_kept_apart_from_finished_output()
    {
        // Writes a file, then hangs: the file exists but the tool never finished with it.
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir,
            [Module("HalfDone", @"/c echo partial> ""%destinationDirectory%\out.csv"" & ping -n 12 127.0.0.1 >nul", timeout: 2)]));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.TimedOut, result.Status);
        Assert.Contains("_Incomplete", result.Reason);

        var category = Path.Combine(report.CaseDirectory, "TESTCOL", "Test");
        Assert.Empty(Directory.GetFiles(category));
        var kept = Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "_Incomplete", "Test"));
        Assert.Equal("HalfDone_out.csv", Path.GetFileName(Assert.Single(kept)));
    }

    [Fact]
    public async Task Cancellation_kills_running_tools()
    {
        using var dir = new TempDirectory();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        var stopwatch = Stopwatch.StartNew();

        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("Hang", Sleeps)]), cancellation.Token);

        stopwatch.Stop();
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(9), $"took {stopwatch.Elapsed}");
        Assert.True(report.Cancelled || report.Results.Any(r => r.Status == WorkStatus.Cancelled),
            "run should report cancellation");
    }

    [Fact]
    public async Task Absent_required_artefact_skips_with_a_reason()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("Needs", "/c exit 0", requires: @"%root%\Windows\System32\config\SYSTEM")]));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Skipped, result.Status);
        Assert.Contains("not present", result.Reason);
    }

    [Fact]
    public async Task Live_only_module_skips_against_a_collection()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("LiveOnly", "/c exit 0", scope: TargetScope.LiveOnly)]));

        Assert.Equal(WorkStatus.Skipped, Assert.Single(report.Results).Status);
    }

    [Fact]
    public async Task Vss_is_withheld_from_a_collection_folder_even_when_requested()
    {
        // A collection folder has no shadow copies; passing --vss would just make the tool fail.
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("Vss", WritesAFile + " %vss%", supportsVss: true)],
                   vss: true, rootIsSelection: false));

        Assert.DoesNotContain("--vss", report.Results.Single().Processors[0].Arguments);
    }

    [Fact]
    public async Task Vss_is_passed_for_a_real_volume_when_the_tool_supports_it()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("Vss", WritesAFile + " %vss%", supportsVss: true)],
                   vss: true, rootIsSelection: true));

        Assert.Contains("--vss", report.Results.Single().Processors[0].Arguments);
    }

    [Fact]
    public async Task Vss_is_withheld_from_a_tool_that_does_not_support_it()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("NoVss", WritesAFile + " %vss%", supportsVss: false)],
                   vss: true, rootIsSelection: true));

        Assert.DoesNotContain("--vss", report.Results.Single().Processors[0].Arguments);
    }

    [Fact]
    public async Task Completed_work_is_skipped_on_a_second_run()
    {
        using var dir = new TempDirectory();
        var config = Config(dir, [Module("Writer", WritesAFile)]);

        await new RunEngine().RunAsync(config);
        var second = await new RunEngine().RunAsync(config);

        var result = Assert.Single(second.Results);
        Assert.Equal(WorkStatus.Skipped, result.Status);
        Assert.Contains("already completed", result.Reason);
    }

    [Fact]
    public async Task Failed_work_is_retried_on_a_second_run()
    {
        // Failures must never be written to the state file, or a re-run would skip them silently.
        using var dir = new TempDirectory();
        var config = Config(dir, [Module("Boom", "/c exit 3")]);

        await new RunEngine().RunAsync(config);
        var second = await new RunEngine().RunAsync(config);

        Assert.Equal(WorkStatus.Failed, Assert.Single(second.Results).Status);
    }

    [Fact]
    public async Task Heavy_modules_do_not_run_concurrently_beyond_the_limit()
    {
        using var dir = new TempDirectory();
        var modules = new[]
        {
            Module("HeavyA", "/c ping -n 4 127.0.0.1 >nul", io: IoWeight.Heavy),
            Module("HeavyB", "/c ping -n 4 127.0.0.1 >nul", io: IoWeight.Heavy)
        };

        var stopwatch = Stopwatch.StartNew();
        await new RunEngine().RunAsync(Config(dir, modules, workers: 4, heavy: 1));
        stopwatch.Stop();

        // Each command takes ~3s. Serialised they cannot finish inside one command's time.
        Assert.True(stopwatch.Elapsed > TimeSpan.FromSeconds(4), $"took {stopwatch.Elapsed} - ran in parallel?");
    }

    [Fact]
    public async Task Manifest_records_the_command_line_and_tool_hash()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Writer", WritesAFile)]));

        var manifest = Path.Combine(report.LogDirectory, "manifest.csv");
        Assert.True(File.Exists(manifest));
        Assert.True(File.Exists(Path.Combine(report.LogDirectory, "manifest.json")));

        var processor = report.Results.Single().Processors[0];
        Assert.NotNull(processor.ToolSha256);
        Assert.Equal(64, processor.ToolSha256.Length);
        Assert.Contains("echo hello", processor.Arguments);
        Assert.True(processor.PeakMemoryBytes > 0);
        Assert.EndsWith(",PeakMemoryMB", File.ReadLines(manifest).First());
        Assert.StartsWith("Most memory: Writer on ", report.DescribePeakMemory());
    }

    [Fact]
    public async Task A_zero_byte_file_is_not_output()
    {
        // EvtxECmd and Hayabusa, unable to open a single log, exit 0 leaving an empty CSV behind.
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(
            Config(dir, [Module("Empty", @"/c type nul> ""%destinationDirectory%\empty.csv""")]));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.NoOutput, result.Status);
        Assert.Contains("0 bytes", result.Reason);
    }

    [Fact]
    public async Task Per_user_output_goes_in_a_folder_per_user_and_only_for_profiles_holding_the_artefact()
    {
        using var dir = new TempDirectory();
        var config = Config(dir, [Module("Writer", WritesAFile, iterate: IterationMode.UserProfile,
            requires: @"%root%\Users\%user%\NTUSER.DAT")]);
        var users = Path.Combine(config.Targets[0].Root, "Users");
        Directory.CreateDirectory(Path.Combine(users, "alice"));
        File.WriteAllText(Path.Combine(users, "alice", "NTUSER.DAT"), "x");
        Directory.CreateDirectory(Path.Combine(users, "Public"));

        var report = await new RunEngine().RunAsync(config);

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        var category = Path.Combine(report.CaseDirectory, "TESTCOL", "Test");
        Assert.True(File.Exists(Path.Combine(category, "alice", "alice_Writer_result.txt")));
        Assert.False(Directory.Exists(Path.Combine(category, "Public")));
    }

    [Fact]
    public void Live_elevation_skips_on_a_live_target_but_not_on_a_collection()
    {
        using var dir = new TempDirectory();
        var module = Module("Raw", WritesAFile, elevation: ElevationRequirement.Live);

        var live = RunPlanner.Build(Config(dir, [module], live: true));
        var collected = RunPlanner.Build(Config(dir, [module]));

        Assert.Single(collected.Items);
        if (new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
        {
            Assert.Single(live.Items);
            return;
        }
        Assert.Empty(live.Items);
        Assert.Contains("elevated", Assert.Single(live.Skipped).Reason);
    }
}