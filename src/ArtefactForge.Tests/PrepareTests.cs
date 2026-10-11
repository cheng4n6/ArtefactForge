using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// The Prepare phase exists for artefacts that cannot be parsed in place - a locked ESE database
/// on a live system. The staged copies are working material, so the contract is that they never
/// reach the output folder.
/// </summary>
public class PrepareTests
{
    private static readonly string Cmd = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private static ProcessorDefinition Step(string commandLine, bool continueOnError = false,
                                            string? workingDirectory = null) => new()
    {
        Executable = Cmd,
        CommandLine = commandLine,
        ContinueOnError = continueOnError,
        WorkingDirectory = workingDirectory
    };

    private static ModuleDefinition Module(ProcessorDefinition[] prepare, ProcessorDefinition[] processors) => new()
    {
        Description = "Staged",
        Category = "Test",
        SourcePath = @"C:\modules\Staged.forge",
        Prepare = prepare,
        Processors = processors
    };

    private static RunConfiguration Config(TempDirectory dir, ModuleDefinition module) => new()
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
                Layout = new LayoutProfile
                {
                    Id = "test", Name = "test",
                    Detect = new LayoutDetectRules { RootIsSelection = true, Markers = ["x"] },
                    Resolve = new LayoutResolveRules()
                }
            }
        ],
        Modules = [module],
        MaxWorkers = 2
    };

    [Fact]
    public async Task Prepare_runs_first_and_its_files_are_visible_to_the_processor()
    {
        using var dir = new TempDirectory();
        var module = Module(
            [Step(@"/c echo staged> ""%workDir%\SRUDB.dat""")],
            [Step(@"/c copy ""%workDir%\SRUDB.dat"" ""%destinationDirectory%\parsed.csv""")]);

        var report = await new RunEngine().RunAsync(Config(dir, module));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Equal(2, result.Processors.Count);
        Assert.Equal("prepare", result.Processors[0].Phase);
        Assert.Equal("process", result.Processors[1].Phase);
    }

    [Fact]
    public async Task Staged_files_never_reach_the_output_folder()
    {
        using var dir = new TempDirectory();
        var module = Module(
            [Step(@"/c echo secret> ""%workDir%\SRUDB.dat""")],
            [Step(@"/c echo done> ""%destinationDirectory%\parsed.csv""")]);

        var report = await new RunEngine().RunAsync(Config(dir, module));

        var delivered = Directory.GetFiles(Path.Combine(report.CaseDirectory, "TESTCOL", "Test"))
                                 .Select(Path.GetFileName).ToList();
        Assert.Contains("SrumECmd_parsed.csv".Replace("SrumECmd", "Staged"), delivered);
        Assert.DoesNotContain(delivered, f => f!.Contains("SRUDB"));
    }

    [Fact]
    public async Task Work_directory_is_removed_after_the_module()
    {
        using var dir = new TempDirectory();
        var module = Module(
            [Step(@"/c echo staged> ""%workDir%\SRUDB.dat""")],
            [Step(@"/c echo done> ""%destinationDirectory%\parsed.csv""")]);

        var report = await new RunEngine().RunAsync(Config(dir, module));
        Assert.False(Directory.Exists(Path.Combine(report.CaseDirectory, "_Staging")));
    }

    [Fact]
    public async Task A_failed_prepare_step_stops_the_module_before_it_parses_nothing()
    {
        using var dir = new TempDirectory();
        var module = Module(
            [Step("/c exit 5")],
            [Step(@"/c echo done> ""%destinationDirectory%\parsed.csv""")]);

        var report = await new RunEngine().RunAsync(Config(dir, module));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Failed, result.Status);
        Assert.Contains("preparation step 1", result.Reason);
        Assert.Single(result.Processors);
    }

    [Fact]
    public async Task ContinueOnError_lets_a_noisy_staging_step_through()
    {
        // esentutl log recovery is the real case: non-zero exit, usable copy.
        using var dir = new TempDirectory();
        var module = Module(
            [Step(@"/c echo staged> ""%workDir%\SRUDB.dat""", continueOnError: false),
             Step("/c exit 5", continueOnError: true)],
            [Step(@"/c echo done> ""%destinationDirectory%\parsed.csv""")]);

        var report = await new RunEngine().RunAsync(Config(dir, module));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Equal(3, result.Processors.Count);
        Assert.Equal(5, result.Processors[1].ExitCode);
    }

    [Fact]
    public async Task WorkingDirectory_is_honoured_and_placeholders_expand_inside_it()
    {
        // esentutl /r resolves its log base name against the current directory, not an argument.
        using var dir = new TempDirectory();
        var module = Module(
            [Step(@"/c echo marker> here.txt", workingDirectory: "%workDir%")],
            [Step(@"/c copy ""%workDir%\here.txt"" ""%destinationDirectory%\found.csv""")]);

        var report = await new RunEngine().RunAsync(Config(dir, module));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Contains("_work", result.Processors[0].WorkingDirectory);
    }

    [Fact]
    public async Task Prepare_steps_are_recorded_in_the_audit_trail()
    {
        // Staging is part of what happened to the evidence, so it belongs in the manifest.
        using var dir = new TempDirectory();
        var module = Module(
            [Step(@"/c echo staged> ""%workDir%\SRUDB.dat""")],
            [Step(@"/c echo done> ""%destinationDirectory%\parsed.csv""")]);

        var report = await new RunEngine().RunAsync(Config(dir, module));

        var csv = File.ReadAllText(Path.Combine(report.LogDirectory, "manifest.csv"));
        Assert.Contains("Phase", csv);
        Assert.Contains("prepare", csv);
        Assert.Contains("process", csv);
    }
}
