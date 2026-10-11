using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// ExpectedStderr: a tool that always writes progress to stderr must not be flagged CheckLog on
/// every run, but a line outside the declared patterns still has to be. The stderr samples are
/// Chainsaw 2.16.3's own output, with the paths replaced.
/// </summary>
public class ExpectedStderrTests
{
    private const string SrumGoodRun =
        "[+] ESE database file loaded from \"D:\\\\case\\\\SRUDB.dat\"\n" +
        "[+] Details about the tables related to the SRUM extensions:\n" +
        "+----------------+----------------+\n" +
        "| Table GUID     | Table Name     |\n" +
        "+----------------+----------------+\n" +
        "[+] Saved output to \"D:\\\\case\\\\Srum.json\"\n";

    private static string ModulesRoot()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !Directory.Exists(Path.Combine(root, "Modules"))) root = Path.GetDirectoryName(root);
        Assert.NotNull(root);
        return Path.Combine(root!, "Modules");
    }

    private static List<string> ShippedPatterns(string module) =>
        ModuleLoader.LoadFile(Path.Combine(ModulesRoot(), "Sigma", module + ".forge")).Processors[0].ExpectedStderr;

    private static string Log(TempDirectory dir, string content)
    {
        var path = dir.File("tool.err.log");
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Srum_progress_and_table_are_expected()
    {
        using var dir = new TempDirectory();
        Assert.True(RunEngine.OnlyExpectedStderr(Log(dir, SrumGoodRun), ShippedPatterns("ChainsawSrum")));
    }

    [Fact]
    public void Srum_patterns_do_not_pass_a_warning()
    {
        using var dir = new TempDirectory();
        var log = Log(dir, SrumGoodRun + "[!] Failed to parse table\n");
        Assert.False(RunEngine.OnlyExpectedStderr(log, ShippedPatterns("ChainsawSrum")));
    }

    [Fact]
    public void Without_patterns_any_stderr_is_unexpected()
    {
        using var dir = new TempDirectory();
        Assert.False(RunEngine.OnlyExpectedStderr(Log(dir, "[+] Saved output\n"), []));
    }

    [Fact]
    public void A_missing_log_is_not_passed()
    {
        using var dir = new TempDirectory();
        Assert.False(RunEngine.OnlyExpectedStderr(Path.Combine(dir.Path, "absent.log"), ["."]));
    }

    [Fact]
    public void An_invalid_pattern_is_refused_at_load()
    {
        using var dir = new TempDirectory();
        var path = dir.File("Bad.forge");
        File.WriteAllText(path, """
            Description: bad
            Processors:
              -
                Executable: x.exe
                CommandLine: run
                ExpectedStderr: ['^[unclosed']
            """);
        var ex = Assert.Throws<FormatException>(() => ModuleLoader.LoadFile(path));
        Assert.Contains("ExpectedStderr", ex.Message);
    }

    [Fact]
    public void Shipped_chainsaw_analyse_modules_load()
    {
        var modules = ModuleLoader.LoadDirectory(Path.Combine(ModulesRoot(), "Sigma"));
        Assert.Empty(modules.Errors);
        var gaps = modules.Items.Single(m => m.Name == "ChainsawGaps");
        Assert.False(gaps.DefaultEnabled);
        Assert.DoesNotContain(" -q", gaps.Processors[0].CommandLine);
        Assert.DoesNotContain(" -q", modules.Items.Single(m => m.Name == "ChainsawSrum").Processors[0].CommandLine);
    }

    // The engine path: a tool that writes its progress to stderr and exits 0.
    private static (string Exe, string Args) Tool(string stderrLines)
    {
        if (OperatingSystem.IsWindows())
        {
            var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            var echoes = string.Join(" & ", stderrLines.Split('\n').Select(l => "echo " + l + " 1>&2"));
            return (cmd, @"/c echo hello> ""%destinationDirectory%\result.txt"" & " + echoes);
        }
        var sh = string.Join("; ", stderrLines.Split('\n').Select(l => "echo '" + l + "' 1>&2"));
        return ("/bin/sh", "-c \"echo hello > '%destinationDirectory%/result.txt'; " + sh + "\"");
    }

    private static async Task<RunReport> Run(TempDirectory dir, string stderrLines, List<string> patterns)
    {
        var (exe, args) = Tool(stderrLines);
        var module = new ModuleDefinition
        {
            Description = "Noisy",
            Category = "Test",
            SourcePath = Path.Combine(dir.Path, "Noisy.forge"),
            Processors = [new ProcessorDefinition { Executable = exe, CommandLine = args, ExpectedStderr = patterns }]
        };
        var config = new RunConfiguration
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
                        Id = "test",
                        Name = "test",
                        Detect = new LayoutDetectRules { Markers = ["x"] },
                        Resolve = new LayoutResolveRules()
                    }
                }
            ],
            Modules = [module],
            MaxWorkers = 1,
            MaxHeavyWorkers = 1
        };
        return await new RunEngine().RunAsync(config);
    }

    [Fact]
    public async Task Expected_progress_on_stderr_completes()
    {
        using var dir = new TempDirectory();
        var report = await Run(dir, "[+] Loading\n[+] Saved output", [@"^\[\+\] "]);

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        var processor = Assert.Single(result.Processors);
        Assert.True(processor.WroteToStderr);
        Assert.True(processor.StderrExpected);
        Assert.Contains(",expected,", File.ReadAllText(Path.Combine(report.LogDirectory, "manifest.csv")));
    }

    [Fact]
    public async Task An_unexpected_line_still_needs_review()
    {
        using var dir = new TempDirectory();
        var report = await Run(dir, "[+] Loading\n[!] Failed to load hive", [@"^\[\+\] "]);

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.CheckLog, result.Status);
        Assert.False(Assert.Single(result.Processors).StderrExpected);
    }
}
