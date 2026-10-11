using ArtefactForge.Core;
using Xunit;

namespace ArtefactForge.Tests;

/// <summary>
/// Memory-heavy modules (Chainsaw, Hayabusa) run one at a time, but start straight away and run
/// beside the rest of the pool rather than queueing behind it. Timed with real processes, so the
/// tool is a short sleep and the assertions allow generous slack.
/// </summary>
public class SchedulingTests
{
    private static ModuleDefinition Module(TempDirectory dir, string name, int seconds, int priority, bool memoryHeavy)
    {
        // ping -n N waits about N-1 seconds; sleep is the POSIX equivalent.
        var (exe, args) = OperatingSystem.IsWindows()
            ? (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
               $@"/c ping -n {seconds + 1} 127.0.0.1 >nul & echo done> ""%destinationDirectory%\{name}.txt""")
            : ("/bin/sh", $"-c \"sleep {seconds}; echo done > '%destinationDirectory%/{name}.txt'\"");

        return new ModuleDefinition
        {
            Description = name,
            Category = "Test",
            SourcePath = Path.Combine(dir.Path, name + ".forge"),
            Priority = priority,
            MemoryWeight = memoryHeavy ? MemoryWeight.Heavy : MemoryWeight.Light,
            IoWeight = memoryHeavy ? IoWeight.Heavy : IoWeight.Light,
            Processors = [new ProcessorDefinition { Executable = exe, CommandLine = args }]
        };
    }

    private static RunConfiguration Config(TempDirectory dir, List<ModuleDefinition> modules) => new()
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
        Modules = modules,
        MaxWorkers = 1,
        MaxHeavyWorkers = 1
    };

    private static (DateTimeOffset Start, DateTimeOffset End) Span(RunReport report, string module)
    {
        var result = report.Results.Single(r => r.Module == module);
        Assert.Equal(WorkStatus.Completed, result.Status);
        return (result.Started, result.Started.AddSeconds(result.DurationSeconds));
    }

    [Fact]
    public async Task Memory_heavy_modules_run_one_at_a_time_from_the_start_beside_the_others()
    {
        using var dir = new TempDirectory();
        // The memory-heavy pair has the latest priority and there is one worker, so before this
        // they would have waited for both light modules and then run last.
        var report = await new RunEngine().RunAsync(Config(dir,
        [
            Module(dir, "LightA", 2, priority: 10, memoryHeavy: false),
            Module(dir, "LightB", 2, priority: 11, memoryHeavy: false),
            Module(dir, "HeavyA", 2, priority: 90, memoryHeavy: true),
            Module(dir, "HeavyB", 2, priority: 91, memoryHeavy: true)
        ]));

        var lightA = Span(report, "LightA");
        var heavyA = Span(report, "HeavyA");
        var heavyB = Span(report, "HeavyB");

        // Never two memory-heavy tools at once.
        Assert.True(heavyB.Start >= heavyA.End.AddMilliseconds(-200) || heavyA.Start >= heavyB.End.AddMilliseconds(-200),
            $"HeavyA {heavyA} and HeavyB {heavyB} overlapped");

        // The first memory-heavy tool did not wait for the worker the light module held.
        var first = heavyA.Start < heavyB.Start ? heavyA : heavyB;
        Assert.True(first.Start < lightA.End.AddMilliseconds(-500),
            $"the first memory-heavy module started at {first.Start}, after LightA finished at {lightA.End}");
    }

    [Fact]
    public void The_Chainsaw_and_Hayabusa_modules_are_memory_heavy()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !Directory.Exists(Path.Combine(root, "Modules"))) root = Path.GetDirectoryName(root);
        Assert.NotNull(root);

        var modules = ModuleLoader.LoadDirectory(Path.Combine(root!, "Modules", "Sigma"));
        Assert.Empty(modules.Errors);
        foreach (var name in new[] { "Chainsaw", "ChainsawGaps", "ChainsawSrum", "Hayabusa" })
            Assert.Equal(MemoryWeight.Heavy, modules.Items.Single(m => m.Name == name).MemoryWeight);
    }
}
