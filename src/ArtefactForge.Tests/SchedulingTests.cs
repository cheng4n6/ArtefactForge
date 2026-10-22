using ArtefactForge.Core;
using Xunit;

namespace ArtefactForge.Tests;

/// <summary>
/// Memory-heavy modules (Chainsaw, Hayabusa) share a memory budget, but start straight away and
/// run beside the rest of the pool rather than queueing behind it. Timed with real processes, so the
/// tool is a short sleep and the assertions allow generous slack.
/// </summary>
public class SchedulingTests
{
    private static ModuleDefinition Module(TempDirectory dir, string name, int seconds, int priority, bool memoryHeavy,
                                           int? estimateMB = null)
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
            MemoryEstimateMB = estimateMB,
            IoWeight = memoryHeavy ? IoWeight.Heavy : IoWeight.Light,
            Processors = [new ProcessorDefinition { Executable = exe, CommandLine = args }]
        };
    }

    private static RunConfiguration Config(TempDirectory dir, List<ModuleDefinition> modules, long budgetBytes = 1) => new()
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
        MaxHeavyWorkers = 1,
        // One byte: no two memory-heavy modules fit, so they run one at a time.
        MemoryBudgetBytes = budgetBytes
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
    public async Task Memory_heavy_modules_that_fit_the_budget_run_together()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir,
        [
            Module(dir, "HeavyA", 3, priority: 90, memoryHeavy: true, estimateMB: 1000),
            Module(dir, "HeavyB", 3, priority: 91, memoryHeavy: true, estimateMB: 1000)
        ], budgetBytes: 2000L << 20));

        var heavyA = Span(report, "HeavyA");
        var heavyB = Span(report, "HeavyB");
        Assert.Equal(2000L << 20, report.MemoryBudgetBytes);
        Assert.True(heavyB.Start < heavyA.End && heavyA.Start < heavyB.End,
            $"HeavyA {heavyA} and HeavyB {heavyB} ran one after the other");
    }

    [Fact]
    public async Task The_longest_memory_heavy_module_last_time_starts_first()
    {
        using var dir = new TempDirectory();
        var modules = new List<ModuleDefinition>
        {
            Module(dir, "Short", 1, priority: 10, memoryHeavy: true),
            Module(dir, "Long", 3, priority: 90, memoryHeavy: true)
        };
        var config = Config(dir, modules);

        // The first run goes by Priority; the second knows Long took longer and starts it first.
        var first = await new RunEngine().RunAsync(config);
        Assert.True(Span(first, "Short").Start < Span(first, "Long").Start);

        var second = await new RunEngine().RunAsync(new RunConfiguration
        {
            CaseName = config.CaseName, OutputRoot = config.OutputRoot, ToolRoots = config.ToolRoots,
            Targets = config.Targets, Modules = config.Modules, MaxWorkers = 1, MaxHeavyWorkers = 1,
            MemoryBudgetBytes = 1, SkipCompleted = false
        });
        Assert.True(Span(second, "Long").Start < Span(second, "Short").Start,
            $"Long {Span(second, "Long")} started after Short {Span(second, "Short")}");
    }

    [Fact]
    public async Task The_budget_starts_what_fits_and_always_one()
    {
        var budget = new MemoryBudget(3L << 30);
        // Bigger than the whole budget, but nothing else is running.
        await budget.WaitAsync(5L << 30, CancellationToken.None);
        var small = budget.WaitAsync(1L << 30, CancellationToken.None);
        Assert.False(small.IsCompleted);

        budget.Release(5L << 30);
        await small.WaitAsync(TimeSpan.FromSeconds(5));

        // 1 GB used of 3: a 1.5 GB module fits beside it, a second 1.5 GB one does not.
        await budget.WaitAsync(3L << 29, CancellationToken.None);
        var tooBig = budget.WaitAsync(3L << 29, CancellationToken.None);
        Assert.False(tooBig.IsCompleted);
        budget.Release(1L << 30);
        await tooBig.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Without_free_memory_the_budget_runs_one_at_a_time()
    {
        var budget = new MemoryBudget(null);
        await budget.WaitAsync(1, CancellationToken.None);
        var next = budget.WaitAsync(1, CancellationToken.None);
        Assert.False(next.IsCompleted);
        budget.Release(1);
        await next.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task A_cancelled_wait_leaves_the_queue()
    {
        var budget = new MemoryBudget(1);
        await budget.WaitAsync(1, CancellationToken.None);
        using var cancel = new CancellationTokenSource();
        var waiting = budget.WaitAsync(1, cancel.Token);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);

        budget.Release(1);
        // Nothing is running or held for the cancelled wait, so the next starts at once.
        Assert.True(budget.WaitAsync(1, CancellationToken.None).IsCompletedSuccessfully);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(512L << 20, 0L)]
    [InlineData(2560L << 20, 1536L << 20)]
    [InlineData(4L << 30, 3L << 30)]
    public void The_budget_keeps_1_GB_back_for_the_other_modules(long? free, long? budget) =>
        Assert.Equal(budget, MemoryBudget.FromFree(free));

    [Fact]
    public async Task A_budget_of_nothing_still_runs_one_at_a_time()
    {
        var budget = new MemoryBudget(MemoryBudget.FromFree(512L << 20));
        await budget.WaitAsync(1, CancellationToken.None);
        var next = budget.WaitAsync(1, CancellationToken.None);
        Assert.False(next.IsCompleted);
        budget.Release(1);
        await next.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Free_memory_is_read_on_this_machine() =>
        Assert.True(MemoryBudget.Available() > 0);

    [Theory]
    [InlineData("Sigma", "Chainsaw")]
    [InlineData("Sigma", "ChainsawSrum")]
    [InlineData("Sigma", "Hayabusa")]
    [InlineData("EZTools", "MFTECmd_MFT")]
    public void The_modules_measured_at_gigabytes_are_memory_heavy_with_an_estimate(string folder, string name)
    {
        var module = Load(folder, name);
        Assert.Equal(MemoryWeight.Heavy, module.MemoryWeight);
        Assert.NotNull(module.MemoryEstimateMB);
    }

    [Fact]
    public void Durations_from_an_earlier_manifest_keep_each_modules_longest()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "manifest.json");
        File.WriteAllText(path, """
            { "Results": [ { "Module": "Chainsaw", "DurationSeconds": 175.7 },
                           { "Module": "Chainsaw", "DurationSeconds": 12.0 },
                           { "Module": "MFTECmd_MFT", "DurationSeconds": 63.6 } ] }
            """);
        var durations = RunEngine.LoadDurations(path);
        Assert.Equal(175.7, durations["chainsaw"]);
        Assert.Equal(63.6, durations["MFTECmd_MFT"]);

        File.WriteAllText(path, "not json");
        Assert.Empty(RunEngine.LoadDurations(path));
        Assert.Empty(RunEngine.LoadDurations(Path.Combine(dir.Path, "missing.json")));
    }

    [Fact]
    public void ChainsawGaps_is_not_memory_heavy_it_peaked_at_30_MB() =>
        Assert.Equal(MemoryWeight.Light, Load("Sigma", "ChainsawGaps").MemoryWeight);

    private static ModuleDefinition Load(string folder, string name)
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !Directory.Exists(Path.Combine(root, "Modules"))) root = Path.GetDirectoryName(root);
        Assert.NotNull(root);

        var modules = ModuleLoader.LoadDirectory(Path.Combine(root!, "Modules", folder));
        Assert.Empty(modules.Errors);
        return modules.Items.Single(m => m.Name == name);
    }
}
