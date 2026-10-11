using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Each collection gets the modules for what it is - Windows or Linux, live or collected - and the
/// rest are reported once per collection rather than one skip line per module.
/// </summary>
public class RunPlannerPlatformTests
{
    private static ModuleDefinition Module(string name, Platform platform, TargetScope scope = TargetScope.Any) => new()
    {
        Description = name,
        Category = "Test",
        SourcePath = Path.Combine("modules", name + ".forge"),
        Platform = platform,
        Scope = scope,
        Processors = [new ProcessorDefinition { Executable = "tool.exe", CommandLine = "x" }]
    };

    private static ResolvedTarget Target(TempDirectory dir, string name, Platform platform, bool live = false) => new()
    {
        SelectionPath = dir.Dir(name),
        Root = dir.Dir(name),
        CollectionName = name,
        IsLive = live,
        Layout = new LayoutProfile
        {
            Id = name, Name = name, Platform = platform,
            Detect = new LayoutDetectRules { RootIsSelection = true, Markers = ["x"] },
            Resolve = new LayoutResolveRules()
        }
    };

    private static RunPlan Plan(TempDirectory dir, ResolvedTarget[] targets, ModuleDefinition[] modules) =>
        RunPlanner.Build(new RunConfiguration
        {
            CaseName = "CASE",
            OutputRoot = dir.Dir("out"),
            ToolRoots = [dir.Path],
            Targets = targets,
            Modules = modules,
            MaxWorkers = 1,
            MaxHeavyWorkers = 1
        });

    private static readonly ModuleDefinition[] Modules =
    [
        Module("WinA", Platform.Windows),
        Module("WinB", Platform.Windows),
        Module("WinLive", Platform.Windows, TargetScope.LiveOnly),
        Module("LinA", Platform.Linux),
        Module("Either", Platform.Any)
    ];

    [Fact]
    public void A_mixed_batch_plans_each_collection_for_what_it_is()
    {
        using var dir = new TempDirectory();
        var plan = Plan(dir, [Target(dir, "WKSTN", Platform.Windows), Target(dir, "web01", Platform.Linux)], Modules);

        string Planned(string collection) => string.Join(",", plan.Items
            .Where(i => i.Target.CollectionName == collection).Select(i => i.Module.Name).OrderBy(n => n));

        Assert.Equal("Either,WinA,WinB", Planned("WKSTN"));
        Assert.Equal("Either,LinA", Planned("web01"));
    }

    [Fact]
    public void What_does_not_apply_is_one_line_per_collection_naming_every_module()
    {
        using var dir = new TempDirectory();
        var plan = Plan(dir, [Target(dir, "WKSTN", Platform.Windows), Target(dir, "web01", Platform.Linux)], Modules);

        Assert.Equal(2, plan.Skipped.Count);
        var windows = plan.Skipped.Single(s => s.Collection == "WKSTN");
        Assert.Equal("2 module(s)", windows.Module);
        Assert.Contains("Windows, collected", windows.Reason);
        Assert.Contains("WinLive", windows.Reason);
        Assert.Contains("LinA", windows.Reason);

        var linux = plan.Skipped.Single(s => s.Collection == "web01");
        Assert.Equal("3 module(s)", linux.Module);
    }

    [Fact]
    public void A_live_target_gets_the_live_modules()
    {
        using var dir = new TempDirectory();
        var plan = Plan(dir, [Target(dir, "LIVE", Platform.Windows, live: true)], Modules);
        Assert.Contains(plan.Items, i => i.Module.Name == "WinLive");
    }

    [Fact]
    public void A_layout_that_names_no_platform_filters_nothing_by_platform()
    {
        using var dir = new TempDirectory();
        var plan = Plan(dir, [Target(dir, "unknown", Platform.Any)], Modules);

        Assert.Equal(4, plan.Items.Count);      // everything except the live-only module
        Assert.Contains("WinLive", Assert.Single(plan.Skipped).Reason);
    }

    [Fact]
    public void Real_skips_keep_their_own_line()
    {
        using var dir = new TempDirectory();
        var needs = new ModuleDefinition
        {
            Description = "needs", Category = "Test", SourcePath = Path.Combine("m", "Needs.forge"),
            Platform = Platform.Linux, Requires = ["%root%/var/log/secure"],
            Processors = [new ProcessorDefinition { Executable = "t", CommandLine = "x" }]
        };
        var plan = Plan(dir, [Target(dir, "web01", Platform.Linux)], [needs]);

        var skip = Assert.Single(plan.Skipped);
        Assert.Equal("Needs", skip.Module);
        Assert.Contains("not present", skip.Reason);
    }

    [Fact]
    public void Shipped_layouts_declare_their_platform()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !Directory.Exists(Path.Combine(root, "Layouts"))) root = Path.GetDirectoryName(root);
        Assert.NotNull(root);

        var layouts = LayoutLoader.LoadDirectory(Path.Combine(root!, "Layouts")).Items.ToDictionary(l => l.Id);
        Assert.Equal(Platform.Windows, layouts["mounted-drive"].Platform);
        Assert.Equal(Platform.Windows, layouts["collection-folder"].Platform);
        Assert.Equal(Platform.Linux, layouts["linux-root"].Platform);
    }
}
