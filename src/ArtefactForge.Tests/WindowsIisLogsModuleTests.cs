using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// When the shipped WindowsIisLogs module runs: any one of the places an IIS server keeps its logs
/// or its configuration, but not HTTPERR alone, which every Windows host has. Made-up roots.
/// </summary>
public class WindowsIisLogsModuleTests
{
    private static ModuleDefinition Shipped()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !Directory.Exists(Path.Combine(root, "Modules"))) root = Path.GetDirectoryName(root);
        Assert.NotNull(root);
        var modules = ModuleLoader.LoadDirectory(Path.Combine(root!, "Modules", "Windows"));
        Assert.Empty(modules.Errors);
        return modules.Items.Single(m => m.Name == "WindowsIisLogs");
    }

    private static RunPlan Plan(TempDirectory dir) =>
        RunPlanner.Build(new RunConfiguration
        {
            CaseName = "CASE",
            OutputRoot = dir.Dir("out"),
            ToolRoots = [dir.Path],
            Targets =
            [
                new ResolvedTarget
                {
                    SelectionPath = dir.Dir("WEB01"), Root = dir.Dir("WEB01"), CollectionName = "WEB01",
                    Layout = new LayoutProfile
                    {
                        Id = "t", Name = "t", Platform = Platform.Windows,
                        Detect = new LayoutDetectRules { RootIsSelection = true, Markers = ["x"] },
                        Resolve = new LayoutResolveRules()
                    }
                }
            ],
            Modules = [Shipped()],
            MaxWorkers = 1,
            MaxHeavyWorkers = 1
        });

    [Theory]
    [InlineData(@"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log")]
    [InlineData(@"Windows\System32\LogFiles\W3SVC1\ex260316.log")]
    [InlineData(@"Windows\System32\LogFiles\FTPSVC2\u_ex260316.log")]
    [InlineData(@"Windows\System32\inetsrv\config\applicationHost.config")]
    public void Any_one_place_an_IIS_server_keeps_its_logs_or_configuration_runs_the_module(string file)
    {
        using var dir = new TempDirectory();
        dir.File(Path.Combine("WEB01", file));

        var plan = Plan(dir);

        Assert.Equal("WindowsIisLogs", Assert.Single(plan.Items).Module.Name);
        Assert.Empty(plan.Skipped);
    }

    [Fact]
    public void HTTPERR_alone_does_not_run_it_and_the_skip_names_every_place_looked_in()
    {
        using var dir = new TempDirectory();
        dir.File(Path.Combine("WEB01", @"Windows\System32\LogFiles\HTTPERR\httperr1.log"));

        var plan = Plan(dir);

        Assert.Empty(plan.Items);
        var reason = Assert.Single(plan.Skipped).Reason;
        Assert.StartsWith("not present: none of ", reason);
        Assert.Contains(@"inetpub\logs\LogFiles", reason);
        Assert.Contains(@"System32\LogFiles\W3SVC*", reason);
        Assert.Contains("applicationHost.config", reason);
    }
}
