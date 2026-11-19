using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// RequiresAny: globs of which one must resolve, for an artefact a system keeps in more than one
/// place, alongside Requires, all of which must. Made-up roots and modules.
/// </summary>
public class RequiresAnyTests
{
    private static ModuleDefinition Module(string name, IReadOnlyList<string>? requires = null, IReadOnlyList<string>? any = null,
                                           IterationMode iterate = IterationMode.None) => new()
    {
        Description = name,
        Category = "Test",
        SourcePath = Path.Combine("modules", name + ".forge"),
        Platform = Platform.Windows,
        Requires = requires ?? [],
        RequiresAny = any ?? [],
        Iterate = iterate,
        Processors = [new ProcessorDefinition { Executable = "tool.exe", CommandLine = "x" }]
    };

    private static ResolvedTarget Target(TempDirectory dir) => new()
    {
        SelectionPath = dir.Dir("HOST01"),
        Root = dir.Dir("HOST01"),
        CollectionName = "HOST01",
        Layout = new LayoutProfile
        {
            Id = "t", Name = "t", Platform = Platform.Windows,
            Detect = new LayoutDetectRules { RootIsSelection = true, Markers = ["x"] },
            Resolve = new LayoutResolveRules { UserProfiles = [@"Users\*"] }
        }
    };

    private static RunPlan Plan(TempDirectory dir, params ModuleDefinition[] modules) =>
        RunPlanner.Build(new RunConfiguration
        {
            CaseName = "CASE",
            OutputRoot = dir.Dir("out"),
            ToolRoots = [dir.Path],
            Targets = [Target(dir)],
            Modules = modules,
            MaxWorkers = 1,
            MaxHeavyWorkers = 1
        });

    private static readonly string[] IisFolders =
        [@"%root%\inetpub\logs\LogFiles", @"%root%\Windows\System32\LogFiles\W3SVC*"];

    [Theory]
    [InlineData(@"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log")]
    [InlineData(@"Windows\System32\LogFiles\W3SVC1\ex260316.log")]
    public void One_of_the_places_is_enough(string file)
    {
        using var dir = new TempDirectory();
        dir.File(Path.Combine("HOST01", file));

        var plan = Plan(dir, Module("Iis", any: IisFolders));

        Assert.Equal("Iis", Assert.Single(plan.Items).Module.Name);
        Assert.Empty(plan.Skipped);
    }

    [Fact]
    public void With_none_of_them_the_skip_names_every_place_looked_in()
    {
        using var dir = new TempDirectory();
        dir.Dir("HOST01");

        var plan = Plan(dir, Module("Iis", any: IisFolders));

        Assert.Empty(plan.Items);
        Assert.Equal(@"not present: none of %root%\inetpub\logs\LogFiles, %root%\Windows\System32\LogFiles\W3SVC*",
                     Assert.Single(plan.Skipped).Reason);
    }

    [Fact]
    public void Requires_still_has_to_resolve_in_full_and_is_named_first()
    {
        using var dir = new TempDirectory();
        dir.File(Path.Combine("HOST01", @"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log"));
        var config = @"%root%\Windows\System32\inetsrv\config\applicationHost.config";

        var without = Plan(dir, Module("Iis", requires: [config], any: IisFolders));
        Assert.Equal($"not present: {config}", Assert.Single(without.Skipped).Reason);

        dir.File(Path.Combine("HOST01", @"Windows\System32\inetsrv\config\applicationHost.config"));
        Assert.Single(Plan(dir, Module("Iis", requires: [config], any: IisFolders)).Items);
    }

    [Fact]
    public void A_single_place_reads_as_a_plain_requirement()
    {
        using var dir = new TempDirectory();
        dir.Dir("HOST01");

        var plan = Plan(dir, Module("One", any: [@"%root%\x.log"]));

        Assert.Equal(@"not present: %root%\x.log", Assert.Single(plan.Skipped).Reason);
    }

    [Fact]
    public void Per_user_modules_check_it_for_each_profile()
    {
        using var dir = new TempDirectory();
        dir.File(Path.Combine("HOST01", @"Users\alice\AppData\Local\Old\history.db"));
        dir.File(Path.Combine("HOST01", @"Users\bob\AppData\Roaming\New\history.db"));
        dir.Dir(Path.Combine("HOST01", @"Users\carol"));

        var plan = Plan(dir, Module("History", any: [@"%userHome%\AppData\Local\Old\history.db", @"%userHome%\AppData\Roaming\New\history.db"],
                                    iterate: IterationMode.UserProfile));

        Assert.Equal(["alice", "bob"], plan.Items.Select(i => i.IterationKey).Order());
    }

    [Fact]
    public void Per_match_modules_iterate_the_first_Requires_glob_only_when_one_of_the_others_resolves()
    {
        using var dir = new TempDirectory();
        dir.File(Path.Combine("HOST01", @"Logs\a.log"));
        dir.File(Path.Combine("HOST01", @"Logs\b.log"));
        var module = Module("PerFile", requires: [@"%root%\Logs\*.log"], any: [@"%root%\Config\one.xml", @"%root%\Config\two.xml"],
                            iterate: IterationMode.Match);

        Assert.Contains("none of", Assert.Single(Plan(dir, module).Skipped).Reason);

        dir.File(Path.Combine("HOST01", @"Config\two.xml"));
        Assert.Equal(2, Plan(dir, module).Items.Count);
    }

    [Fact]
    public void The_module_file_key_is_RequiresAny_and_a_module_without_it_is_unchanged()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "Iis.forge");
        File.WriteAllText(path,
            "Description: test\nCategory: WebLogs\nRequiresAny:\n  - '%root%\\inetpub\\logs\\LogFiles'\n  - '%root%\\Windows\\System32\\LogFiles\\W3SVC*'\n"
            + "Processors:\n  -\n    Executable: builtin:WindowsDhcpServerLog\n    CommandLine: --root \"%root%\" --out \"%destinationDirectory%\"\n");
        Assert.Equal(IisFolders, ModuleLoader.LoadFile(path).RequiresAny);

        File.WriteAllText(path, "Description: test\nRequires: ['%root%\\x']\nProcessors:\n  -\n    Executable: tool.exe\n    CommandLine: x\n");
        Assert.Empty(ModuleLoader.LoadFile(path).RequiresAny);
    }
}
