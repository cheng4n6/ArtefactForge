using ArtefactForge.Core;

namespace ArtefactForge.Tests;

public class ToolRootsTests
{
    [Fact]
    public void Tool_roots_are_the_package_tools_then_a_sibling_ez_tools_then_the_analysts_roots()
    {
        using var dir = new TempDirectory();
        var app = dir.Dir("ArtefactForge");
        var sibling = dir.Dir("EZ-Tools");
        var extra = dir.Dir(Path.Combine("cases", "tools"));

        var roots = ToolInventory.Roots(app, [extra]);

        Assert.Equal(new[] { Path.Combine(app, "Tools"), sibling, extra }, roots.ToArray());
    }

    [Fact]
    public void A_tool_kept_in_an_added_root_is_found_by_the_tool_check()
    {
        // The tools command checked only Tools\ and EZ-Tools\, so it listed tools kept elsewhere
        // as missing although a run with the same --tools found and used them.
        using var dir = new TempDirectory();
        var app = dir.Dir("ArtefactForge");
        var extra = dir.Dir("elsewhere");
        dir.File(Path.Combine("elsewhere", "parser", "Parser.exe"));
        var module = new ModuleDefinition
        {
            Description = "Parser",
            Category = "Test",
            SourcePath = @"C:\modules\Parser.forge",
            Processors = [new ProcessorDefinition { Executable = @"parser\Parser.exe", CommandLine = "" }]
        };

        var tool = Assert.Single(ToolInventory.Scan([module], ToolInventory.Roots(app, [extra])));

        Assert.True(tool.Found);
        Assert.Equal(extra, tool.ToolRoot);
    }
}
