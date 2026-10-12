using System.Diagnostics;
using ArtefactForge.Core;
using Xunit;

namespace ArtefactForge.Tests;

public class ToolVersionTests
{
    [Theory]
    [InlineData("chainsaw 2.16.5\r\n", "2.16.5")]
    [InlineData("Hayabusa v4.1.0 - Dev Build", "4.1.0")]
    [InlineData("tool 1.2.3.4", "1.2.3.4")]
    [InlineData("no number here", null)]
    public void The_first_version_number_in_a_tools_output_is_its_version(string output, string? expected)
    {
        Assert.Equal(expected, ToolVersion.Parse(output));
    }

    [Fact]
    public void A_tool_that_prints_its_version_is_asked_for_it()
    {
        // chainsaw.exe has no version resource, so it is asked with --version.
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");

        Assert.Equal("2.16.5", ToolVersion.FromOutput(cmd, "/c echo chainsaw 2.16.5"));
    }

    [Fact]
    public void A_tool_copied_in_without_VERSIONS_txt_still_has_a_version()
    {
        // Users supply their own Hayabusa and Chainsaw, and the package has no VERSIONS.txt, so
        // the update check said the installed version was unknown. The executable is asked instead.
        using var temp = new TempDirectory();
        var tools = temp.Dir("Tools");
        var exe = Path.Combine(temp.Dir(@"Tools\hayabusa"), "hayabusa.exe");
        File.Copy(Environment.ProcessPath!, exe);

        var expected = FileVersionInfo.GetVersionInfo(exe).FileVersion;
        Assert.False(string.IsNullOrEmpty(expected));
        Assert.Equal(expected, ToolInventory.InstalledVersion(tools, "hayabusa"));
    }

    [Fact]
    public void A_tool_that_cannot_be_asked_falls_back_to_VERSIONS_txt()
    {
        using var temp = new TempDirectory();
        var tools = temp.Dir("Tools");
        File.WriteAllText(Path.Combine(temp.Dir(@"Tools\chainsaw"), "chainsaw.exe"), "not a program");
        File.WriteAllText(Path.Combine(tools, ToolUpdater.VersionsFile),
            "chainsaw.exe   v2.16.3 (chainsaw_x86_64-pc-windows-msvc.exe)\r\n");

        Assert.Equal("2.16.3", ToolInventory.InstalledVersion(tools, "chainsaw"));
    }

    [Fact]
    public void A_tool_with_neither_has_no_version()
    {
        using var temp = new TempDirectory();
        var tools = temp.Dir("Tools");
        File.WriteAllText(Path.Combine(temp.Dir(@"Tools\chainsaw"), "chainsaw.exe"), "not a program");

        Assert.Null(ToolInventory.InstalledVersion(tools, "chainsaw"));
    }
}
