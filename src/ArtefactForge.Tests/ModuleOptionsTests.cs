using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Options let an analyst tune a module without editing it. Only declared options can be set, so a
/// typo cannot quietly produce a command line that parses nothing - the failure mode this whole
/// tool is built to avoid.
/// </summary>
public class ModuleOptionsTests
{
    private static ModuleDefinition Module(params ModuleOption[] options) => new()
    {
        SourcePath = @"C:\modules\Hayabusa.forge",
        Options = options,
        Processors = [new ProcessorDefinition { Executable = "x.exe", CommandLine = "run %options%" }]
    };

    private static ModuleOption Flag(string name, bool on, string expand) =>
        new() { Name = name, Kind = OptionKind.Flag, Default = on ? "true" : "false", Expand = expand };

    private static ModuleOption Choice(string name, string def, string expand, params string[] choices) =>
        new() { Name = name, Kind = OptionKind.Choice, Default = def, Expand = expand, Choices = choices };

    [Fact]
    public void Defaults_expand_with_no_overrides()
    {
        var module = Module(
            Choice("Profile", "verbose", "-p %value%", "standard", "verbose"),
            Flag("NoSummary", true, "-N"),
            Flag("Carve", false, "-x"));

        Assert.Equal("-p verbose -N", ModuleOptions.Expand(module));
    }

    [Fact]
    public void Options_keep_declaration_order()
    {
        // A stable command line is diffable between runs, and readable in the manifest.
        var module = Module(Flag("A", true, "-a"), Flag("B", true, "-b"), Flag("C", true, "-c"));
        Assert.Equal("-a -b -c", ModuleOptions.Expand(module));
    }

    [Fact]
    public void An_override_replaces_the_default()
    {
        var module = Module(Choice("MinLevel", "informational", "-m %value%", "informational", "high"));
        var result = ModuleOptions.Expand(module, new Dictionary<string, string> { ["MinLevel"] = "high" });
        Assert.Equal("-m high", result);
    }

    [Fact]
    public void A_flag_turned_off_contributes_nothing()
    {
        var module = Module(Flag("NoSummary", true, "-N"));
        Assert.Equal("", ModuleOptions.Expand(module, new Dictionary<string, string> { ["NoSummary"] = "false" }));
    }

    [Fact]
    public void An_empty_choice_contributes_nothing()
    {
        // How Chainsaw's Status and Level are left unset: no flag at all, rather than an empty one.
        var module = Module(Choice("Status", "", "--status %value%", "", "stable"));
        Assert.Equal("", ModuleOptions.Expand(module));
    }

    [Fact]
    public void Text_options_pass_through_verbatim()
    {
        var module = Module(new ModuleOption { Name = "Extra", Kind = OptionKind.Text, Expand = "%value%" });
        var result = ModuleOptions.Expand(module, new Dictionary<string, string> { ["Extra"] = "--threads 4" });
        Assert.Equal("--threads 4", result);
    }

    [Fact]
    public void An_override_for_an_undeclared_option_is_ignored_by_Expand()
    {
        // Expand is not the gate - TryValidate is. Expand must not invent flags from stray keys.
        var module = Module(Flag("NoSummary", true, "-N"));
        var result = ModuleOptions.Expand(module, new Dictionary<string, string> { ["Nonsense"] = "true" });
        Assert.Equal("-N", result);
    }

    [Fact]
    public void Unknown_option_names_are_rejected_with_the_known_ones_listed()
    {
        var module = Module(Flag("NoSummary", true, "-N"));
        Assert.False(ModuleOptions.TryValidate(module, "Nonsense", "true", out var error));
        Assert.Contains("no option 'Nonsense'", error);
        Assert.Contains("NoSummary", error);
    }

    [Fact]
    public void A_value_outside_the_declared_choices_is_rejected()
    {
        var module = Module(Choice("Profile", "verbose", "-p %value%", "standard", "verbose"));
        Assert.False(ModuleOptions.TryValidate(module, "Profile", "gorgeous", out var error));
        Assert.Contains("must be one of", error);
    }

    [Fact]
    public void A_flag_given_a_non_boolean_is_rejected()
    {
        var module = Module(Flag("Sort", false, "-s"));
        Assert.False(ModuleOptions.TryValidate(module, "Sort", "maybe", out var error));
        Assert.Contains("use true or false", error);
    }

    [Theory]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData("yes")]
    [InlineData("1")]
    [InlineData("false")]
    [InlineData("no")]
    [InlineData("0")]
    public void Boolean_spellings_are_accepted(string value)
    {
        var module = Module(Flag("Sort", false, "-s"));
        Assert.True(ModuleOptions.TryValidate(module, "Sort", value, out _));
    }

    [Fact]
    public void Option_names_are_matched_case_insensitively()
    {
        var module = Module(Flag("NoSummary", false, "-N"));
        Assert.True(ModuleOptions.TryValidate(module, "nosummary", "true", out _));
        Assert.Equal("-N", ModuleOptions.Expand(module, new Dictionary<string, string> { ["NOSUMMARY"] = "true" }));
    }

    [Fact]
    public void Effective_values_report_what_will_actually_be_used()
    {
        // What a settings UI binds to.
        var module = Module(Choice("Profile", "verbose", "-p %value%", "standard", "verbose"), Flag("Sort", false, "-s"));
        var effective = ModuleOptions.Effective(module, new Dictionary<string, string> { ["Sort"] = "true" });

        Assert.Equal("verbose", effective["Profile"]);
        Assert.Equal("true", effective["Sort"]);
    }
}
