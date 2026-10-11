using ArtefactForge.Core;

namespace ArtefactForge.Tests;

public class PlaceholdersTests
{
    private static PlaceholderContext Context(bool vss = false, string? user = null, string? match = null,
                                              string root = @"D:\Evidence\C") => new()
    {
        Root = root,
        DestinationDirectory = @"D:\Cases\HOST01\Registry",
        ToolsDir = @"D:\AF\Tools",
        CaseName = "HOST01",
        CollectionName = "CyLR-HOST01",
        ModuleName = "RECmd_NTUSER",
        User = user,
        Match = match,
        VssEnabled = vss
    };

    [Fact]
    public void Expands_root_and_destination()
    {
        var result = Placeholders.Resolve(@"-d ""%root%\Windows"" --csv ""%destinationDirectory%""", Context());
        Assert.Equal(@"-d ""D:\Evidence\C\Windows"" --csv ""D:\Cases\HOST01\Registry""", result);
    }

    [Fact]
    public void SourceDirectory_is_an_alias_for_root_so_stock_mkape_files_work()
    {
        Assert.Equal(@"D:\Evidence\C", Placeholders.Resolve("%sourceDirectory%", Context()));
    }

    [Fact]
    public void Placeholder_names_are_case_insensitive()
    {
        Assert.Equal(@"D:\Evidence\C", Placeholders.Resolve("%RooT%", Context()));
    }

    [Fact]
    public void Expands_the_user()
    {
        var result = Placeholders.Resolve(@"-f ""%root%\Users\%user%\NTUSER.DAT""", Context(user: "jbloggs"));
        Assert.Equal(@"-f ""D:\Evidence\C\Users\jbloggs\NTUSER.DAT""", result);
    }

    [Fact]
    public void Expands_match_and_its_parts()
    {
        var ctx = Context(match: @"D:\Evidence\C\Users\alice\AppData\Local\CDP\L.alice\ActivitiesCache.db");
        Assert.Equal("ActivitiesCache.db", Placeholders.Resolve("%matchName%", ctx));
        Assert.Equal(@"D:\Evidence\C\Users\alice\AppData\Local\CDP\L.alice", Placeholders.Resolve("%matchDir%", ctx));
    }

    [Fact]
    public void Vss_expands_when_enabled()
    {
        Assert.Equal("-f x --vss", Placeholders.Resolve("-f x %vss%", Context(vss: true)));
    }

    [Fact]
    public void Vss_leaves_no_trailing_or_double_space_when_disabled()
    {
        // %vss% sits unconditionally in every command line, so a disabled one must vanish cleanly.
        Assert.Equal("-f x", Placeholders.Resolve("-f x %vss%", Context()));
        Assert.Equal("-f x --csv y", Placeholders.Resolve("-f x %vss% --csv y", Context()));
    }

    [Fact]
    public void Does_not_mangle_a_path_containing_consecutive_spaces()
    {
        // Collapsing runs of spaces globally would corrupt any evidence path with a double space.
        var ctx = Context(root: @"D:\Evidence\Case  001\C");
        var result = Placeholders.Resolve(@"-d ""%root%\Windows"" %vss%", ctx);
        Assert.Equal(@"-d ""D:\Evidence\Case  001\C\Windows""", result);
    }

    [Fact]
    public void Unknown_placeholders_are_left_alone()
    {
        // Better a visibly wrong command line than a silently truncated one.
        Assert.Equal("%notAThing%", Placeholders.Resolve("%notAThing%", Context()));
    }

    [Fact]
    public void A_lone_percent_is_not_treated_as_a_placeholder()
    {
        Assert.Equal("50% done", Placeholders.Resolve("50% done", Context()));
    }

    [Fact]
    public void Absent_user_and_match_expand_to_nothing()
    {
        Assert.Equal("", Placeholders.Resolve("%user%%match%", Context()));
    }
}
