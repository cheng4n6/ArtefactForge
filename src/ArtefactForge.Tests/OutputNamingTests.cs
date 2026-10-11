using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Every case here is a real filename observed coming out of a tool during the build. Getting
/// these wrong does not throw - it silently mislabels evidence or overwrites one user's output
/// with another's, which is why they are pinned.
/// </summary>
public class OutputNamingTests
{
    [Fact]
    public void Prefixes_the_tool_name_when_absent()
    {
        Assert.Equal("EvtxECmd_EventLogs.csv", OutputNaming.Build("EventLogs.csv", "EvtxECmd", null));
    }

    [Fact]
    public void Strips_a_leading_tool_timestamp()
    {
        // AmcacheParser writes 20260819002514_Amcache_ProgramEntries.csv
        Assert.Equal("Amcache_ProgramEntries.csv",
            OutputNaming.Build("20260819002514_Amcache_ProgramEntries.csv", "Amcache", null));
    }

    [Fact]
    public void Strips_SQLECmds_twenty_digit_timestamp()
    {
        // SQLECmd stamps yyyyMMddHHmmssffffff, six digits longer than the other EZ Tools
        Assert.Equal("SQLECmd_ChromiumBrowser_HistoryVisits_Default_History.csv",
            OutputNaming.Build("20260819002514123456_ChromiumBrowser_HistoryVisits_Default_History.csv",
                "SQLECmd", null));
    }

    [Fact]
    public void Does_not_prefix_twice_when_the_name_already_identifies_the_tool()
    {
        // SrumECmd writes 20260818232832_SrumECmd_NetworkUsages_Output.csv
        Assert.Equal("SrumECmd_NetworkUsages_Output.csv",
            OutputNaming.Build("20260818232832_SrumECmd_NetworkUsages_Output.csv", "SrumECmd", null));
    }

    [Fact]
    public void Leaves_a_name_alone_when_the_tool_name_appears_mid_string()
    {
        // SBECmd writes !SBECmd_Messages.txt - the leading '!' keeps it at the top of the folder.
        Assert.Equal("!SBECmd_Messages.txt", OutputNaming.Build("!SBECmd_Messages.txt", "SBECmd", null));
    }

    [Fact]
    public void Puts_the_user_first()
    {
        Assert.Equal("jbloggs_JLECmd_AutomaticDestinations.csv",
            OutputNaming.Build("20260818232521_AutomaticDestinations.csv", "JLECmd", "jbloggs"));
    }

    [Fact]
    public void Strips_a_username_the_tool_embedded_itself()
    {
        // WxTCmd writes 20260819002531_User_Activity.csv - timestamp AND username.
        // Without stripping, this becomes User_WxTCmd_User_Activity.csv.
        Assert.Equal("User_WxTCmd_Activity.csv",
            OutputNaming.Build("20260819002531_User_Activity.csv", "WxTCmd", "User"));
    }

    [Fact]
    public void Matches_the_embedded_username_case_insensitively()
    {
        Assert.Equal("User_WxTCmd_Activity.csv",
            OutputNaming.Build("20260819002531_user_Activity.csv", "WxTCmd", "User"));
    }

    [Fact]
    public void Preserves_a_non_csv_extension()
    {
        Assert.Equal("Chainsaw_findings.json", OutputNaming.Build("findings.json", "Chainsaw", null));
    }

    [Fact]
    public void Handles_a_name_that_is_nothing_but_a_timestamp()
    {
        // Degenerate, but it must not produce a dangling separator or an extension-only filename.
        Assert.Equal("Tool.csv", OutputNaming.Build("20260819002514_.csv", "Tool", null));
    }

    [Fact]
    public void Deduplicate_returns_the_name_unchanged_when_free()
    {
        using var dir = new TempDirectory();
        Assert.Equal("a.csv", OutputNaming.Deduplicate(dir.Path, "a.csv"));
    }

    [Fact]
    public void Deduplicate_walks_past_names_already_taken()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(Path.Combine(dir.Path, "a.csv"), "");
        Assert.Equal("a_2.csv", OutputNaming.Deduplicate(dir.Path, "a.csv"));

        File.WriteAllText(Path.Combine(dir.Path, "a_2.csv"), "");
        Assert.Equal("a_3.csv", OutputNaming.Deduplicate(dir.Path, "a.csv"));
    }
}
