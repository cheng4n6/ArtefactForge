using System.Diagnostics;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

public class LakeQueryAppsTests
{
    private const string Name = "CASE01 evidence lake";

    private static Func<ProcessStartInfo, string?> Answers(string? version, string? uiInstalled = "true") => start =>
        start.ArgumentList.Contains("--version") ? version : uiInstalled;

    private static string Lake(TempDirectory dir) => dir.File(Path.Combine("CASE01", "_Lake", "case.duckdb"));

    [Fact]
    public void The_chosen_duckdb_wins_then_path_then_the_winget_links_folder()
    {
        var chosen = Path.Combine("tools", "duckdb.exe");
        var onPath = Path.Combine("bin", "duckdb.exe");
        var winget = Path.Combine("local", "Microsoft", "WinGet", "Links", "duckdb.exe");
        var path = string.Join(Path.PathSeparator, "nothing", "\"bin\"");

        Assert.Equal(chosen, LakeQueryApps.FindDuckDb(chosen, path, "local", _ => true));
        Assert.Equal(onPath, LakeQueryApps.FindDuckDb(chosen, path, "local", p => p != chosen));
        Assert.Equal(winget, LakeQueryApps.FindDuckDb(null, path, "local", p => p == winget));
        Assert.Null(LakeQueryApps.FindDuckDb(null, path, "local", _ => false));
    }

    [Fact]
    public void Dbeaver_is_found_where_it_installs_for_all_users_or_one()
    {
        var perUser = Path.Combine("local", "DBeaver", "dbeaver.exe");
        Assert.Equal(perUser, LakeQueryApps.FindDBeaver(null, "pf", "local", p => p == perUser));
        Assert.Equal(Path.Combine("pf", "DBeaver", "dbeaver.exe"), LakeQueryApps.FindDBeaver(null, "pf", "local", _ => true));
        Assert.Null(LakeQueryApps.FindDBeaver(null, "pf", "local", _ => false));
    }

    [Theory]
    [InlineData("v1.4.2 (Andium) 68d7555f68", "1.4.2")]
    [InlineData("v1.5.2", "1.5.2")]
    [InlineData("1.1.3", "1.1.3")]
    [InlineData("not duckdb", null)]
    [InlineData(null, null)]
    public void The_duckdb_version_is_read_from_its_version_text(string? text, string? expected)
    {
        Assert.Equal(expected is null ? null : Version.Parse(expected), LakeQueryApps.ParseVersion(text));
    }

    [Fact]
    public void A_cli_older_than_the_duckdb_that_built_the_lake_is_turned_away_with_the_version_needed()
    {
        using var dir = new TempDirectory();

        var plan = LakeQueryApps.Plan(LakeQueryApp.DuckDbCli, Lake(dir), "v1.5.2", Name, "duckdb.exe", null, Answers("v1.4.3 abc"));

        Assert.Null(plan.Start);
        Assert.Equal(LakeQueryFix.Locate, plan.Fix);
        Assert.Contains("1.5 or later", plan.Problem);
    }

    [Fact]
    public void A_cli_of_the_same_minor_version_opens_the_lake_read_only()
    {
        using var dir = new TempDirectory();
        var lake = Lake(dir);

        var plan = LakeQueryApps.Plan(LakeQueryApp.DuckDbCli, lake, "v1.5.2", Name, "duckdb.exe", null, Answers("v1.5.0"));

        Assert.NotNull(plan.Start);
        Assert.Equal(["-readonly", lake], plan.Start.ArgumentList);
        Assert.Equal(Path.GetDirectoryName(lake), plan.Start.WorkingDirectory);
    }

    [Fact]
    public void Something_that_reports_no_version_is_not_taken_for_the_duckdb_cli()
    {
        using var dir = new TempDirectory();

        var plan = LakeQueryApps.Plan(LakeQueryApp.DuckDbCli, Lake(dir), null, Name, "duckdb.exe", null, Answers(null));

        Assert.Null(plan.Start);
        Assert.Equal(LakeQueryFix.Locate, plan.Fix);
    }

    [Fact]
    public void No_cli_found_says_how_to_get_one()
    {
        using var dir = new TempDirectory();

        var plan = LakeQueryApps.Plan(LakeQueryApp.DuckDbUi, Lake(dir), null, Name, null, null, Answers("v1.5.0"));

        Assert.Equal(LakeQueryFix.Locate, plan.Fix);
        Assert.Contains("winget install DuckDB.cli", plan.Problem);
    }

    [Fact]
    public void The_web_ui_needs_a_cli_that_has_it_and_its_extension_installed()
    {
        using var dir = new TempDirectory();
        var lake = Lake(dir);

        var old = LakeQueryApps.Plan(LakeQueryApp.DuckDbUi, lake, null, Name, "duckdb.exe", null, Answers("v1.1.3"));
        var missing = LakeQueryApps.Plan(LakeQueryApp.DuckDbUi, lake, null, Name, "duckdb.exe", null, Answers("v1.5.0", "false"));
        var ready = LakeQueryApps.Plan(LakeQueryApp.DuckDbUi, lake, null, Name, "duckdb.exe", null, Answers("v1.5.0"));

        Assert.Contains("1.2.1 or later", old.Problem);
        Assert.Equal(LakeQueryFix.InstallUi, missing.Fix);
        Assert.Equal("duckdb.exe", missing.Program);
        Assert.Equal(["-readonly", lake, "-ui"], ready.Start!.ArgumentList);
    }

    [Fact]
    public void Dbeaver_gets_a_read_only_duckdb_connection_to_the_lake()
    {
        using var dir = new TempDirectory();
        var lake = Lake(dir);

        var plan = LakeQueryApps.Plan(LakeQueryApp.DBeaver, lake, null, "A|B=C", null, "dbeaver.exe", _ => throw new InvalidOperationException());

        Assert.Equal("-con", plan.Start!.ArgumentList[0]);
        var con = plan.Start.ArgumentList[1].Split('|');
        Assert.Contains("driver=duckdb", con);
        Assert.Contains("url=jdbc:duckdb:" + lake, con);
        Assert.Contains("prop.duckdb.read_only=true", con);
        Assert.Contains("name=A B C", con);
    }

    [Fact]
    public void No_lake_file_means_nothing_is_started_whatever_is_installed()
    {
        using var dir = new TempDirectory();

        var plan = LakeQueryApps.Plan(LakeQueryApp.DuckDbCli, Path.Combine(dir.Path, "case.duckdb"), null, Name,
            "duckdb.exe", "dbeaver.exe", Answers("v1.5.0"));

        Assert.Null(plan.Start);
        Assert.Equal(LakeQueryFix.None, plan.Fix);
    }
}
