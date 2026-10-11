using ArtefactForge.Core;

namespace ArtefactForge.Tests;

public class AppCatalogTests
{
    private static string Write(TempDirectory dir, string yaml)
    {
        var path = Path.Combine(dir.Path, AppCatalog.FileName);
        File.WriteAllText(path, yaml);
        return path;
    }

    [Fact]
    public void Apps_resolve_through_the_tool_roots_in_file_order()
    {
        using var dir = new TempDirectory();
        var tools = dir.Dir("Tools");
        var second = dir.Dir("EZ-Tools");
        dir.File(Path.Combine("EZ-Tools", "viewer", "Viewer.exe"));
        dir.File(Path.Combine("Tools", "tle", "Tle.exe"));
        var path = Write(dir, """
            Apps:
              -
                Name: Second
                Description: found in the second root
                Executable: viewer/Viewer.exe
              -
                Name: First
                Executable: tle/Tle.exe
            """);

        var result = AppCatalog.Load(path, [tools, second]);

        Assert.Null(result.Error);
        Assert.Equal(new[] { "Second", "First" }, result.Apps.Select(a => a.Name).ToArray());
        Assert.Equal(Path.Combine(second, "viewer/Viewer.exe"), result.Apps[0].ResolvedPath);
        Assert.Equal("found in the second root", result.Apps[0].Description);
        Assert.True(result.Apps[1].Found);
    }

    [Fact]
    public void A_missing_app_stays_listed_with_the_path_checked()
    {
        using var dir = new TempDirectory();
        var tools = dir.Dir("Tools");
        var path = Write(dir, "Apps:\n  - Name: Ghost\n    Executable: ghost/Ghost.exe\n");

        var app = Assert.Single(AppCatalog.Load(path, [tools]).Apps);
        Assert.False(app.Found);
        Assert.Equal(Path.Combine(tools, "ghost/Ghost.exe"), app.LookedFor);
    }

    [Fact]
    public void A_full_path_is_used_as_is()
    {
        using var dir = new TempDirectory();
        var exe = dir.File(Path.Combine("Program Files", "Db", "Db.exe"));
        var path = Write(dir, $"Apps:\n  - Name: Db\n    Executable: '{exe}'\n");

        Assert.Equal(exe, Assert.Single(AppCatalog.Load(path, [dir.Dir("Tools")]).Apps).ResolvedPath);
    }

    [Fact]
    public void An_entry_without_an_executable_is_shown_as_a_problem_not_dropped()
    {
        using var dir = new TempDirectory();
        var path = Write(dir, "Apps:\n  - Name: Half written\n");

        var app = Assert.Single(AppCatalog.Load(path, [dir.Dir("Tools")]).Apps);
        Assert.False(app.Found);
        Assert.Contains("no Executable", app.Description);
    }

    [Fact]
    public void Malformed_yaml_is_reported_not_thrown()
    {
        using var dir = new TempDirectory();
        var path = Write(dir, "Apps:\n  - Name: [unclosed\n");

        var result = AppCatalog.Load(path, [dir.Dir("Tools")]);
        Assert.NotNull(result.Error);
        Assert.Contains(AppCatalog.FileName, result.Error);
        Assert.Empty(result.Apps);
    }

    [Fact]
    public void A_missing_file_is_flagged_and_an_empty_list_is_not_an_error()
    {
        using var dir = new TempDirectory();
        Assert.True(AppCatalog.Load(Path.Combine(dir.Path, "none.yaml"), []).FileMissing);

        var empty = AppCatalog.Load(Write(dir, AppCatalog.Template), []);
        Assert.False(empty.FileMissing);
        Assert.Null(empty.Error);
        Assert.Empty(empty.Apps);
    }

    [Fact]
    public void The_shipped_list_parses_and_names_seven_apps()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root, AppCatalog.FileName)))
            root = Path.GetDirectoryName(root);
        Assert.NotNull(root);

        var result = AppCatalog.Load(Path.Combine(root!, AppCatalog.FileName), []);
        Assert.Null(result.Error);
        Assert.Equal(7, result.Apps.Count);
        Assert.All(result.Apps, a => Assert.StartsWith(@"eztools\", a.Executable));
    }
}
