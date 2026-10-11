using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Real collections routinely exceed MAX_PATH - browser cache and Recent LNKs named after long
/// URLs are the usual culprits. Verified on a machine with LongPathsEnabled=0 and no
/// longPathAware manifest: .NET applies the \\?\ prefix itself, so this works regardless.
/// PathGlob swallows IOException by design, so without this test a MAX_PATH regression would
/// show up as artefacts silently missing from the output rather than as an error.
/// </summary>
public class LongPathTests
{
    private static string DeepPath(TempDirectory dir, out string relativeGlob)
    {
        var segment = new string('a', 40);
        relativeGlob = string.Join(Path.DirectorySeparatorChar, Enumerable.Repeat("*", 7));
        return Path.Combine(dir.Path, string.Join(Path.DirectorySeparatorChar, Enumerable.Repeat(segment, 7)));
    }

    [Fact]
    public void Glob_finds_a_file_beyond_the_260_character_limit()
    {
        using var dir = new TempDirectory();
        var deep = DeepPath(dir, out var glob);
        Directory.CreateDirectory(deep);

        var file = Path.Combine(deep, "NTUSER.DAT");
        File.WriteAllText(file, "x");
        Assert.True(file.Length > 260, $"path was only {file.Length} characters");

        Assert.Single(PathGlob.Expand(Path.Combine(dir.Path, glob, "NTUSER.DAT")));
    }

    [Fact]
    public void AnyMatch_sees_a_required_artefact_beyond_the_limit()
    {
        // If this regressed, the module would report 'not present' for a file that is right there.
        using var dir = new TempDirectory();
        var deep = DeepPath(dir, out var glob);
        Directory.CreateDirectory(deep);
        File.WriteAllText(Path.Combine(deep, "ActivitiesCache.db"), "x");

        Assert.True(PathGlob.AnyMatch(Path.Combine(dir.Path, glob, "ActivitiesCache.db")));
    }
}
