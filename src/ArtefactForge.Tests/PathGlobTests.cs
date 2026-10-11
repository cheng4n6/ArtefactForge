using ArtefactForge.Core;

namespace ArtefactForge.Tests;

public class PathGlobTests
{
    private static TempDirectory BuildTree()
    {
        var dir = new TempDirectory();
        dir.File(@"C\Windows\System32\config\SYSTEM");
        dir.File(@"C\Windows\System32\config\SOFTWARE");
        dir.File(@"C\Windows\System32\winevt\Logs\System.evtx");
        dir.File(@"C\Windows\System32\winevt\Logs\Security.evtx");
        dir.File(@"C\Windows\System32\winevt\Logs\notes.txt");
        dir.File(@"C\Users\alice\NTUSER.DAT");
        dir.File(@"C\Users\bob\NTUSER.DAT");
        dir.File(@"C\Users\Public\desktop.ini");
        dir.File(@"C\Users\alice\AppData\Local\ConnectedDevicesPlatform\L.alice\ActivitiesCache.db");
        dir.File(@"C\$MFT");
        return dir;
    }

    [Fact]
    public void Matches_a_literal_path()
    {
        using var dir = BuildTree();
        Assert.Single(PathGlob.Expand(Path.Combine(dir.Path, @"C\Windows\System32\config\SYSTEM")));
    }

    [Fact]
    public void Matches_a_dollar_prefixed_name()
    {
        // $MFT and $Extend are the reason Path.Combine is used rather than string interpolation.
        using var dir = BuildTree();
        Assert.Single(PathGlob.Expand(Path.Combine(dir.Path, @"C\$MFT")));
    }

    [Fact]
    public void Expands_a_wildcard_directory_segment()
    {
        using var dir = BuildTree();
        var hits = PathGlob.Expand(Path.Combine(dir.Path, @"C\Users\*\NTUSER.DAT"));
        Assert.Equal(2, hits.Count);
    }

    [Fact]
    public void Expands_a_wildcard_in_the_final_segment()
    {
        using var dir = BuildTree();
        var hits = PathGlob.Expand(Path.Combine(dir.Path, @"C\Windows\System32\winevt\Logs\*.evtx"));
        Assert.Equal(2, hits.Count);
        Assert.DoesNotContain(hits, h => h.EndsWith("notes.txt"));
    }

    [Fact]
    public void Expands_two_wildcard_segments()
    {
        // WxTCmd's ActivitiesCache.db sits behind an opaque folder name.
        using var dir = BuildTree();
        var hits = PathGlob.Expand(Path.Combine(dir.Path,
            @"C\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db"));
        Assert.Single(hits);
    }

    [Fact]
    public void Returns_nothing_for_a_missing_path()
    {
        using var dir = BuildTree();
        Assert.Empty(PathGlob.Expand(Path.Combine(dir.Path, @"C\Windows\AppCompat\Programs\RecentFileCache.bcf")));
    }

    [Fact]
    public void Does_not_recurse_across_directory_levels()
    {
        // A single * must match one segment only, or a Users-tree glob would walk the whole profile.
        using var dir = BuildTree();
        Assert.Empty(PathGlob.Expand(Path.Combine(dir.Path, @"C\Users\*\ActivitiesCache.db")));
    }

    [Fact]
    public void Matches_a_directory_as_well_as_a_file()
    {
        using var dir = BuildTree();
        Assert.Single(PathGlob.Expand(Path.Combine(dir.Path, @"C\Windows\System32\winevt\Logs")));
    }

    [Fact]
    public void AnyMatch_reports_presence()
    {
        using var dir = BuildTree();
        Assert.True(PathGlob.AnyMatch(Path.Combine(dir.Path, @"C\Users\*\NTUSER.DAT")));
        Assert.False(PathGlob.AnyMatch(Path.Combine(dir.Path, @"C\Users\*\UsrClass.dat")));
    }

    [Fact]
    public void Empty_or_relative_patterns_yield_nothing_rather_than_throwing()
    {
        Assert.Empty(PathGlob.Expand(""));
        Assert.Empty(PathGlob.Expand(@"Users\*\NTUSER.DAT"));
    }
}
