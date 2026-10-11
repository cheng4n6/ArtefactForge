using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// The case roll-up reads what the summary modules wrote, so it has to survive the ordinary
/// messiness of CSV - quoted commas, missing columns, a collection that produced no summary at all.
/// </summary>
public class SystemInventoryTests
{
    private static void WriteSummary(TempDirectory dir, string collection, params string[] facts)
    {
        var folder = Path.Combine(dir.Path, collection, "SystemInfo");
        Directory.CreateDirectory(folder);

        var lines = new List<string> { "\"Category\",\"Item\",\"Value\",\"Source\"" };
        lines.AddRange(facts);
        File.WriteAllLines(Path.Combine(folder, "SystemInfo.csv"), lines);
    }

    [Fact]
    public void Builds_one_row_per_collection()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "web01", "\"Identity\",\"Hostname\",\"web01\",\"etc/hostname\"");
        WriteSummary(dir, "db02", "\"Identity\",\"Hostname\",\"db02\",\"etc/hostname\"");

        var path = SystemInventory.Build(dir.Path);

        Assert.NotNull(path);
        var lines = File.ReadAllLines(path!);
        Assert.Equal(3, lines.Length);              // header plus two hosts
        Assert.Contains("web01", lines[2]);         // sorted, so db02 comes first
        Assert.Contains("db02", lines[1]);
    }

    [Fact]
    public void Skips_underscore_folders_so_logs_are_not_treated_as_a_host()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "web01", "\"Identity\",\"Hostname\",\"web01\",\"etc/hostname\"");
        Directory.CreateDirectory(Path.Combine(dir.Path, "_Logs", "SystemInfo"));

        var lines = File.ReadAllLines(SystemInventory.Build(dir.Path)!);
        Assert.Equal(2, lines.Length);
        Assert.DoesNotContain("_Logs", string.Join("\n", lines));
    }

    [Fact]
    public void A_collection_without_a_summary_is_left_out_rather_than_blank_filled()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "web01", "\"Identity\",\"Hostname\",\"web01\",\"etc/hostname\"");
        Directory.CreateDirectory(Path.Combine(dir.Path, "db02", "Registry"));

        var lines = File.ReadAllLines(SystemInventory.Build(dir.Path)!);
        Assert.Equal(2, lines.Length);
        Assert.DoesNotContain("db02", string.Join("\n", lines));
    }

    [Fact]
    public void Returns_null_when_nothing_produced_a_summary()
    {
        // An empty inventory file would read as a failed run rather than an absent feature.
        using var dir = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(dir.Path, "web01", "Registry"));

        Assert.Null(SystemInventory.Build(dir.Path));
        Assert.False(File.Exists(Path.Combine(dir.Path, "SystemInventory.csv")));
    }

    [Fact]
    public void Values_containing_commas_survive_the_round_trip()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "web01",
            "\"Accounts\",\"UID0Accounts\",\"root, backdoor\",\"etc/passwd\"",
            "\"Identity\",\"Hostname\",\"web01\",\"etc/hostname\"");

        var lines = File.ReadAllLines(SystemInventory.Build(dir.Path)!);
        Assert.Contains("\"root, backdoor\"", lines[1]);
    }

    [Fact]
    public void Collection_gaps_are_counted_not_listed()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "web01",
            "\"Identity\",\"Hostname\",\"web01\",\"etc/hostname\"",
            "\"CollectionGaps\",\"UnreadableSymlink\",\"etc/os-release\",\"link target not collected\"",
            "\"CollectionGaps\",\"UnreadableSymlink\",\"etc/resolv.conf\",\"link target not collected\"");

        var lines = File.ReadAllLines(SystemInventory.Build(dir.Path)!);
        var header = lines[0].Split(',');
        var gapColumn = Array.FindIndex(header, h => h.Trim('"') == "CollectionGaps");

        Assert.True(gapColumn >= 0);
        Assert.Equal("2", lines[1].Split(',')[gapColumn].Trim('"'));
    }

    [Fact]
    public void A_summary_with_only_a_header_does_not_produce_a_row()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "web01");

        Assert.Null(SystemInventory.Build(dir.Path));
    }
}
