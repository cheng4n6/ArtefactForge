using ArtefactForge.Core;

namespace ArtefactForge.Tests;

public class LayoutDetectorTests
{
    private static LayoutProfile MountedDrive() => new()
    {
        Name = "Mounted drive or live system",
        Id = "mounted-drive",
        Priority = 10,
        Detect = new LayoutDetectRules
        {
            RootIsSelection = true,
            Markers = [@"Windows\System32\config\SYSTEM", "$MFT"],
            MatchMode = MarkerMatchMode.Any
        },
        Resolve = new LayoutResolveRules { RootOffset = "." }
    };

    private static LayoutProfile CollectionFolder() => new()
    {
        Name = "Collection folder (drive-letter root)",
        Id = "collection-folder",
        Priority = 20,
        Detect = new LayoutDetectRules
        {
            Markers = [@"?\Windows\System32\config\SYSTEM", @"?\$MFT"],
            MatchMode = MarkerMatchMode.Any,
            DriveLetterFolder = true
        },
        Resolve = new LayoutResolveRules { RootOffset = "?" }
    };

    private static LayoutProfile[] Profiles() => [MountedDrive(), CollectionFolder()];

    [Fact]
    public void Detects_a_cylr_style_collection_and_resolves_the_drive_folder_as_root()
    {
        using var dir = new TempDirectory();
        dir.File(@"C\Windows\System32\config\SYSTEM");
        dir.File(@"C\$MFT");
        // CyLR leaves its own files beside the drive folder; they must not confuse detection.
        dir.File("CyLR.exe");
        dir.File("HOST01.zip");

        var targets = LayoutDetector.Detect(dir.Path, Profiles());

        var target = Assert.Single(targets);
        Assert.Equal("collection-folder", target.Layout.Id);
        Assert.Equal(Path.Combine(dir.Path, "C"), target.Root);
        Assert.Equal("C", target.DriveLetter);
        Assert.False(target.IsLive);
    }

    [Fact]
    public void Detects_a_drive_root_where_the_selection_is_itself_the_root()
    {
        using var dir = new TempDirectory();
        dir.File(@"Windows\System32\config\SYSTEM");

        var target = Assert.Single(LayoutDetector.Detect(dir.Path, Profiles()));
        Assert.Equal("mounted-drive", target.Layout.Id);
        Assert.Equal(dir.Path, target.Root);
    }

    [Fact]
    public void Yields_one_target_per_drive_letter_and_disambiguates_the_names()
    {
        using var dir = new TempDirectory();
        dir.File(@"C\Windows\System32\config\SYSTEM");
        dir.File(@"D\$MFT");

        var targets = LayoutDetector.Detect(dir.Path, Profiles());

        Assert.Equal(2, targets.Count);
        Assert.All(targets, t => Assert.Contains("_", t.CollectionName));
        Assert.Contains(targets, t => t.DriveLetter == "C");
        Assert.Contains(targets, t => t.DriveLetter == "D");
    }

    [Fact]
    public void A_single_collection_keeps_the_plain_folder_name()
    {
        using var dir = new TempDirectory();
        dir.File(@"C\$MFT");

        var target = Assert.Single(LayoutDetector.Detect(dir.Path, Profiles()));
        Assert.Equal(Path.GetFileName(dir.Path), target.CollectionName);
    }

    [Fact]
    public void Returns_nothing_when_no_profile_matches()
    {
        using var dir = new TempDirectory();
        dir.File(@"Documents\notes.txt");
        Assert.Empty(LayoutDetector.Detect(dir.Path, Profiles()));
    }

    [Fact]
    public void Returns_nothing_for_a_path_that_does_not_exist()
    {
        Assert.Empty(LayoutDetector.Detect(@"D:\definitely\not\here", Profiles()));
    }

    [Fact]
    public void Ignores_multi_character_folders_when_looking_for_a_drive_letter()
    {
        using var dir = new TempDirectory();
        dir.File(@"CC\Windows\System32\config\SYSTEM");
        Assert.Empty(LayoutDetector.Detect(dir.Path, Profiles()));
    }

    [Fact]
    public void MatchMode_all_requires_every_marker()
    {
        // Live profiles must stay on MatchMode.Any: a non-elevated session cannot stat the SYSTEM
        // hive, so File.Exists returns false for a file that is present. This pins the difference.
        using var dir = new TempDirectory();
        dir.File(@"C\$MFT");

        var strict = CollectionFolder();
        var all = new LayoutProfile
        {
            Name = strict.Name, Id = "strict", Priority = 5,
            Detect = new LayoutDetectRules
            {
                Markers = strict.Detect.Markers,
                MatchMode = MarkerMatchMode.All,
                DriveLetterFolder = true
            },
            Resolve = strict.Resolve
        };

        Assert.Empty(LayoutDetector.Detect(dir.Path, [all]));
        Assert.Single(LayoutDetector.Detect(dir.Path, [strict]));
    }

    [Fact]
    public void Lower_priority_number_wins()
    {
        using var dir = new TempDirectory();
        dir.File(@"Windows\System32\config\SYSTEM");
        dir.File(@"C\$MFT");

        // Both profiles can match this tree; mounted-drive is priority 10 and must win.
        var target = Assert.Single(LayoutDetector.Detect(dir.Path, Profiles()));
        Assert.Equal("mounted-drive", target.Layout.Id);
    }
}
