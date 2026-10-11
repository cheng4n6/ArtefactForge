using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// The name becomes a folder under the case directory, so anything that cannot be a folder has to
/// be refused up front rather than surfacing as an IO error partway through a run.
/// </summary>
public class CollectionNamingTests
{
    [Theory]
    [InlineData("WKSTN-042")]
    [InlineData("dc01.corp.local")]
    [InlineData("Finance Laptop 7")]
    [InlineData("HOST_01")]
    public void Accepts_names_that_look_like_hosts(string raw)
    {
        Assert.True(CollectionNaming.TryValidate(raw, out var name, out var error));
        Assert.Equal(raw, name);
        Assert.Null(error);
    }

    [Fact]
    public void Trims_surrounding_whitespace()
    {
        Assert.True(CollectionNaming.TryValidate("  WKSTN-042  ", out var name, out _));
        Assert.Equal("WKSTN-042", name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Rejects_an_empty_name(string? raw)
    {
        Assert.False(CollectionNaming.TryValidate(raw, out _, out var error));
        Assert.Equal("a name is required", error);
    }

    [Theory]
    [InlineData("bad:name")]
    [InlineData("bad/name")]
    [InlineData("bad\\name")]
    [InlineData("what?")]
    [InlineData("pipe|name")]
    [InlineData("star*name")]
    public void Rejects_characters_a_folder_cannot_contain(string raw)
    {
        Assert.False(CollectionNaming.TryValidate(raw, out _, out var error));
        Assert.Contains("cannot contain", error);
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("nul")]
    [InlineData("COM1")]
    [InlineData("LPT9")]
    public void Rejects_reserved_device_names(string raw)
    {
        // Windows will not create a folder called CON, whatever the case.
        Assert.False(CollectionNaming.TryValidate(raw, out _, out var error));
        Assert.Contains("reserved", error);
    }

    [Fact]
    public void Rejects_a_trailing_dot()
    {
        // Windows strips it silently, so 'HOST.' and 'HOST' would land in the same folder.
        Assert.False(CollectionNaming.TryValidate("HOST01.", out _, out var error));
        Assert.Contains("dot or a space", error);
    }

    [Fact]
    public void Rejects_a_name_that_would_bloat_every_path()
    {
        Assert.False(CollectionNaming.TryValidate(new string('a', CollectionNaming.MaxLength + 1), out _, out var error));
        Assert.Contains("longer than", error);
    }

    [Fact]
    public void Renaming_a_target_changes_only_the_name()
    {
        var target = new ResolvedTarget
        {
            SelectionPath = @"E:\",
            Root = @"E:\",
            Layout = new LayoutProfile { Id = "mounted", Name = "Mounted drive" },
            DriveLetter = "E",
            CollectionName = "IMAGE_E"
        };

        var renamed = target.Renamed("WKSTN-042");

        Assert.Equal("WKSTN-042", renamed.CollectionName);
        Assert.Equal(target.Root, renamed.Root);
        Assert.Equal(target.SelectionPath, renamed.SelectionPath);
        Assert.Equal(target.DriveLetter, renamed.DriveLetter);
        Assert.Same(target.Layout, renamed.Layout);
        Assert.Equal("IMAGE_E", target.CollectionName);
    }
}
