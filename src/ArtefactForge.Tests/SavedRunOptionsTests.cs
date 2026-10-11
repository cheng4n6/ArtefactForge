using System.Text.Json;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>Run options come back from a file anyone can edit, so they are put in range on load.</summary>
public class SavedRunOptionsTests
{
    [Fact]
    public void Values_in_range_are_kept()
    {
        var options = new SavedRunOptions
        {
            Workers = 12, HeavyWorkers = 3, ZipsAtOnce = 4, Vss = true, SkipCompleted = false, CleanupExtracted = true
        }.Clamped();

        Assert.Equal(12, options.Workers);
        Assert.Equal(3, options.HeavyWorkers);
        Assert.Equal(4, options.ZipsAtOnce);
        Assert.True(options.Vss);
        Assert.False(options.SkipCompleted);
        Assert.True(options.CleanupExtracted);
    }

    [Fact]
    public void Zero_and_negative_counts_become_one()
    {
        var options = new SavedRunOptions { Workers = 0, HeavyWorkers = -2, ZipsAtOnce = 0 }.Clamped();

        Assert.Equal(1, options.Workers);
        Assert.Equal(1, options.HeavyWorkers);
        Assert.Equal(1, options.ZipsAtOnce);
    }

    [Fact]
    public void Oversized_counts_are_capped()
    {
        var options = new SavedRunOptions { Workers = 500, HeavyWorkers = 500, ZipsAtOnce = 500 }.Clamped();

        Assert.Equal(SavedRunOptions.MaxWorkersLimit, options.Workers);
        Assert.Equal(SavedRunOptions.MaxWorkersLimit, options.HeavyWorkers);
        Assert.Equal(SavedRunOptions.MaxZipsAtOnce, options.ZipsAtOnce);
    }

    [Fact]
    public void Heavy_io_never_exceeds_the_worker_count()
    {
        var options = new SavedRunOptions { Workers = 4, HeavyWorkers = 6 }.Clamped();

        Assert.Equal(4, options.HeavyWorkers);
    }

    [Fact]
    public void A_settings_file_without_run_options_gets_the_defaults()
    {
        var options = JsonSerializer.Deserialize<SavedRunOptions>("{}")!.Clamped();

        Assert.Equal(8, options.Workers);
        Assert.Equal(2, options.HeavyWorkers);
        Assert.Equal(2, options.ZipsAtOnce);
        Assert.True(options.SkipCompleted);
        Assert.False(options.Vss);
        Assert.False(options.CleanupExtracted);
    }
}
