using System.Globalization;
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

    [Theory]
    [InlineData(1.0, 1.0)]
    [InlineData(0.0, 0.0)]
    [InlineData(-3.0, 0.0)]
    [InlineData(500.0, SavedRunOptions.MaxKeepFreeGB)]
    [InlineData(double.NaN, 1.0)]
    public void Keep_free_is_put_in_range(double saved, double expected) =>
        Assert.Equal(expected, new SavedRunOptions { KeepFreeGB = saved }.Clamped().KeepFreeGB);

    [Fact]
    public void Keep_free_defaults_to_1_GB() =>
        Assert.Equal(1L << 30, SavedRunOptions.ToBytes(new SavedRunOptions().Clamped().KeepFreeGB));

    [Fact]
    public void Nothing_is_reported_when_nothing_changes()
    {
        var typed = new SavedRunOptions { Workers = 8, HeavyWorkers = 2, ZipsAtOnce = 2, KeepFreeGB = 1.5 };

        Assert.Empty(typed.Adjustments(typed.Clamped()));
    }

    [Fact]
    public void Each_changed_value_is_reported_with_what_is_used()
    {
        var typed = new SavedRunOptions { Workers = 4, HeavyWorkers = 6, ZipsAtOnce = 0, KeepFreeGB = 500 };

        var lines = typed.Adjustments(typed.Clamped());

        Assert.Equal(
        [
            "Heavy IO 6 is more than the workers; using 4.",
            "Zips at once 0 is out of range; using 1.",
            "Keep free (GB) 500 is out of range; using 64."
        ], lines);
    }

    [Theory]
    [InlineData("4", true, 4)]
    [InlineData(" 12 ", true, 12)]
    [InlineData("-1", true, -1)]
    [InlineData("abc", false, 0)]
    [InlineData("2.5", false, 0)]
    [InlineData("", false, 0)]
    [InlineData(null, false, 0)]
    public void Counts_must_be_whole_numbers(string? text, bool ok, int expected)
    {
        Assert.Equal(ok, SavedRunOptions.TryParseCount(text, out var value));
        if (ok) Assert.Equal(expected, value);
    }

    [Theory]
    [InlineData("1", true, 1.0)]
    [InlineData("0.5", true, 0.5)]
    [InlineData("abc", false, 0.0)]
    [InlineData("NaN", false, 0.0)]
    [InlineData("Infinity", false, 0.0)]
    [InlineData(null, false, 0.0)]
    public void Keep_free_must_be_a_finite_number(string? text, bool ok, double expected)
    {
        Assert.Equal(ok, SavedRunOptions.TryParseGB(text, CultureInfo.InvariantCulture, out var value));
        if (ok) Assert.Equal(expected, value);
    }
}
