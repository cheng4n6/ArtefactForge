using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// When a collection was made, its time zone and last boot, read from the collector's own files
/// in the shape the converted collection keeps them. Made-up hosts and times.
/// </summary>
public class CollectorTimesTests
{
    private static readonly DateTimeOffset RunStarted = new(2026, 4, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Velociraptor_collection_time_boot_and_time_zone_come_from_client_info()
    {
        using var dir = new TempDirectory();
        var root = dir.Dir("C");
        File.WriteAllText(Path.Combine(dir.Dir("_Velociraptor"), "client_info.json"),
            """{"Hostname":"HOST01","BootTime":1774944000,"ClientStart":"2026-03-31T10:07:46.0041838Z","LocalTZ":"BST","LocalTZOffset":3600}""");

        var times = CollectorTimesReader.Read(root, null, false, RunStarted);

        Assert.Equal(new DateTime(2026, 3, 31, 10, 7, 46, DateTimeKind.Utc), times.CollectedUtc);
        Assert.False(times.CollectedApprox);
        Assert.Equal(new DateTime(2026, 3, 31, 8, 0, 0, DateTimeKind.Utc), times.BootUtc);
        Assert.Equal("BST (UTC+01:00)", times.TimeZone);
        Assert.Contains("client_info.json", times.CollectedFrom);
    }

    [Fact]
    public void UAC_collection_time_is_the_first_log_line_converted_to_UTC()
    {
        using var dir = new TempDirectory();
        File.WriteAllLines(Path.Combine(dir.Dir("_UAC"), "uac.log"),
        [
            "2026-03-31 06:00:00 -0400 INF Unix-like Artifacts Collector v3.0.0",
            "2026-03-31 06:00:00 -0400 INF Hostname: HOST01"
        ]);

        var times = CollectorTimesReader.Read(dir.Path, null, false, RunStarted);

        Assert.Equal(new DateTime(2026, 3, 31, 10, 0, 0, DateTimeKind.Utc), times.CollectedUtc);
        Assert.Null(times.BootUtc);
    }

    [Fact]
    public void KAPE_collection_time_is_the_last_console_log_name_beside_the_drive_folder()
    {
        using var dir = new TempDirectory();
        var root = dir.Dir("C");
        File.WriteAllText(dir.File("2026-03-30T090000_ConsoleLog.txt"), "");
        File.WriteAllText(dir.File("2026-03-31T101530_ConsoleLog.txt"), "");

        var times = CollectorTimesReader.Read(root, null, false, RunStarted);

        Assert.Equal(new DateTime(2026, 3, 31, 10, 15, 30, DateTimeKind.Utc), times.CollectedUtc);
        Assert.Contains("the last of 2 KAPE runs", times.CollectedFrom);
    }

    [Fact]
    public void A_zip_with_no_collector_record_gives_its_own_write_time_marked_as_an_estimate()
    {
        using var dir = new TempDirectory();
        var root = dir.Dir(Path.Combine("_Extracted", "HOST01", "C"));
        var zip = dir.File("HOST01.zip");
        File.WriteAllText(zip, "");
        File.SetLastWriteTimeUtc(zip, new DateTime(2026, 3, 31, 23, 39, 26, 500, DateTimeKind.Utc));

        var times = CollectorTimesReader.Read(root, zip, false, RunStarted);

        Assert.Equal(new DateTime(2026, 3, 31, 23, 39, 26, DateTimeKind.Utc), times.CollectedUtc);
        Assert.True(times.CollectedApprox);
    }

    [Fact]
    public void A_folder_with_no_collector_record_records_nothing_rather_than_a_guess()
    {
        using var dir = new TempDirectory();
        var root = dir.Dir("C");
        File.WriteAllText(Path.Combine(dir.Dir(Path.Combine("C", "Windows")), "notes.txt"), "");

        Assert.True(CollectorTimesReader.Read(root, null, false, RunStarted).IsEmpty);
    }

    [Fact]
    public void A_live_system_is_collected_when_the_run_starts()
    {
        var times = CollectorTimesReader.Read(@"C:\", null, true, RunStarted);

        Assert.Equal(RunStarted.UtcDateTime, times.CollectedUtc);
        Assert.NotNull(times.BootUtc);
        Assert.True(times.BootUtc < DateTime.UtcNow);
        Assert.Contains("UTC", times.TimeZone);
    }

    [Fact]
    public void A_damaged_client_info_is_passed_over()
    {
        using var dir = new TempDirectory();
        var root = dir.Dir("C");
        File.WriteAllText(Path.Combine(dir.Dir("_Velociraptor"), "client_info.json"), "{ not json");

        Assert.True(CollectorTimesReader.Read(root, null, false, RunStarted).IsEmpty);
    }
}
