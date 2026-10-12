using ArtefactForge.Core;
using ArtefactForge.Core.Ioc;

namespace ArtefactForge.Tests;

/// <summary>
/// The sweep over a case's output: hits land in IocHits.csv, adding an IOC searches for that IOC
/// alone, and processing a host again rebuilds that host's hits and leaves the others alone.
/// </summary>
public class IocSweepTests
{
    private static void Output(TempDirectory dir, string host, string relative, params string[] lines)
    {
        var path = dir.File(Path.Combine(host, relative));
        File.WriteAllLines(path, lines);
    }

    private static List<IocHit> Hits(TempDirectory dir) => IocSweep.ReadHits(IocSweep.HitsPathFor(dir.Path)).ToList();

    private static TempDirectory Case()
    {
        var dir = new TempDirectory();
        Output(dir, "DC01", Path.Combine("EventLogs", "EvtxECmd_Output.csv"),
            "RecordNumber,TimeCreated,Computer,Payload",
            "1,2026-03-01 10:00:00,DC01,Process C:\\Temp\\ABC.exe started",
            "2,2026-03-01 10:05:00,DC01,Connection to 203.0.113.7");
        Output(dir, "WS02", Path.Combine("ProgramExecution", "Amcache_UnassociatedFileEntries.csv"),
            "Name,FullPath,SHA1,FileKeyLastWriteTimestamp",
            "ABC.exe,c:\\users\\bob\\abc.exe,0123456789abcdef0123456789abcdef01234567,2026-02-27 08:00:00");
        Output(dir, "WS03", Path.Combine("FileSystem", "MFTECmd_Output.csv"),
            "FileName,ParentPath,Created0x10",
            "notes.txt,.\\Users\\carol,2026-01-01");
        // Not hosts: the case's own folders, and the case-level files beside them.
        Output(dir, "_Logs", "manifest.csv", "Collection,Module", "ABC.exe,ABC.exe");
        File.WriteAllText(Path.Combine(dir.Path, "SystemInventory.csv"), "Collection\r\nABC.exe\r\n");
        return dir;
    }

    [Fact]
    public async Task Adding_an_IOC_finds_it_on_every_host_and_writes_the_hits_file()
    {
        using var dir = Case();
        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);

        var result = await IocSweep.SweepAsync(dir.Path, added);

        Assert.Equal(3, result.Hosts);
        Assert.Equal(3, result.FilesScanned);
        Assert.Equal(2, result.Hits);
        Assert.Equal(2, result.HostsWithHits);
        Assert.Empty(result.Problems);

        var hits = Hits(dir);
        var dc = hits.Single(h => h.Host == "DC01");
        Assert.Equal("File name", dc.IocType);
        Assert.Equal("ABC.exe", dc.Ioc);
        Assert.Equal("EventLogs", dc.Module);   // no manifest names the file, so its category folder
        Assert.Equal("2026-03-01 10:00:00", dc.Time);
        Assert.Equal(Path.Combine("DC01", "EventLogs", "EvtxECmd_Output.csv"), dc.OutputFile);
        Assert.Equal(2, dc.LineNumber);
        Assert.Contains("C:\\Temp\\ABC.exe started", dc.MatchingLine);
        Assert.Equal("2026-02-27 08:00:00", hits.Single(h => h.Host == "WS02").Time);
    }

    [Fact]
    public async Task Hashes_are_found_in_hash_columns()
    {
        using var dir = Case();
        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.Hash, "0123456789ABCDEF0123456789ABCDEF01234567")]);

        await IocSweep.SweepAsync(dir.Path, added);

        Assert.Equal("WS02", Assert.Single(Hits(dir)).Host);
    }

    [Fact]
    public async Task A_second_IOC_is_searched_for_alone_and_the_first_IOCs_hits_stay()
    {
        using var dir = Case();
        await IocSweep.SweepAsync(dir.Path, IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]));
        // Gone from the output since the first sweep: had ABC.exe been searched for again, its
        // DC01 hit would have gone too.
        File.Delete(Path.Combine(dir.Path, "DC01", "EventLogs", "EvtxECmd_Output.csv"));
        Output(dir, "DC01", Path.Combine("EventLogs", "Other.csv"), "Payload", "203.0.113.7 again");

        var result = await IocSweep.SweepAsync(dir.Path, IocList.Add(dir.Path, [IocEntry.Create(IocType.IP, "203.0.113.7")]));

        Assert.Equal(1, result.Iocs);
        var hits = Hits(dir);
        Assert.Equal(2, hits.Count(h => h.Ioc == "ABC.exe"));
        Assert.Equal("Other.csv", Path.GetFileName(Assert.Single(hits, h => h.Ioc == "203.0.113.7").OutputFile));
    }

    [Fact]
    public async Task Sweeping_the_same_IOC_again_does_not_double_its_hits()
    {
        using var dir = Case();
        var ioc = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);

        await IocSweep.SweepAsync(dir.Path, ioc);
        await IocSweep.SweepAsync(dir.Path, ioc);

        Assert.Equal(2, Hits(dir).Count);
    }

    [Fact]
    public async Task Rebuilding_one_host_leaves_every_other_hosts_hits_as_they_were()
    {
        using var dir = Case();
        await IocSweep.SweepAsync(dir.Path, IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]));
        var ws02Before = Hits(dir).Single(h => h.Host == "WS02");

        // WS02's output is no longer looked at; DC01 is processed again with new output.
        File.Delete(Path.Combine(dir.Path, "WS02", "ProgramExecution", "Amcache_UnassociatedFileEntries.csv"));
        Output(dir, "DC01", Path.Combine("EventLogs", "EvtxECmd_Output.csv"),
            "RecordNumber,TimeCreated,Payload",
            "7,2026-03-02,ABC.exe again",
            "8,2026-03-02,and ABC.exe once more");

        var result = await IocSweep.RebuildHostsAsync(dir.Path, ["DC01"]);

        Assert.Equal(1, result.Hosts);
        var hits = Hits(dir);
        Assert.Equal(ws02Before, hits.Single(h => h.Host == "WS02"));
        Assert.Equal([2L, 3L], hits.Where(h => h.Host == "DC01").Select(h => h.LineNumber));
    }

    [Fact]
    public async Task A_host_rebuild_uses_the_whole_list()
    {
        using var dir = Case();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe"), IocEntry.Create(IocType.IP, "203.0.113.7")]);

        await IocSweep.RebuildHostsAsync(dir.Path, ["DC01"]);

        Assert.Equal(["203.0.113.7", "ABC.exe"], Hits(dir).Select(h => h.Ioc).Order());
    }

    [Fact]
    public async Task Removing_an_IOC_drops_its_hits_only()
    {
        using var dir = Case();
        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe"), IocEntry.Create(IocType.IP, "203.0.113.7")]);
        await IocSweep.SweepAsync(dir.Path, added);

        await IocSweep.RemoveHitsAsync(dir.Path, IocList.Remove(dir.Path, [IocEntry.Create(IocType.FileName, "abc.exe")]));

        Assert.Equal("203.0.113.7", Assert.Single(Hits(dir)).Ioc);
    }

    [Fact]
    public async Task Counts_per_IOC_give_hits_and_hosts()
    {
        using var dir = Case();
        Output(dir, "DC01", Path.Combine("EventLogs", "More.csv"), "Payload", "ABC.exe", "ABC.exe");
        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe"), IocEntry.Create(IocType.Account, "nobody")]);
        await IocSweep.SweepAsync(dir.Path, added);

        var counts = IocSweep.Summarise(dir.Path);

        Assert.Equal(new IocHitCount(4, 2), counts[added[0].Key]);
        Assert.False(counts.ContainsKey(added[1].Key));
    }

    [Fact]
    public async Task A_cancelled_sweep_writes_nothing()
    {
        using var dir = Case();
        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => IocSweep.SweepAsync(dir.Path, added, null, cancelled.Token));

        Assert.False(File.Exists(IocSweep.HitsPathFor(dir.Path)));
    }

    [Fact]
    public async Task A_file_that_cannot_be_read_is_reported_not_passed_over()
    {
        using var dir = Case();
        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        var locked = Path.Combine(dir.Path, "WS02", "ProgramExecution", "Amcache_UnassociatedFileEntries.csv");

        IocSweepResult result;
        using (new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            result = await IocSweep.SweepAsync(dir.Path, added);

        Assert.Contains(result.Problems, p => p.Contains("Amcache_UnassociatedFileEntries.csv"));
        Assert.Contains("could not be read", result.Describe());
        Assert.Contains("could not be read", IocSweep.LastResult(dir.Path));
    }

    [Fact]
    public async Task The_module_comes_from_the_manifest_even_when_the_case_has_moved_since()
    {
        using var dir = Case();
        // Written where the case was processed, before it was copied to where it is now.
        var destination = Path.Combine("X:\\", "Cases", "CaseA", "DC01", "EventLogs");
        File.WriteAllText(Path.Combine(dir.Path, "_Logs", "manifest.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            Results = new[]
            {
                new
                {
                    Collection = "DC01",
                    Module = "EvtxECmd",
                    Destination = destination,
                    Processors = new[] { new { OutputFiles = new[] { "20260301_Output.csv => EvtxECmd_Output.csv" } } }
                }
            }
        }));

        await IocSweep.SweepAsync(dir.Path, IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]));

        Assert.Equal("EvtxECmd", Hits(dir).Single(h => h.Host == "DC01").Module);
    }

    [Fact]
    public async Task After_a_run_only_the_hosts_that_ran_are_rebuilt()
    {
        using var dir = Case();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        var report = new RunReport { CaseDirectory = dir.Path, LogDirectory = Path.Combine(dir.Path, "_Logs") };
        report.Results.Add(Result("WS02", WorkStatus.Completed));
        report.Results.Add(Result("DC01", WorkStatus.Skipped));

        await IocSweep.AfterRunAsync(report);

        Assert.Equal("WS02", Assert.Single(Hits(dir)).Host);
    }

    [Fact]
    public async Task After_a_run_a_case_without_a_list_gets_no_IOC_files()
    {
        using var dir = Case();
        var report = new RunReport { CaseDirectory = dir.Path, LogDirectory = Path.Combine(dir.Path, "_Logs") };
        report.Results.Add(Result("WS02", WorkStatus.Completed));

        await IocSweep.AfterRunAsync(report);

        Assert.False(File.Exists(IocList.PathFor(dir.Path)));
        Assert.False(File.Exists(IocSweep.HitsPathFor(dir.Path)));
    }

    [Fact]
    public async Task After_a_stopped_run_the_hits_are_left_and_the_log_says_they_may_be_stale()
    {
        using var dir = Case();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        var report = new RunReport { CaseDirectory = dir.Path, LogDirectory = Path.Combine(dir.Path, "_Logs"), Cancelled = true };
        report.Results.Add(Result("WS02", WorkStatus.Cancelled));

        await IocSweep.AfterRunAsync(report);

        Assert.False(File.Exists(IocSweep.HitsPathFor(dir.Path)));
        Assert.Contains("out of date", IocSweep.LastResult(dir.Path));
    }

    [Fact]
    public async Task The_list_is_never_written_by_a_sweep()
    {
        using var dir = Case();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        var path = IocList.PathFor(dir.Path);
        var written = File.GetLastWriteTimeUtc(path);
        var content = File.ReadAllBytes(path);

        await IocSweep.RebuildAllAsync(dir.Path);

        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Equal(written, File.GetLastWriteTimeUtc(path));
    }

    private static WorkResult Result(string collection, WorkStatus status) => new()
    {
        Collection = collection,
        Module = "EvtxECmd",
        Category = "EventLogs",
        Status = status
    };
}
