using System.Text;
using ArtefactForge.Core.Ioc;
using ArtefactForge.Lake;
using ArtefactForge.Lake.Queries;

namespace ArtefactForge.Tests;

/// <summary>
/// The lake's IOC sweep against the C# IOC sweep, as decided (Matthew, 2026-11-19): the same hits,
/// compared on IocType, Ioc, Host, Module, Time, OutputFile and LineNumber. MatchingLine is the
/// lake's row written back from its cells, so it is compared only for files written the way the
/// lake writes a line (a cell quoted only when it must be), and its other differences are only of
/// form. Made-up hosts, users and addresses.
/// </summary>
public class IocLakeParityTests
{
    private const string Sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
    private const string Md5 = "900150983cd24fb0d6963f7d28e17f72";

    private static void Write(string path, params string[] lines)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, string.Join("\r\n", lines) + "\r\n", new UTF8Encoding(true));
    }

    private static string Q(string s) => s.Contains(',') || s.Contains('"') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;

    /// <summary>Each IOC among the neighbours that should and should not make it a whole value.</summary>
    private static IEnumerable<string> Contexts(string v)
    {
        yield return v;
        yield return "x" + v;
        yield return v + "x";
        yield return v + ".bak";
        yield return v + ".";
        yield return v + ". next";
        yield return v + ".com";
        yield return v + "-";
        yield return "-" + v;
        yield return "sub." + v;
        yield return "(" + v + ")";
        yield return "ran " + v + " at 10:00";
        yield return v.ToUpperInvariant();
        yield return v + "$";
        yield return "_" + v;
        yield return v + "1";
        yield return "1" + v;
        yield return v + ":443";
        yield return v + "\\";
        yield return v + "/x";
        yield return "\"" + v + "\"";
        yield return "{\"Path\":\"" + v.Replace("\\", "\\\\") + "\"}";
        yield return v.Replace('\\', '/');
        yield return v.Length > 2 && v[1] == ':' ? v[2..] : v;
        yield return v.Length > 2 && v[1] == ':' ? @"\Device\HarddiskVolume3" + v[2..] : v;
    }

    private static readonly string[] Values =
    [
        "evil.exe", @"C:\Temp\evil.exe", @"C:\Staging\", "10.0.0.1", "2001:db8::1", "evil.com", @"CORP\bob", "alice",
        "svc_backup", "bob@example.test", Sha1, Md5
    ];

    private static void WholeCase(string caseDir)
    {
        // Every context of every value in one file, a row each, with a time column.
        var rows = new List<string> { "Row,TimeCreated,LastWriteTime,Text" };
        var n = 0;
        foreach (var value in Values)
            foreach (var text in Contexts(value))
            {
                n++;
                // Some rows have no TimeCreated: their time is the next time column's.
                rows.Add($"{n},{(n % 3 == 0 ? "" : "2026-03-16 10:00:00")},2026-03-17 11:00:00,{Q(text)}");
            }
        Write(Path.Combine(caseDir, "HOST01", "Tools", "Tool_Output.csv"), [.. rows]);

        // Hashes only count in hash columns: in Sysmon's list, as Amcache's 0000-prefixed FileId, or not at all.
        Write(Path.Combine(caseDir, "HOST02", "Amcache", "Amcache_UnassociatedFileEntries.csv"),
            "ProgramName,SHA1,FileKeyLastWriteTimestamp,Notes",
            $"tool,0000{Sha1},2026-03-15 09:00:00,",
            $"tool2,{Sha1.ToUpperInvariant()},2026-03-15 09:00:01,",
            $"tool3,,2026-03-15 09:00:02,mentions {Sha1} in a note",
            $"tool4,{Sha1}0,2026-03-15 09:00:03,");
        Write(Path.Combine(caseDir, "HOST02", "EventLogs", "Sysmon.csv"),
            "TimeCreated,EventId,Hashes,Payload",
            $"2026-03-15 10:00:00.1234567,1,\"SHA1={Sha1},MD5={Md5}\",\"{{\"\"Image\"\":\"\"C:\\\\Temp\\\\evil.exe\"\"}}\"",
            "2026-03-15 10:00:01.0000000,3,,connect to 10.0.0.1:443 and 10.0.0.12 then evil.com.au and www.evil.com",
            "2026-03-15 10:00:02.0000000,4624,,CORP\\bob logged on; bobby did not; Bob@Example.test mailed");
        // Two per-user folders, and a file in its category folder directly.
        Write(Path.Combine(caseDir, "HOST02", "LNKFiles", "alice", "alice_LECmd_Recent.csv"),
            "SourceFile,SourceCreated,LocalPath",
            @"C:\Users\alice\Recent\a.lnk,2026-03-10 08:00:00,C:\Temp\evil.exe",
            @"C:\Users\alice\Recent\b.lnk,2026-03-10 08:00:01,C:\Staging\loot.zip");
        // A host with nothing on the list.
        Write(Path.Combine(caseDir, "HOST03", "Tools", "Other.csv"), "A,B", "1,2");

        // The run's manifest names the module that wrote one file; the others go by their folder.
        Directory.CreateDirectory(Path.Combine(caseDir, "_Logs"));
        File.WriteAllText(Path.Combine(caseDir, "_Logs", "manifest.json"), $$"""
            { "Results": [ { "Module": "ToolX", "Collection": "HOST01",
                             "Destination": "{{Path.Combine(caseDir, "HOST01", "Tools").Replace("\\", "\\\\")}}",
                             "Processors": [ { "OutputFiles": [ "Tool_Output.csv" ] } ] } ] }
            """);

        IocList.Add(caseDir,
        [
            IocEntry.Create(IocType.FileName, "evil.exe"), IocEntry.Create(IocType.Path, @"C:\Temp\evil.exe"),
            IocEntry.Create(IocType.Path, @"C:\Staging\"), IocEntry.Create(IocType.IP, "10.0.0.1"),
            IocEntry.Create(IocType.IP, "2001:db8::1"), IocEntry.Create(IocType.Domain, "evil.com"),
            IocEntry.Create(IocType.Account, @"CORP\bob"), IocEntry.Create(IocType.Account, "alice"),
            IocEntry.Create(IocType.Account, "svc_backup"), IocEntry.Create(IocType.Account, "bob@example.test"),
            IocEntry.Create(IocType.Hash, Sha1), IocEntry.Create(IocType.Hash, Md5)
        ]);
    }

    private static (List<IocHit> CSharp, List<IocHit> Lake) RunBoth(string caseDir)
    {
        IocSweep.RebuildAllAsync(caseDir).GetAwaiter().GetResult();
        var csharp = IocSweep.ReadHits(IocSweep.HitsPathFor(caseDir)).ToList();
        var result = LakeBuilder.Build(caseDir, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30 });
        Assert.NotEqual(LakeOutcome.Failed, result.Outcome);
        Assert.DoesNotContain(result.Warnings, w => w.Contains("IOC", StringComparison.Ordinal));
        var lake = IocSweep.ReadHits(Path.Combine(IocResults.OutputRootFor(result.LakeDirectory!), IocResults.HitsFileName)).ToList();
        return (csharp, lake);
    }

    private static string Key(IocHit h) => string.Join(" | ", h.IocType, h.Ioc, h.Host, h.Module, h.Time, h.OutputFile, h.LineNumber);

    [Fact]
    public void The_lake_finds_the_same_hits_as_the_CSharp_sweep_in_the_same_order()
    {
        using var dir = new TempDirectory();
        WholeCase(dir.Path);

        var (csharp, lake) = RunBoth(dir.Path);

        Assert.NotEmpty(csharp);
        var missing = csharp.Select(Key).Except(lake.Select(Key)).ToList();
        var extra = lake.Select(Key).Except(csharp.Select(Key)).ToList();
        Assert.True(missing.Count == 0 && extra.Count == 0,
            $"only C#:\n  {string.Join("\n  ", missing)}\nonly lake:\n  {string.Join("\n  ", extra)}");
        Assert.Equal(csharp.Select(Key), lake.Select(Key));
        // These files quote a cell only when it must be, as the lake writes a line: the lines are the same.
        Assert.Equal(csharp.Select(h => h.MatchingLine), lake.Select(h => h.MatchingLine));

        Assert.True(lake.Any(h => h.Module == "ToolX"),
            "modules: " + string.Join(", ", lake.Select(h => h.Host + ":" + h.Module + ":" + h.OutputFile).Distinct()));
        Assert.True(lake.Any(h => h.Module == "LNKFiles" && h.Ioc == @"C:\Staging\"),
            "LNK hits: " + string.Join("; ", lake.Where(h => h.OutputFile.Contains("LNKFiles")).Select(h => h.Ioc + " @" + h.LineNumber + " " + h.Module)));
        Assert.Contains(lake, h => h.Ioc == Sha1 && h.OutputFile.EndsWith("Amcache_UnassociatedFileEntries.csv") && h.LineNumber == 2);
        Assert.DoesNotContain(lake, h => h.Ioc == Sha1 && h.LineNumber == 4 && h.OutputFile.Contains("Amcache"));
        Assert.Contains(lake, h => h.Time == "2026-03-17 11:00:00");
    }

    [Fact]
    public void A_file_that_quotes_every_cell_differs_only_in_the_form_of_its_lines()
    {
        using var dir = new TempDirectory();
        Write(Path.Combine(dir.Path, "HOST01", "SystemInfo", "SystemInfo.csv"),
            "\"Category\",\"Item\",\"Value\",\"Source\"", "\"Identity\",\"Owner\",\"svc_backup\",\"SOFTWARE\"");
        IocList.Add(dir.Path, [IocEntry.Create(IocType.Account, "svc_backup")]);

        var (csharp, lake) = RunBoth(dir.Path);

        Assert.Equal(csharp.Select(Key), lake.Select(Key));
        Assert.Equal("\"Identity\",\"Owner\",\"svc_backup\",\"SOFTWARE\"", csharp.Single().MatchingLine);
        Assert.Equal("Identity,Owner,svc_backup,SOFTWARE", lake.Single().MatchingLine);
    }

    [Fact]
    public void Without_an_IOC_list_the_lake_writes_no_hits_file()
    {
        using var dir = new TempDirectory();
        Write(Path.Combine(dir.Path, "HOST01", "Tools", "Other.csv"), "A,B", "1,2");

        var result = LakeBuilder.Build(dir.Path, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30 });

        Assert.False(File.Exists(Path.Combine(IocResults.OutputRootFor(result.LakeDirectory!), IocResults.HitsFileName)));
        Assert.Contains("no IOCs.csv in the case", File.ReadAllText(Path.Combine(result.LakeDirectory!, LakeNames.LogFile)));
    }

    [Fact]
    public void A_list_without_a_Value_column_stops_both_rather_than_being_ignored()
    {
        using var dir = new TempDirectory();
        Write(Path.Combine(dir.Path, "HOST01", "Tools", "Other.csv"), "A,B", "1,2");
        File.WriteAllText(Path.Combine(dir.Path, IocList.FileName), "Kind,Thing\r\nIP,10.0.0.1\r\n");

        Assert.Throws<InvalidDataException>(() => IocList.Load(dir.Path));
        var lake = LakeBuilder.Build(dir.Path, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30 });
        Assert.Equal(LakeOutcome.BuiltCheckLog, lake.Outcome);
        Assert.Contains(lake.Warnings, w => w.Contains("IOC sweep queries failed") && w.Contains("Value column"));
    }
}
