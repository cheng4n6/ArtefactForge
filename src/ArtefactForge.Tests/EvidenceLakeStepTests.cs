using System.Text.Json;
using ArtefactForge.Core;
using ArtefactForge.Core.Report;
using ArtefactForge.Lake;
using ArtefactForge.Lake.Contract;

namespace ArtefactForge.Tests;

public class EvidenceLakeStepTests
{
    private const long GB = 1L << 30;

    private const string Timeline = "RunTime,ExecutableName\r\n2026-11-01 09:21:00,\\VOLUME{01}\\WINDOWS\\SYSTEM32\\CMD.EXE\r\n";

    [Fact]
    public void The_lake_takes_free_memory_less_keep_free_and_the_runs_workers()
    {
        var options = EvidenceLakeStep.OptionsFor(maxWorkers: 6, keepFreeBytes: 2 * GB, freeBytes: 10 * GB);

        Assert.Equal(8 * GB, options.MemoryLimitBytes);
        Assert.Equal(6, options.Threads);
        Assert.StartsWith("ArtefactForge ", options.Producer);
    }

    [Fact]
    public void The_lake_gets_at_least_one_GB_and_one_thread_and_its_own_default_when_free_memory_is_unknown()
    {
        Assert.Equal(EvidenceLakeStep.MinimumMemoryBytes, EvidenceLakeStep.OptionsFor(0, 4 * GB, 3 * GB).MemoryLimitBytes);
        Assert.Equal(1, EvidenceLakeStep.OptionsFor(0, 0, 3 * GB).Threads);
        Assert.Null(EvidenceLakeStep.OptionsFor(4, GB, null).MemoryLimitBytes);
    }

    private static LakeResult Result(LakeOutcome outcome, params LakeSourceResult[] sources) => new()
    {
        Outcome = outcome, Message = "Built X: 1 host(s).", Sources = sources, TimelineRows = 12
    };

    private static LakeSourceResult Source(string status, long rejected = 0, long untimed = 0) => new()
    {
        SourceId = 1, Host = "HOST01", Path = "a.csv", Status = status, RowsRejected = rejected, TimeUnread = untimed
    };

    [Fact]
    public void A_clean_build_is_completed_and_anything_to_look_at_is_check_log_with_what_and_where()
    {
        Assert.Equal(WorkStatus.Completed, EvidenceLakeStep.Describe(Result(LakeOutcome.Built, Source("loaded"))).Status);

        var (status, reason) = EvidenceLakeStep.Describe(Result(LakeOutcome.BuiltCheckLog,
            Source("loaded"), Source("header_mismatch"), Source("failed"), Source("loaded", rejected: 3), Source("loaded", untimed: 7)));

        Assert.Equal(WorkStatus.CheckLog, status);
        Assert.Contains("1 with a header that does not fit", reason);
        Assert.Contains("1 not loaded", reason);
        Assert.Contains("1 with rows that could not be read (3 rows)", reason);
        Assert.Contains("1 with rows kept out of the timeline for want of a UTC time (7 rows)", reason);
        Assert.Contains(@"_Lake\lake.log", reason);
    }

    [Theory]
    [InlineData(LakeOutcome.NotSwapped)]
    [InlineData(LakeOutcome.Failed)]
    public void A_lake_not_built_or_not_swapped_in_is_failed_with_the_reason(LakeOutcome outcome)
    {
        var (status, reason) = EvidenceLakeStep.Describe(Result(outcome) with { Message = "could not be replaced." });
        Assert.Equal(WorkStatus.Failed, status);
        Assert.Equal("could not be replaced", reason);
    }

    [Fact]
    public void The_step_builds_the_lake_and_reports_it_as_one_case_result()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(@"HOST01\Prefetch\PECmd_Output_Timeline.csv"), Timeline);

        var result = EvidenceLakeStep.Build(dir.Path, maxWorkers: 2, keepFreeBytes: 0);

        Assert.Equal(WorkStatus.Completed, result.Status);
        Assert.Equal("(case)", result.Collection);
        Assert.Equal("EvidenceLake", result.Module);
        Assert.Equal(Path.Combine(dir.Path, "_Lake"), result.Destination);
        Assert.Contains("1 timeline rows", result.Reason);
    }

    [Fact]
    public void A_case_folder_with_no_hosts_fails_with_the_lakes_reason()
    {
        using var dir = new TempDirectory();
        dir.Dir("_Logs");

        var result = EvidenceLakeStep.Build(dir.Path, 2, 0);

        Assert.Equal(WorkStatus.Failed, result.Status);
        Assert.Contains("No host folders", result.Reason);
    }

    // --- back-fill --------------------------------------------------------------------------------

    private static string ManifestJson(string destination) => JsonSerializer.Serialize(new
    {
        Case = "CASE",
        Results = new object[]
        {
            new
            {
                Collection = "HOST01", Module = "PECmd", Category = "Prefetch", Status = (int)WorkStatus.Completed,
                Destination = destination, Started = DateTimeOffset.Parse("2026-11-01T10:00:00Z"), DurationSeconds = 5.0,
                Processors = new object[]
                {
                    new
                    {
                        Executable = @"C:\Tools\PECmd.exe", Arguments = "-d x --csv y", ToolVersion = "1.5.0.0",
                        ToolSha256 = "AB12", OutputFiles = new[] { "20261101100301_PECmd_Output_Timeline.csv => PECmd_Output_Timeline.csv" }
                    }
                }
            },
            new
            {
                Collection = "HOST01", Module = "LECmd_Recent", Category = "LNKFiles", Iteration = "alice", Status = 5,
                Destination = Path.Combine(Path.GetDirectoryName(destination)!, "LNKFiles", "alice"),
                Processors = new object[]
                {
                    new { Executable = @"C:\Tools\LECmd.exe", Arguments = "", ToolVersion = "1.5.1.0", OutputFiles = new[] { "x.csv => alice_LECmd_Recent.csv" } }
                }
            }
        }
    });

    private static OutputsManifest ReadOutputs(string hostDir) => OutputsManifestFile.Read(OutputsManifestFile.PathIn(hostDir))!;

    [Fact]
    public void A_host_without_outputs_json_gets_one_from_the_last_run_manifest_and_its_files()
    {
        using var dir = new TempDirectory();
        var hostDir = dir.Dir("HOST01");
        var prefetch = dir.Dir(@"HOST01\Prefetch");
        File.WriteAllText(Path.Combine(prefetch, "PECmd_Output_Timeline.csv"), Timeline);
        File.WriteAllText(dir.File(@"HOST01\LNKFiles\alice\alice_LECmd_Recent.csv"), "SourceFile\r\na.lnk\r\n");
        File.WriteAllText(dir.File(@"HOST01\FileSystem\MFTECmd_MFT.csv"), "EntryNumber\r\n1\r\n");
        File.WriteAllText(dir.File(@"HOST01\_Incomplete\FileSystem\MFTECmd_J.csv"), "x\r\n");
        File.WriteAllText(dir.File(@"_Logs\manifest.json"), ManifestJson(prefetch));

        var result = HostOutputs.BackFill(dir.Path, new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc));

        Assert.Equal(["HOST01"], result.Hosts);
        Assert.True(result.FromManifest);
        var outputs = ReadOutputs(hostDir).Outputs.ToDictionary(o => o.Path);
        Assert.Equal(3, outputs.Count);

        var listed = outputs["Prefetch/PECmd_Output_Timeline.csv"];
        Assert.Equal("PECmd", listed.Parser);
        Assert.Equal("1.5.0.0", listed.ParserVersion);
        Assert.Equal("20261101100301_PECmd_Output_Timeline.csv", listed.ToolFileName);
        Assert.Equal(OutputStatus.Completed, listed.Status);

        // Listed with status 5 (Failed) in the manifest: the status is kept, never read as complete.
        var lnk = outputs["LNKFiles/alice/alice_LECmd_Recent.csv"];
        Assert.Equal(OutputStatus.Failed, lnk.Status);
        Assert.Equal("alice", lnk.User);

        var alone = outputs["FileSystem/MFTECmd_MFT.csv"];
        Assert.Equal("MFTECmd", alone.Parser);
        Assert.Null(alone.ParserVersion);
        Assert.Equal("MFTECmd_MFT.csv", alone.ToolFileName);
        Assert.Equal(OutputStatus.Completed, alone.Status);
    }

    [Fact]
    public void A_case_moved_since_its_run_still_takes_versions_from_its_manifest()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(@"HOST01\Prefetch\PECmd_Output_Timeline.csv"), Timeline);
        File.WriteAllText(dir.File(@"HOST01\LNKFiles\alice_LECmd_Recent.csv"), "SourceFile\r\na.lnk\r\n");
        // Written where the case was at the time of its run.
        File.WriteAllText(dir.File(@"_Logs\manifest.json"), ManifestJson(@"Z:\elsewhere\CASE\HOST01\Prefetch")
            .Replace(@"Z:\\elsewhere\\CASE\\HOST01\\LNKFiles\\alice", @"Z:\\elsewhere\\CASE\\HOST01\\LNKFiles"));

        HostOutputs.BackFill(dir.Path, DateTime.UtcNow);

        var outputs = ReadOutputs(Path.Combine(dir.Path, "HOST01")).Outputs.ToDictionary(o => o.Path);
        Assert.Equal("1.5.0.0", outputs["Prefetch/PECmd_Output_Timeline.csv"].ParserVersion);
        // An earlier layout put a user's file straight in the category folder.
        var lnk = outputs["LNKFiles/alice_LECmd_Recent.csv"];
        Assert.Equal("1.5.1.0", lnk.ParserVersion);
        Assert.Equal("alice", lnk.User);
    }

    [Fact]
    public void A_host_without_a_manifest_entry_is_back_filled_from_its_files_with_the_user_taken_from_its_folder()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(@"HOST01\LNKFiles\alice\alice_LECmd_Recent.csv"), "SourceFile\r\na.lnk\r\n");
        File.WriteAllText(dir.File(@"HOST01\Ransomware\RansomwareSummary.csv"), "Collection\r\nHOST01\r\n");

        var result = HostOutputs.BackFill(dir.Path, DateTime.UtcNow);

        Assert.False(result.FromManifest);
        var outputs = ReadOutputs(Path.Combine(dir.Path, "HOST01")).Outputs.ToDictionary(o => o.Path);
        var lnk = outputs["LNKFiles/alice/alice_LECmd_Recent.csv"];
        Assert.Equal("alice", lnk.User);
        Assert.Equal("LECmd", lnk.Parser);
        Assert.Equal("LECmd_Recent.csv", lnk.ToolFileName);
        Assert.Equal("ArtefactForge", outputs["Ransomware/RansomwareSummary.csv"].Parser);
    }

    [Fact]
    public void A_host_that_has_outputs_json_is_left_alone()
    {
        using var dir = new TempDirectory();
        var hostDir = dir.Dir("HOST01");
        File.WriteAllText(dir.File(@"HOST01\Prefetch\PECmd_Output_Timeline.csv"), Timeline);
        File.WriteAllText(OutputsManifestFile.PathIn(hostDir), "{ \"keep\": \"me\" }");

        var result = HostOutputs.BackFill(dir.Path, DateTime.UtcNow);

        Assert.Empty(result.Hosts);
        Assert.Equal("{ \"keep\": \"me\" }", File.ReadAllText(OutputsManifestFile.PathIn(hostDir)));
    }

    [Fact]
    public void The_lake_log_says_which_hosts_were_back_filled()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(@"HOST01\Prefetch\PECmd_Output_Timeline.csv"), Timeline);
        var messages = new List<string>();

        var result = EvidenceLakeStep.Build(dir.Path, 2, 0, new Collector(messages));

        Assert.Equal(WorkStatus.Completed, result.Status);
        var log = File.ReadAllText(Path.Combine(dir.Path, "_Lake", "lake.log"));
        Assert.Contains("outputs.json written from the files on disk for host(s) that had none: HOST01", log);
        Assert.Contains(messages, m => m.Contains("found from outputs.json"));
    }

    [Fact]
    public void Manifest_results_are_read_with_their_processors_and_status_numbers()
    {
        var results = HostOutputs.ReadManifestResults(ManifestJson(@"C:\case\HOST01\Prefetch"));

        Assert.Equal(2, results.Count);
        Assert.Equal(WorkStatus.Completed, results[0].Status);
        Assert.Equal(WorkStatus.Failed, results[1].Status);
        Assert.Equal("alice", results[1].Iteration);
        Assert.Equal("1.5.0.0", Assert.Single(results[0].Processors).ToolVersion);
        Assert.Throws<InvalidDataException>(() => HostOutputs.ReadManifestResults("{}"));
    }

    // --- status, overview line and report -----------------------------------------------------

    private static void WriteBuild(TempDirectory dir, string result, int mismatched = 0, string message = "m")
    {
        File.WriteAllText(dir.File(@"_Lake\build.json"), JsonSerializer.Serialize(new
        {
            format = "evidence-lake-build", startedUtc = "2026-11-18T10:15:00Z", result, message,
            database = result == "notswapped" ? "case.duckdb.new" : "case.duckdb",
            hosts = new[] { "HOST01", "HOST02" }, timelineRows = 1234567, sourcesLoaded = 9,
            sourcesHeaderMismatch = mismatched, sourcesFailed = 0, warnings = Array.Empty<string>()
        }));
    }

    [Fact]
    public void A_case_with_no_lake_has_no_status()
    {
        using var dir = new TempDirectory();
        Assert.Null(EvidenceLakeStep.Status(dir.Path));
    }

    [Fact]
    public void A_clean_build_reads_as_built_with_its_hosts_and_rows_and_needs_no_attention()
    {
        using var dir = new TempDirectory();
        WriteBuild(dir, "built");

        var status = EvidenceLakeStep.Status(dir.Path)!;

        Assert.False(status.NeedsAttention);
        Assert.True(status.HasLake);
        Assert.Equal(2, status.Hosts);
        Assert.Contains("2 hosts, 1,234,567 timeline rows", status.Describe());
        Assert.StartsWith("Built ", status.Describe());
    }

    [Theory]
    [InlineData("checklog", "2 sources need a look", true)]
    [InlineData("notswapped", "case.duckdb.new", true)]
    [InlineData("failed", "failed: could not list", false)]
    public void A_build_that_needs_a_look_says_so_and_is_marked_for_attention(string result, string expected, bool hasLake)
    {
        using var dir = new TempDirectory();
        WriteBuild(dir, result, mismatched: 2, message: "could not list the host folders");

        var status = EvidenceLakeStep.Status(dir.Path)!;

        Assert.True(status.NeedsAttention);
        Assert.Equal(hasLake, status.HasLake);
        Assert.Contains(expected, status.Describe());
    }

    [Fact]
    public void An_unreadable_build_record_is_reported_not_taken_as_no_lake()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(@"_Lake\build.json"), "{ not json");

        var status = EvidenceLakeStep.Status(dir.Path)!;

        Assert.True(status.NeedsAttention);
        Assert.Contains("could not be read", status.Describe());
    }

    [Fact]
    public void The_case_report_shows_the_lake_only_once_one_has_been_built()
    {
        using var dir = new TempDirectory();
        dir.Dir("HOST01");
        var context = new CaseReportContext { CaseDirectory = dir.Path, Hosts = [], GeneratedUtc = DateTime.UtcNow };
        var section = CaseReport.Sections.Single(s => s.GetType().Name == "EvidenceLakeSection");

        Assert.Null(section.Build(context));

        WriteBuild(dir, "checklog", mismatched: 1);
        var built = section.Build(context)!;
        Assert.Contains("1 source need a look", System.Net.WebUtility.HtmlDecode(built.Body));
        Assert.Equal("lake", Assert.Single(built.Findings).SectionId);
    }

    [Fact]
    public void The_build_lake_run_option_is_saved_and_off_by_default()
    {
        Assert.False(new SavedRunOptions().BuildLake);
        Assert.True(new SavedRunOptions { BuildLake = true }.Clamped().BuildLake);
    }

    private sealed class Collector(List<string> lines) : IProgress<string>
    {
        public void Report(string value) => lines.Add(value);
    }
}
