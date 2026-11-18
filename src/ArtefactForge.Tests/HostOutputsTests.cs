using System.Text.Json;
using ArtefactForge.Core;
using ArtefactForge.Lake.Contract;

namespace ArtefactForge.Tests;

/// <summary>
/// &lt;Case&gt;\&lt;Host&gt;\outputs.json, which the evidence lake reads to know what produced each file,
/// and the lake option, which this build has no add-on for.
/// </summary>
public class HostOutputsTests
{
    private static readonly string Cmd = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private const string WritesAFile = @"/c echo hello> ""%destinationDirectory%\result.csv""";

    private static ModuleDefinition Module(string name, string commandLine, int? timeout = null,
        IterationMode iterate = IterationMode.None, string category = "Test") => new()
    {
        Description = name,
        Category = category,
        Version = "1.2",
        SourcePath = $@"C:\modules\{name}.forge",
        Iterate = iterate,
        Timeout = timeout,
        Processors = [new ProcessorDefinition { Executable = Cmd, CommandLine = commandLine }]
    };

    private static RunConfiguration Config(TempDirectory dir, ModuleDefinition[] modules, bool lake = false) => new()
    {
        CaseName = "CASE",
        OutputRoot = dir.Dir("out"),
        ToolRoots = [dir.Path],
        Targets =
        [
            new ResolvedTarget
            {
                SelectionPath = dir.Dir("evidence"),
                Root = dir.Dir("evidence"),
                CollectionName = "HOST01",
                Layout = new LayoutProfile
                {
                    Id = "test",
                    Name = "test",
                    Platform = Platform.Windows,
                    Detect = new LayoutDetectRules { Markers = ["x"] },
                    Resolve = new LayoutResolveRules()
                }
            }
        ],
        Modules = modules,
        MaxWorkers = 2,
        BuildLake = lake
    };

    /// <summary>A module's result as the engine records it, with one processor that delivered files.</summary>
    private static WorkResult Result(string hostDir, string module, string category, WorkStatus status,
        string executable, string arguments, string? iteration = null, string? folder = null, params string[] files)
    {
        var result = new WorkResult
        {
            Collection = Path.GetFileName(hostDir),
            Module = module,
            Category = category,
            Iteration = iteration,
            Status = status,
            Destination = folder ?? Path.Combine(hostDir, category),
            Started = new DateTimeOffset(2026, 11, 18, 10, 0, 0, TimeSpan.Zero),
            DurationSeconds = 30
        };
        result.Processors.Add(new ProcessorRecord
        {
            Executable = executable,
            Arguments = arguments,
            ToolVersion = "1.5.2.0",
            ToolSha256 = "DE16",
            OutputFiles = [.. files]
        });
        return result;
    }

    private static string Deliver(string hostDir, string relative, string text = "a,b\r\n1,2\r\n")
    {
        var full = Path.Combine(hostDir, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, text);
        return full;
    }

    private static List<WorkResult> Write(string caseDir, IReadOnlyList<WorkResult> results,
        IReadOnlyList<ModuleDefinition>? modules = null, IReadOnlyDictionary<string, HostContext>? hosts = null) =>
        HostOutputs.Write(caseDir, results, modules ?? [], hosts ?? new Dictionary<string, HostContext>(),
            new DateTime(2026, 11, 18, 11, 0, 0, DateTimeKind.Utc));

    private static OutputsManifest ReadList(string hostDir) =>
        OutputsManifestFile.Read(Path.Combine(hostDir, "outputs.json")) ?? throw new Xunit.Sdk.XunitException("no outputs.json");

    [Fact]
    public async Task A_run_writes_outputs_json_in_the_host_folder_listing_what_produced_each_file()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Writer", WritesAFile)]));

        Assert.Equal(0, report.NeedsReview);
        var list = ReadList(Path.Combine(report.CaseDirectory, "HOST01"));
        Assert.Equal("ArtefactForge", list.Producer.Name);
        Assert.Equal("HOST01", list.Host.Name);
        Assert.Equal(Platforms.Windows, list.Host.Platform);
        var entry = Assert.Single(list.Outputs);
        Assert.Equal("Test/Writer_result.csv", entry.Path);
        Assert.Equal("csv", entry.Format);
        Assert.Equal("cmd", entry.Parser);
        Assert.Equal("result.csv", entry.ToolFileName);
        Assert.Equal("Writer", entry.Module);
        Assert.Equal("1.2", entry.ModuleVersion);
        Assert.Equal(OutputStatus.Completed, entry.Status);
        Assert.Contains("result.csv", entry.Arguments);
        Assert.Equal(new FileInfo(Path.Combine(report.CaseDirectory, "HOST01", "Test", "Writer_result.csv")).Length, entry.Bytes);
        Assert.NotNull(entry.ProducedUtc);
    }

    [Fact]
    public async Task Status_is_written_as_a_word_never_the_enum_number()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Writer", WritesAFile)]));

        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(report.CaseDirectory, "HOST01", "outputs.json")));
        var status = doc.RootElement.GetProperty("outputs")[0].GetProperty("status");
        Assert.Equal(JsonValueKind.String, status.ValueKind);
        Assert.Equal("completed", status.GetString());
    }

    [Fact]
    public async Task Partial_output_of_a_timed_out_tool_is_never_listed()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir,
            [Module("HalfDone", @"/c echo partial> ""%destinationDirectory%\out.csv"" & ping -n 12 127.0.0.1 >nul", timeout: 2)]));

        Assert.Equal(WorkStatus.TimedOut, Assert.Single(report.Results).Status);
        var hostDir = Path.Combine(report.CaseDirectory, "HOST01");
        Assert.True(File.Exists(Path.Combine(hostDir, "_Incomplete", "Test", "HalfDone_out.csv")));
        Assert.Empty(ReadList(hostDir).Outputs);
    }

    [Fact]
    public void Partial_output_is_not_listed_even_when_a_finished_file_of_the_same_name_is_there()
    {
        // The finished file is an earlier run's; this run's file went to _Incomplete.
        using var dir = new TempDirectory();
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"Test\HalfDone_out.csv");
        Deliver(hostDir, @"_Incomplete\Test\HalfDone_out.csv");
        var result = Result(hostDir, "HalfDone", "Test", WorkStatus.TimedOut, Cmd, "/c x", files: "out.csv => HalfDone_out.csv");
        result.Processors[0] = new ProcessorRecord
        {
            Executable = Cmd, Arguments = "/c x", OutputFiles = ["out.csv => HalfDone_out.csv"],
            DeliveredTo = Path.Combine(hostDir, "_Incomplete", "Test")
        };

        Write(Path.GetDirectoryName(hostDir)!, [result]);

        Assert.Empty(ReadList(hostDir).Outputs);
    }

    [Fact]
    public void A_later_run_replaces_the_entries_of_files_it_rewrote_and_keeps_the_others()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"EventLogs\EvtxECmd_EventLogs.csv");
        Deliver(hostDir, @"Prefetch\PECmd_Output.csv");
        Write(caseDir,
        [
            Result(hostDir, "EvtxECmd", "EventLogs", WorkStatus.Completed, @"C:\Tools\EvtxECmd.exe", "first", files: "EvtxECmd_EventLogs.csv"),
            Result(hostDir, "PECmd", "Prefetch", WorkStatus.Completed, @"C:\Tools\PECmd.exe", "first",
                files: "20261118100301_PECmd_Output.csv => PECmd_Output.csv")
        ]);

        Write(caseDir,
        [
            Result(hostDir, "EvtxECmd", "EventLogs", WorkStatus.CheckLog, @"C:\Tools\EvtxECmd.exe", "second", files: "EvtxECmd_EventLogs.csv")
        ]);

        var outputs = ReadList(hostDir).Outputs;
        Assert.Equal(["EventLogs/EvtxECmd_EventLogs.csv", "Prefetch/PECmd_Output.csv"], outputs.Select(o => o.Path));
        Assert.Equal("second", outputs[0].Arguments);
        Assert.Equal(OutputStatus.CheckLog, outputs[0].Status);
        Assert.Equal("first", outputs[1].Arguments);
        Assert.Equal("20261118100301_PECmd_Output.csv", outputs[1].ToolFileName);
        Assert.Equal("PECmd", outputs[1].Parser);
    }

    [Fact]
    public void An_entry_whose_file_has_gone_is_dropped_on_the_next_run()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        var prefetch = Deliver(hostDir, @"Prefetch\PECmd_Output.csv");
        Deliver(hostDir, @"EventLogs\EvtxECmd_EventLogs.csv");
        Write(caseDir, [Result(hostDir, "PECmd", "Prefetch", WorkStatus.Completed, @"C:\Tools\PECmd.exe", "x", files: "PECmd_Output.csv")]);
        File.Delete(prefetch);

        Write(caseDir, [Result(hostDir, "EvtxECmd", "EventLogs", WorkStatus.Completed, @"C:\Tools\EvtxECmd.exe", "x", files: "EvtxECmd_EventLogs.csv")]);

        Assert.Equal("EventLogs/EvtxECmd_EventLogs.csv", Assert.Single(ReadList(hostDir).Outputs).Path);
    }

    [Fact]
    public void A_file_that_could_not_be_moved_into_the_host_folder_is_not_listed()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"Test\Writer_a.csv");

        Write(caseDir, [Result(hostDir, "Writer", "Test", WorkStatus.Failed, Cmd, "x",
            files: ["a.csv => Writer_a.csv", "b.csv => FAILED: the file is in use"])]);

        var entry = Assert.Single(ReadList(hostDir).Outputs);
        Assert.Equal("Test/Writer_a.csv", entry.Path);
        Assert.Equal(OutputStatus.Failed, entry.Status);
    }

    [Fact]
    public void Per_user_output_names_its_user()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"Registry\alice\alice_RECmd_NTUSER.csv");
        var module = Module("RECmd_NTUSER", "x", iterate: IterationMode.UserProfile, category: "Registry");

        Write(caseDir, [Result(hostDir, "RECmd_NTUSER", "Registry", WorkStatus.Completed, @"C:\Tools\RECmd.exe", "x",
            iteration: "alice", folder: Path.Combine(hostDir, "Registry", "alice"),
            files: "20261118_RECmd_Batch_NTUSER.csv => alice_RECmd_NTUSER.csv")], [module]);

        var entry = Assert.Single(ReadList(hostDir).Outputs);
        Assert.Equal("Registry/alice/alice_RECmd_NTUSER.csv", entry.Path);
        Assert.Equal("alice", entry.User);
        Assert.Equal("RECmd", entry.Parser);
    }

    [Fact]
    public void A_match_iteration_is_not_taken_for_a_user()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"Test\Writer_a.csv");
        var module = Module("Writer", "x", iterate: IterationMode.Match);

        Write(caseDir, [Result(hostDir, "Writer", "Test", WorkStatus.Completed, Cmd, "x", iteration: "Security.evtx",
            files: "a.csv => Writer_a.csv")], [module]);

        Assert.Null(Assert.Single(ReadList(hostDir).Outputs).User);
    }

    [Fact]
    public void Builtin_and_PowerShell_parsers_are_named_for_what_parsed_the_input()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"Linux\LinuxBodyfile.csv");
        Deliver(hostDir, @"Linux\LinuxAuth.csv");
        var script = dir.File(@"Scripts\linux\Parse-LinuxAuth.ps1");

        Write(caseDir,
        [
            Result(hostDir, "LinuxBodyfile", "Linux", WorkStatus.Completed, "builtin:LinuxBodyfile", "--root x",
                files: "LinuxBodyfile.csv"),
            Result(hostDir, "LinuxAuth", "Linux", WorkStatus.Completed,
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -Root \"x\" -Out \"y\"", files: "LinuxAuth.csv")
        ]);

        var outputs = ReadList(hostDir).Outputs;
        Assert.Equal("Parse-LinuxAuth", outputs[0].Parser);
        Assert.Equal(BuildInfo.InformationalVersion, outputs[0].ParserVersion);
        Assert.Equal(64, outputs[0].ParserSha256!.Length);
        Assert.Equal("LinuxBodyfile", outputs[1].Parser);
    }

    [Fact]
    public void ArtefactForges_own_analyses_are_listed_with_ArtefactForge_as_the_parser()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"IpHistory\IpHistory.csv");
        Deliver(hostDir, @"IpHistory\IpHistorySources.csv");
        Deliver(hostDir, @"Ransomware\RansomwareSummary.csv");
        Deliver(hostDir, @"DataAccess\Activity.csv");
        Deliver(hostDir, @"DataAccess\Users.csv");
        Deliver(hostDir, @"RemoteAccess\RemoteAccess.csv");
        WorkResult Derived(string module, WorkStatus status) => new()
        {
            Collection = "HOST01", Module = module, Category = module, Status = status,
            Destination = Path.Combine(hostDir, module)
        };

        Write(caseDir,
        [
            Derived("IpHistory", WorkStatus.Completed), Derived("Ransomware", WorkStatus.CheckLog),
            // DataAccess reports nothing when it writes its files without trouble, so they are
            // listed with no result of their own.
            // Found nothing new this time: the earlier run's file is not claimed for this run.
            Derived("RemoteAccess", WorkStatus.NoOutput)
        ]);

        var outputs = ReadList(hostDir).Outputs;
        Assert.Equal(
            ["DataAccess/Activity.csv", "DataAccess/Users.csv", "IpHistory/IpHistory.csv",
             "IpHistory/IpHistorySources.csv", "Ransomware/RansomwareSummary.csv"],
            outputs.Select(o => o.Path));
        Assert.All(outputs, o => Assert.Equal("ArtefactForge", o.Parser));
        Assert.Equal("DataAccess", outputs[1].Module);
        Assert.Equal(OutputStatus.Completed, outputs[1].Status);
        Assert.Equal(OutputStatus.CheckLog, outputs[4].Status);
        Assert.Equal("Ransomware", outputs[4].Module);
    }

    [Fact]
    public void An_analysis_that_failed_this_time_leaves_the_earlier_runs_entries_as_they_were()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"Ransomware\RansomwareSummary.csv");
        WorkResult Ransomware(WorkStatus status) => new()
        {
            Collection = "HOST01", Module = "Ransomware", Category = "Ransomware", Status = status,
            Destination = Path.Combine(hostDir, "Ransomware")
        };
        Write(caseDir, [Ransomware(WorkStatus.CheckLog)]);
        var before = Assert.Single(ReadList(hostDir).Outputs);

        Write(caseDir, [Ransomware(WorkStatus.Failed)]);

        Assert.Equal(before, Assert.Single(ReadList(hostDir).Outputs));
    }

    [Fact]
    public void Host_details_come_from_the_system_summary_and_the_collector()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        Deliver(hostDir, @"SystemInfo\SystemInfo.csv",
            "Category,Item,Value\r\nSystem,Hostname,WKS-01\r\nSystem,ProductName,Windows 11 Pro\r\n"
            + "System,Timezone,GMT Standard Time\r\nSystem,TimezoneActiveBiasMinutes,0\r\n");
        var collected = new DateTime(2026, 11, 17, 22, 41, 0, DateTimeKind.Utc);
        var hosts = new Dictionary<string, HostContext>(StringComparer.OrdinalIgnoreCase)
        {
            ["HOST01"] = new(Platform.Any, new CollectorTimes { CollectedUtc = collected, Collector = "velociraptor", TimeZone = "BST (UTC+01:00)" })
        };

        Write(caseDir, [Result(hostDir, "Writer", "Test", WorkStatus.Completed, Cmd, "x")], hosts: hosts);

        var host = ReadList(hostDir).Host;
        Assert.Equal("HOST01", host.Name);
        Assert.Equal("WKS-01", host.Hostname);
        Assert.Equal(Platforms.Windows, host.Platform);
        Assert.Equal("GMT Standard Time (UTC+00:00)", host.TimeZone);
        Assert.Equal(collected, host.CollectedUtc);
        Assert.Equal("velociraptor", host.Collector);
    }

    [Fact]
    public void Without_a_system_summary_the_time_zone_is_the_collectors()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        var hosts = new Dictionary<string, HostContext>(StringComparer.OrdinalIgnoreCase)
        {
            ["HOST01"] = new(Platform.Linux, new CollectorTimes { Collector = "uac", TimeZone = "BST (UTC+01:00)" })
        };

        Write(caseDir, [Result(hostDir, "Writer", "Test", WorkStatus.Completed, Cmd, "x")], hosts: hosts);

        var host = ReadList(hostDir).Host;
        Assert.Equal("BST (UTC+01:00)", host.TimeZone);
        Assert.Equal(Platforms.Linux, host.Platform);
        Assert.Null(host.Hostname);
    }

    [Fact]
    public void Case_wide_results_and_hosts_with_no_folder_get_no_outputs_json()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        dir.Dir(@"CASE\_Logs");
        var results = new List<WorkResult>
        {
            new() { Collection = "_Logs", Module = "x", Category = "x", Status = WorkStatus.Completed },
            new() { Collection = "GHOST", Module = "x", Category = "x", Status = WorkStatus.Failed }
        };

        Assert.Empty(Write(caseDir, results));
        Assert.False(File.Exists(Path.Combine(caseDir, "_Logs", "outputs.json")));
        Assert.False(Directory.Exists(Path.Combine(caseDir, "GHOST")));
    }

    [Fact]
    public void An_outputs_json_that_cannot_be_written_is_reported_and_does_not_throw()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        dir.Dir(@"CASE\HOST01\outputs.json.tmp");   // a folder where the temporary file must go

        var problems = Write(caseDir, [Result(hostDir, "Writer", "Test", WorkStatus.Completed, Cmd, "x")]);

        var problem = Assert.Single(problems);
        Assert.Equal("HOST01", problem.Collection);
        Assert.Equal(HostOutputs.ModuleName, problem.Module);
        Assert.Equal(WorkStatus.Failed, problem.Status);
        Assert.Contains("could not write outputs.json", problem.Reason);
    }

    [Fact]
    public void An_outputs_json_from_a_newer_format_is_left_alone_and_reported()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        var path = Path.Combine(hostDir, "outputs.json");
        var newer = "{\"format\":\"evidence-lake-outputs\",\"formatVersion\":2,\"producer\":{\"name\":\"Later\"},"
                    + "\"updatedUtc\":\"2027-01-01T00:00:00Z\",\"host\":{\"name\":\"HOST01\"},\"outputs\":[]}";
        File.WriteAllText(path, newer);

        var problem = Assert.Single(Write(caseDir, [Result(hostDir, "Writer", "Test", WorkStatus.Completed, Cmd, "x")]));

        Assert.Equal(WorkStatus.Failed, problem.Status);
        Assert.Contains("format version 2", problem.Reason);
        Assert.Equal(newer, File.ReadAllText(path));
    }

    [Fact]
    public void An_unreadable_outputs_json_is_written_again_from_this_run_and_flagged()
    {
        using var dir = new TempDirectory();
        var caseDir = dir.Dir("CASE");
        var hostDir = dir.Dir(@"CASE\HOST01");
        File.WriteAllText(Path.Combine(hostDir, "outputs.json"), "{ half a fi");
        Deliver(hostDir, @"Test\Writer_a.csv");

        var problem = Assert.Single(Write(caseDir,
            [Result(hostDir, "Writer", "Test", WorkStatus.Completed, Cmd, "x", files: "a.csv => Writer_a.csv")]));

        Assert.Equal(WorkStatus.CheckLog, problem.Status);
        Assert.Contains("files from earlier runs are not listed", problem.Reason);
        Assert.Equal("Test/Writer_a.csv", Assert.Single(ReadList(hostDir).Outputs).Path);
    }

    [Fact]
    public async Task A_run_asked_for_the_lake_says_the_add_on_is_not_installed_and_flags_it()
    {
        using var dir = new TempDirectory();
        var report = await new RunEngine().RunAsync(Config(dir, [Module("Writer", WritesAFile)], lake: true));

        var lake = Assert.Single(report.Results, r => r.Module == EvidenceLake.ModuleName);
        Assert.Equal(WorkStatus.ToolMissing, lake.Status);
        Assert.Equal(EvidenceLake.NotInstalled, lake.Reason);
        Assert.Equal(1, report.NeedsReview);
        Assert.False(Directory.Exists(Path.Combine(report.CaseDirectory, EvidenceLake.FolderName)));
    }

    [Fact]
    public async Task A_run_not_asked_for_the_lake_does_not_mention_it()
    {
        using var dir = new TempDirectory();
        var config = Config(dir, [Module("Writer", WritesAFile)]);
        Assert.False(config.BuildLake);

        var report = await new RunEngine().RunAsync(config);

        Assert.DoesNotContain(report.Results, r => r.Module == EvidenceLake.ModuleName);
        Assert.Equal(0, report.NeedsReview);
    }

    [Fact]
    public void The_lake_option_survives_a_saved_run_config()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "run.json");
        new RunRequest { Lake = true }.Save(path);

        Assert.Contains("\"Lake\": true", File.ReadAllText(path));
        Assert.True(RunRequest.Load(path).Lake);
        Assert.False(new RunRequest().Lake);
    }
}
