using ArtefactForge.Lake.Cli;
using ArtefactForge.Lake.Queries;
using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

/// <summary>The saved queries: their headers, the session that runs them, and af-lake's query commands.</summary>
public class LakeQueryTests
{
    private static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    [Fact]
    public void Every_saved_query_has_a_header_and_what_it_requires_is_a_setup_query()
    {
        Assert.NotEmpty(LakeQueryCatalogue.All);
        foreach (var query in LakeQueryCatalogue.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(query.Title), query.Name);
            Assert.False(string.IsNullOrWhiteSpace(query.Category), query.Name);
            Assert.False(string.IsNullOrWhiteSpace(query.Description), query.Name);
            Assert.DoesNotContain('—', query.Sql);   // house style: no em dashes
            foreach (var required in query.Requires)
                Assert.True(LakeQueryCatalogue.Find(required)?.IsSetup, $"{query.Name} requires {required}");
        }
        Assert.True(LakeQueryCatalogue.Find("ransomware_prepare")!.IsSetup);
        Assert.Contains(LakeQueryCatalogue.Find("ransomware_prepare")!.Parameters, p => p is { Name: "usn_min_files", Default: "50" });
    }

    [Fact]
    public void A_header_block_gives_the_fields_continuation_lines_inputs_tables_and_parameters()
    {
        var query = LakeQuery.Parse("example", string.Join("\n",
            "-- title: An example",
            "-- category: test",
            "-- severity: low",
            "-- description: First part,",
            "--   and the rest.",
            "-- requires: a_setup, another",
            "-- input: my_list = List.csv (Name, Value)",
            "-- table: raw_thing (A, B)",
            "-- parameter: limit = 10 - how many",
            "SELECT 1"));

        Assert.Equal(("An example", "test", "low"), (query.Title, query.Category, query.Severity));
        Assert.Equal("First part, and the rest.", query.Description);
        Assert.Equal(["a_setup", "another"], query.Requires);
        var input = query.Inputs.Single();
        Assert.Equal(("my_list", "List.csv"), (input.Table, input.FileName));
        Assert.Equal(["Name", "Value"], input.Columns);
        Assert.Equal(["A", "B"], query.Tables.Single().Columns);
        Assert.Equal(new LakeQueryParameter("limit", "10", "how many"), query.Parameters.Single());
        Assert.False(query.IsSetup);
        Assert.Throws<InvalidDataException>(() => LakeQuery.Parse("bad", "-- category: x\nSELECT 1"));
    }

    [Fact]
    public void A_lake_with_no_MFTECmd_output_runs_the_ransomware_queries_and_says_each_host_was_not_checked()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        var result = LakeBuilder.Build(temp.Path, Small);
        Assert.Equal(LakeOutcome.Built, result.Outcome);

        using var session = new LakeQuerySession(result.DatabasePath!, temp.Path);
        var rows = session.RunToRows(LakeQueryCatalogue.Find("ransomware_hosts")!);

        Assert.Equal(("HOST01", "Not checked"), (rows.Single()["Collection"], rows.Single()["Status"]));
        // No host checked, so no case file, as the Ransomware step does.
        Assert.False(File.Exists(Path.Combine(RansomwareResults.OutputRootFor(result.LakeDirectory!), RansomwareResults.CaseFileName)));
    }

    [Fact]
    public void Queries_open_the_lake_read_only_so_running_them_leaves_it_as_it_was()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        var result = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false });
        var before = File.ReadAllBytes(result.DatabasePath!);

        using (var session = new LakeQuerySession(result.DatabasePath!, temp.Path))
        {
            session.RunToRows(LakeQueryCatalogue.Find("ransomware_case")!);
            Assert.ThrowsAny<System.Data.Common.DbException>(() => session.Execute("CREATE TABLE main.scribble (x INTEGER)"));
        }

        Assert.Equal(before, File.ReadAllBytes(result.DatabasePath!));
        Assert.False(Directory.Exists(Path.Combine(result.LakeDirectory!, LakeNames.ResultsFolder)));
    }

    [Fact]
    public void A_parameter_given_replaces_the_default_the_query_runs_with()
    {
        using var temp = new TempDirectory();
        // 60 renames adding .crypt to six types across six folders: enough at the default of 50.
        var usn = new System.Text.StringBuilder(string.Join(',', UsnHeader) + "\r\n");
        string[] types = ["docx", "xlsx", "pdf", "jpg", "png", "csv"];
        for (var i = 0; i < 60; i++)
        {
            var name = $"f{i}.{types[i % 6]}";
            var folder = $".\\Users\\alice\\Documents\\D{i % 6}";
            usn.Append($"{name},,{7000 + i},2,5,5,{folder},1,2026-11-01 09:30:{i % 60:00}.0000000,RenameOldName,Archive,0,x\r\n");
            usn.Append($"{name}.crypt,,{7000 + i},2,5,5,{folder},2,2026-11-01 09:30:{i % 60:00}.0000000,RenameNewName|Close,Archive,0,x\r\n");
        }
        temp.Write(@"HOST01\FileSystem\MFTECmd_USNJournal.csv", usn.ToString());
        var result = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false });
        var query = LakeQueryCatalogue.Find("ransomware_hosts")!;

        using (var session = new LakeQuerySession(result.DatabasePath!, temp.Path))
            Assert.Equal(".crypt", session.RunToRows(query).Single()["Extension"]);
        using (var stricter = new LakeQuerySession(result.DatabasePath!, temp.Path,
                   new Dictionary<string, string> { ["usn_min_files"] = "100" }))
            Assert.Equal("None found", stricter.RunToRows(query).Single()["Status"]);
    }

    [Fact]
    public void The_command_line_lists_the_queries_and_runs_one_into_a_CSV()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        var error = new StringWriter();
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["build", temp.Path, "--memory-gb", "0.5", "--threads", "2"], new StringWriter(), error));

        var list = new StringWriter();
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["queries"], list, error));
        Assert.Contains("ransomware_hosts", list.ToString());
        Assert.Contains("--param usn_min_files=50", list.ToString());

        var output = new StringWriter();
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["query", temp.Path, "ransomware_hosts"], output, error));
        var csv = Path.Combine(temp.Path, "_Lake", "results", "ransomware_hosts.csv");
        Assert.StartsWith("\"Collection\",\"Host\",\"Status\"", File.ReadAllLines(csv)[0].TrimStart('﻿'));

        Assert.Equal(LakeCli.ExitUsage, LakeCli.Run(["query", temp.Path, "no_such_query"], new StringWriter(), error));
        Assert.Equal(LakeCli.ExitUsage, LakeCli.Run(["query", temp.Path, "ransomware_prepare"], new StringWriter(), error));
        Assert.Equal(LakeCli.ExitUsage,
            LakeCli.Run(["query", temp.Path, "ransomware_hosts", "--param", "nonsense=1"], new StringWriter(), error));
    }

    [Fact]
    public void A_lake_build_writes_the_ransomware_files_beside_the_lake_and_logs_it()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");

        var result = LakeBuilder.Build(temp.Path, Small);

        var root = RansomwareResults.OutputRootFor(result.LakeDirectory!);
        Assert.True(File.Exists(Path.Combine(root, RansomwareResults.CaseFileName)));
        Assert.True(File.Exists(Path.Combine(root, "HOST01", "Ransomware", RansomwareResults.SummaryFileName)));
        Assert.True(File.Exists(Path.Combine(root, "HOST01", "Ransomware", RansomwareResults.EvidenceFileName)));
        Assert.Contains("Ransomware from the lake's queries", File.ReadAllText(Path.Combine(result.LakeDirectory!, LakeNames.LogFile)));
    }
}
