using System.Text.Json;
using System.Xml.Linq;
using ArtefactForge.Core;
using ArtefactForge.Lake.Contract;

namespace ArtefactForge.Tests;

/// <summary>
/// The outputs.json contract the evidence lake reads. It is shared with a program that knows
/// nothing of ArtefactForge, so its shape and its independence are both tested here.
/// </summary>
public class LakeContractTests
{
    private static OutputsManifest Manifest(params OutputEntry[] outputs) => new()
    {
        Producer = new OutputsProducer { Name = "ArtefactForge", Version = "0.6.0", Build = "0.6.0+abc1234" },
        UpdatedUtc = new DateTime(2026, 11, 18, 10, 15, 2, 345, DateTimeKind.Utc),
        Host = new OutputsHost { Name = "HOST01", Hostname = "HOST01", Platform = Platforms.Windows },
        Outputs = outputs
    };

    private static OutputEntry Entry(string path, string arguments = "--csv x") => new()
    {
        Path = path,
        Format = "csv",
        Parser = "EvtxECmd",
        ParserVersion = "1.5.2.0",
        Arguments = arguments,
        Status = OutputStatus.Completed,
        ProducedUtc = new DateTime(2026, 11, 18, 10, 2, 44, DateTimeKind.Utc),
        Bytes = 12
    };

    [Fact]
    public void Lake_contract_references_no_other_ArtefactForge_assembly()
    {
        // Every assembly the engine's side of the solution builds, as loaded here.
        string[] engine = [typeof(RunEngine).Assembly.GetName().Name!, typeof(LakeContractTests).Assembly.GetName().Name!];
        var references = typeof(OutputsManifest).Assembly.GetReferencedAssemblies().Select(r => r.Name!).ToList();

        Assert.DoesNotContain(references, engine.Contains);
        Assert.DoesNotContain(references, r => r.StartsWith("ArtefactForge", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Lake_contract_project_has_no_project_or_package_references()
    {
        // The compiled references only show what the code uses; the project file shows what a
        // later change might add before any code uses it.
        var project = FindProjectFile();
        var root = XDocument.Load(project).Root!;

        Assert.Empty(root.Descendants("ProjectReference"));
        Assert.Empty(root.Descendants("PackageReference"));
    }

    private static string FindProjectFile()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "src", "ArtefactForge.Lake.Contract", "ArtefactForge.Lake.Contract.csproj");
            if (File.Exists(candidate)) return candidate;
        }
        throw new Xunit.Sdk.XunitException("ArtefactForge.Lake.Contract.csproj not found above the test folder.");
    }

    [Fact]
    public void Lake_contract_depends_on_nothing_but_the_runtime()
    {
        var references = typeof(OutputsManifest).Assembly.GetReferencedAssemblies();
        Assert.All(references, r => Assert.True(
            r.Name!.StartsWith("System", StringComparison.Ordinal) || r.Name == "netstandard",
            $"{r.Name} is not part of the runtime"));
    }

    [Fact]
    public void An_outputs_list_survives_a_round_trip_through_json()
    {
        var manifest = Manifest(Entry("EventLogs/EvtxECmd_EventLogs.csv"));

        var read = OutputsManifestFile.Parse(OutputsManifestFile.Serialise(manifest));

        Assert.Equal(OutputsManifest.FormatName, read.Format);
        Assert.Equal(1, read.FormatVersion);
        Assert.Equal("HOST01", read.Host.Name);
        var entry = Assert.Single(read.Outputs);
        Assert.Equal(manifest.Outputs[0], entry);
    }

    [Fact]
    public void Names_are_camel_case_status_is_a_word_and_times_are_utc_to_the_second()
    {
        var json = OutputsManifestFile.Serialise(Manifest(Entry("EventLogs/EvtxECmd_EventLogs.csv")));

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("evidence-lake-outputs", root.GetProperty("format").GetString());
        Assert.Equal("2026-11-18T10:15:02Z", root.GetProperty("updatedUtc").GetString());
        var entry = root.GetProperty("outputs")[0];
        Assert.Equal(JsonValueKind.String, entry.GetProperty("status").ValueKind);
        Assert.Equal("completed", entry.GetProperty("status").GetString());
        Assert.Equal("2026-11-18T10:02:44Z", entry.GetProperty("producedUtc").GetString());
        Assert.Equal(JsonValueKind.Null, entry.GetProperty("user").ValueKind);
    }

    [Fact]
    public void A_time_without_an_offset_is_read_as_utc()
    {
        var json = OutputsManifestFile.Serialise(Manifest()).Replace("2026-11-18T10:15:02Z", "2026-11-18T10:15:02");

        var read = OutputsManifestFile.Parse(json);

        Assert.Equal(DateTimeKind.Utc, read.UpdatedUtc.Kind);
        Assert.Equal(new DateTime(2026, 11, 18, 10, 15, 2, DateTimeKind.Utc), read.UpdatedUtc);
    }

    [Fact]
    public void A_file_from_a_newer_format_version_is_refused_not_read_as_empty()
    {
        var json = OutputsManifestFile.Serialise(Manifest() with { FormatVersion = 2 });

        var ex = Assert.Throws<UnsupportedFormatVersionException>(() => OutputsManifestFile.Parse(json));
        Assert.Equal(2, ex.FormatVersion);
    }

    [Fact]
    public void A_file_that_is_not_an_outputs_list_is_refused()
    {
        Assert.Throws<InvalidDataException>(() => OutputsManifestFile.Parse("{\"format\":\"something-else\",\"producer\":{\"name\":\"x\"},\"host\":{\"name\":\"h\"}}"));
        Assert.Throws<InvalidDataException>(() => OutputsManifestFile.Parse("not json"));
        Assert.Throws<InvalidDataException>(() => OutputsManifestFile.Parse("null"));
    }

    [Fact]
    public void A_missing_file_reads_as_none()
    {
        using var dir = new TempDirectory();
        Assert.Null(OutputsManifestFile.Read(Path.Combine(dir.Path, "outputs.json")));
    }

    [Fact]
    public void Merging_replaces_rewritten_files_keeps_the_rest_and_drops_files_that_have_gone()
    {
        using var dir = new TempDirectory();
        dir.File(@"EventLogs\EvtxECmd_EventLogs.csv");
        dir.File(@"Prefetch\PECmd_Output.csv");
        var existing = Manifest(
            Entry("EventLogs/EvtxECmd_EventLogs.csv", "old"),
            Entry("Prefetch/PECmd_Output.csv", "kept"),
            Entry("Amcache/Gone.csv", "gone"));
        var update = Manifest(Entry("EventLogs/EvtxECmd_EventLogs.csv", "new"));

        var merged = OutputsManifestFile.Merge(existing, update, dir.Path);

        Assert.Equal(["EventLogs/EvtxECmd_EventLogs.csv", "Prefetch/PECmd_Output.csv"], merged.Outputs.Select(o => o.Path));
        Assert.Equal("new", merged.Outputs[0].Arguments);
        Assert.Equal("kept", merged.Outputs[1].Arguments);
    }

    [Fact]
    public void Merging_matches_paths_whatever_their_case_or_separators()
    {
        using var dir = new TempDirectory();
        dir.File(@"EventLogs\EvtxECmd_EventLogs.csv");
        var existing = Manifest(Entry(@"eventlogs\evtxecmd_eventlogs.csv", "old"));
        var update = Manifest(Entry("EventLogs/EvtxECmd_EventLogs.csv", "new"));

        var merged = OutputsManifestFile.Merge(existing, update, dir.Path);

        Assert.Equal("new", Assert.Single(merged.Outputs).Arguments);
    }

    [Fact]
    public void Merging_never_lists_files_under_Incomplete_or_outside_the_host_folder()
    {
        using var dir = new TempDirectory();
        var host = dir.Dir("HOST01");
        dir.File(@"HOST01\_Incomplete\EventLogs\EvtxECmd_EventLogs.csv");
        dir.File("Other.csv");
        var update = Manifest(
            Entry("_Incomplete/EventLogs/EvtxECmd_EventLogs.csv"),
            Entry("../Other.csv"),
            Entry(Path.Combine(dir.Path, "Other.csv")));

        Assert.Empty(OutputsManifestFile.Merge(null, update, host).Outputs);
    }

    [Fact]
    public void Merging_keeps_host_details_the_update_does_not_know()
    {
        using var dir = new TempDirectory();
        var existing = Manifest() with
        {
            Host = new OutputsHost { Name = "HOST01", Hostname = "HOST01", TimeZone = "GMT Standard Time", Collector = "kape" }
        };
        var update = Manifest() with { Host = new OutputsHost { Name = "HOST01", Platform = Platforms.Windows } };

        var merged = OutputsManifestFile.Merge(existing, update, dir.Path);

        Assert.Equal("HOST01", merged.Host.Hostname);
        Assert.Equal("GMT Standard Time", merged.Host.TimeZone);
        Assert.Equal("kape", merged.Host.Collector);
        Assert.Equal(Platforms.Windows, merged.Host.Platform);
    }

    [Fact]
    public void Writing_replaces_the_file_whole_and_leaves_no_temporary_file()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, OutputsManifestFile.FileName);
        File.WriteAllText(path, "old");

        OutputsManifestFile.Write(path, Manifest(Entry("a.csv")));

        Assert.Equal("a.csv", Assert.Single(OutputsManifestFile.Read(path)!.Outputs).Path);
        Assert.Equal([path], Directory.GetFiles(dir.Path));
    }

    [Fact]
    public void The_schema_names_every_property_the_records_write_and_requires_the_contract_fields()
    {
        using var schema = JsonDocument.Parse(OutputsManifestFile.Schema());
        using var written = JsonDocument.Parse(OutputsManifestFile.Serialise(Manifest(Entry("a.csv"))));
        var root = schema.RootElement;

        Names(root.GetProperty("properties")).ShouldCover(written.RootElement);
        Names(root.GetProperty("properties").GetProperty("producer").GetProperty("properties"))
            .ShouldCover(written.RootElement.GetProperty("producer"));
        Names(root.GetProperty("properties").GetProperty("host").GetProperty("properties"))
            .ShouldCover(written.RootElement.GetProperty("host"));
        var output = root.GetProperty("$defs").GetProperty("output");
        Names(output.GetProperty("properties")).ShouldCover(written.RootElement.GetProperty("outputs")[0]);

        Assert.Equal(["path", "parser", "status"], output.GetProperty("required").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(
            ["completed", "checklog", "nooutput", "failed", "timedout", "cancelled"],
            output.GetProperty("properties").GetProperty("status").GetProperty("enum").EnumerateArray().Select(e => e.GetString()));
    }

    private static HashSet<string> Names(JsonElement properties) =>
        properties.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
}

internal static class SchemaAssertions
{
    /// <summary>Every property in <paramref name="written"/> is described by the schema.</summary>
    public static void ShouldCover(this HashSet<string> schemaNames, JsonElement written)
    {
        foreach (var property in written.EnumerateObject())
            Assert.True(schemaNames.Contains(property.Name), $"the schema does not describe '{property.Name}'");
    }
}
