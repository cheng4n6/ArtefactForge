using ArtefactForge.Lake.Cli;
using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

public sealed class LakeRulesTests
{
    [Fact]
    public void Every_connection_turns_off_extension_downloads_and_sets_memory_threads_and_spill_folder()
    {
        using var temp = new TempDirectory();
        var spill = Path.Combine(temp.Path, "spill");
        var options = new LakeOptions { MemoryLimitBytes = 768L * 1024 * 1024, Threads = 3 };

        using var db = LakeDatabase.Open(Path.Combine(temp.Path, "x.duckdb"), options, spill);

        Assert.Equal(false, Scalar(db, "SELECT current_setting('autoinstall_known_extensions')"));
        Assert.Equal(false, Scalar(db, "SELECT current_setting('autoload_known_extensions')"));
        Assert.Equal(false, Scalar(db, "SELECT current_setting('allow_community_extensions')"));
        Assert.Equal(3L, Convert.ToInt64(Scalar(db, "SELECT current_setting('threads')")));
        Assert.Equal("768.0 MiB", Scalar(db, "SELECT current_setting('memory_limit')"));
        Assert.Equal(spill, Scalar(db, "SELECT current_setting('temp_directory')"));
        // Locked, so no SQL run later (a mapping, a saved query) can turn them back on.
        Assert.ThrowsAny<Exception>(() => LakeDatabase.Execute(db, "SET autoload_known_extensions = true"));
    }

    [Fact]
    public void The_settings_in_force_are_recorded_in_the_lake()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");

        LakeBuilder.Build(temp.Path, new LakeOptions { Threads = 2, MemoryLimitBytes = 1L << 30, Producer = "test" });

        using var lake = OpenLake(Path.Combine(temp.Path, "_Lake", "case.duckdb"));
        var meta = Rows(lake, "SELECT key, value FROM lake_meta").ToDictionary(r => (string)r["key"]!, r => r["value"] as string);
        Assert.Equal("false", meta["setting.autoinstall_known_extensions"]?.ToLowerInvariant());
        Assert.Equal("false", meta["setting.autoload_known_extensions"]?.ToLowerInvariant());
        Assert.Equal("2", meta["setting.threads"]);
        Assert.Equal("1", meta["lake_format_version"]);
        Assert.Equal("test", meta["producer"]);
        Assert.StartsWith("v", meta["duckdb_version"]);
    }

    [Fact]
    public void The_lake_library_references_only_the_contract_DuckDB_and_the_base_class_library()
    {
        var references = typeof(LakeBuilder).Assembly.GetReferencedAssemblies().Select(r => r.Name!).ToList();

        Assert.Contains("ArtefactForge.Lake.Contract", references);
        Assert.Contains(references, r => r.StartsWith("DuckDB.NET", StringComparison.Ordinal));
        var others = references.Where(r =>
                !(r == "ArtefactForge.Lake.Contract"
                  || r.StartsWith("DuckDB.NET.", StringComparison.Ordinal)
                  || r.StartsWith("System", StringComparison.Ordinal)
                  || r is "netstandard" or "mscorlib" or "Microsoft.Win32.Primitives"))
            .ToList();
        Assert.Empty(others);
    }

    [Theory]
    [InlineData("20261118100301_PECmd_Output.csv", null, "PECmd_Output.csv")]
    [InlineData("PECmd_Output.csv", null, "PECmd_Output.csv")]
    [InlineData("alice_LECmd_Recent.csv", "alice", "LECmd_Recent.csv")]
    [InlineData("20261118100301_alice_LECmd_Recent.csv", "alice", "LECmd_Recent.csv")]
    [InlineData("Amcache_ProgramEntries.csv", null, "Amcache_ProgramEntries.csv")]
    public void File_names_lose_a_tool_timestamp_and_the_users_prefix(string name, string? user, string expected) =>
        Assert.Equal(expected, SourceDiscovery.StripName(name, user));

    [Fact]
    public void Every_kind_has_a_mapping_and_a_raw_table_name()
    {
        Assert.Equal(["evtxecmd", "mftecmd.mft", "mftecmd.usnjournal", "pecmd.output", "pecmd.timeline"],
            KindRegistry.All.Select(k => k.Kind));
        Assert.All(KindRegistry.All, k =>
        {
            Assert.NotNull(k.MapSql);
            Assert.Contains("FROM " + k.RawTable, k.MapSql);
            Assert.NotEmpty(k.RequiredColumns);
        });
    }

    [Fact]
    public void A_header_is_read_without_its_byte_order_mark_and_with_quoted_names()
    {
        using var temp = new TempDirectory();
        var path = temp.Write("a.csv", "\"Run,Time\",ExecutableName\r\nx,y\r\n", byteOrderMark: true);

        Assert.Equal(["Run,Time", "ExecutableName"], SourceDiscovery.ReadHeader(path));
    }

    [Fact]
    public void The_command_line_builds_a_lake_and_lists_its_kinds()
    {
        using var temp = new TempDirectory();
        WriteArtefactForgeHost(temp, "HOST01");
        var output = new StringWriter();
        var error = new StringWriter();

        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["build", temp.Path, "--memory-gb", "0.5", "--threads", "2"], output, error));
        Assert.Contains("Built ", output.ToString());
        Assert.True(File.Exists(Path.Combine(temp.Path, "_Lake", "case.duckdb")));

        var kinds = new StringWriter();
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["kinds"], kinds, error));
        Assert.Contains("pecmd.timeline", kinds.ToString());
    }

    [Fact]
    public void The_command_line_exits_non_zero_when_sources_need_a_look_or_nothing_was_built()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv", "When,Program\r\nx,y\r\n");
        var error = new StringWriter();

        Assert.Equal(LakeCli.ExitCheckLog, LakeCli.Run(["build", temp.Path], new StringWriter(), error));

        using var empty = new TempDirectory();
        Assert.Equal(LakeCli.ExitFailed, LakeCli.Run(["build", empty.Path], new StringWriter(), error));
        Assert.Contains("No host folders", error.ToString());
    }

    [Theory]
    [InlineData]
    [InlineData("build")]
    [InlineData("build", "--threads", "0", ".")]
    [InlineData("build", "--memory-gb", "lots", ".")]
    [InlineData("frobnicate")]
    public void The_command_line_rejects_bad_arguments_with_exit_code_two(params string[] args)
    {
        var error = new StringWriter();
        Assert.Equal(LakeCli.ExitUsage, LakeCli.Run(args, new StringWriter(), error));
        Assert.NotEmpty(error.ToString());
    }
}
