using System.Text.Json;
using ArtefactForge.Core;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

public class JournalExportTests
{
    private static string Journal(TempDirectory dir, string name, Action<TestJournalWriter> build)
    {
        var w = new TestJournalWriter();
        build(w);
        return w.WriteTo(Path.Combine(dir.Path, "root", "var", "log", "journal", "0123abcd", name));
    }

    private static (int Exit, string Log, string Errors) Run(TempDirectory dir)
    {
        var log = new StringWriter();
        var errors = new StringWriter();
        var exit = JournalExport.Run(Path.Combine(dir.Path, "root"), Path.Combine(dir.Path, "out"), log, errors, CancellationToken.None);
        return (exit, log.ToString(), errors.ToString());
    }

    [Fact]
    public void Files_are_merged_into_one_timeline()
    {
        using var dir = new TempDirectory();
        Journal(dir, "system@a.journal", w =>
        {
            var m = w.AddData("MESSAGE", "system");
            w.AddEntry(1, 1_000, m);
            w.AddEntry(2, 3_000, m);
        });
        Journal(dir, "user-1000.journal", w => w.AddEntry(1, 2_000, w.AddData("MESSAGE", "user")));

        var (exit, _, errors) = Run(dir);
        Assert.Equal(0, exit);
        Assert.Equal("", errors);

        var lines = File.ReadAllLines(Path.Combine(dir.Path, "out", "LinuxJournal_Entries.jsonl"));
        var messages = lines.Select(l => JsonDocument.Parse(l).RootElement.GetProperty("MESSAGE").GetString()).ToArray();
        Assert.Equal(new[] { "system", "user", "system" }, messages);
    }

    [Fact]
    public void Json_follows_journalctl_for_repeated_and_binary_fields()
    {
        using var dir = new TempDirectory();
        Journal(dir, "system.journal", w => w.AddEntry(1, 1,
            w.AddData("TAG", "one"), w.AddData("TAG", "two"),
            w.AddData("RAW", [0xff, 0x01]), w.AddData("MULTI", "line\nand\ttab")));

        Run(dir);
        var root = JsonDocument.Parse(File.ReadAllLines(Path.Combine(dir.Path, "out", "LinuxJournal_Entries.jsonl"))[0]).RootElement;

        Assert.Equal(JsonValueKind.Array, root.GetProperty("TAG").ValueKind);
        Assert.Equal("two", root.GetProperty("TAG")[1].GetString());
        Assert.Equal(255, root.GetProperty("RAW")[0].GetInt32());
        Assert.Equal("line\nand\ttab", root.GetProperty("MULTI").GetString());
        Assert.Equal("abababababababababababababababab", root.GetProperty("_BOOT_ID").GetString());
    }

    [Fact]
    public void Authentication_entries_are_classified_like_auth_log()
    {
        using var dir = new TempDirectory();
        Journal(dir, "system.journal", w =>
        {
            var sshd = w.AddData("SYSLOG_IDENTIFIER", "sshd");
            w.AddEntry(1, 1, sshd, w.AddData("MESSAGE", "Accepted publickey for alice from 192.0.2.7 port 51000 ssh2"));
            w.AddEntry(2, 2, sshd, w.AddData("MESSAGE", "Received disconnect from 192.0.2.7"));
            w.AddEntry(3, 3, w.AddData("SYSLOG_IDENTIFIER", "cron"), w.AddData("MESSAGE", "not authentication"));
        });

        Run(dir);
        var auth = File.ReadAllLines(Path.Combine(dir.Path, "out", "LinuxJournal_Auth.csv"));
        var key = File.ReadAllLines(Path.Combine(dir.Path, "out", "LinuxJournal_KeyEvents.csv"));

        Assert.Equal(3, auth.Length);          // header + two sshd rows; cron is not auth
        Assert.Equal(2, key.Length);           // header + the accepted login
        Assert.Contains("\"LoginSuccess\",\"alice\",\"192.0.2.7\"", key[1]);
    }

    [Fact]
    public void No_journal_is_not_an_error()
    {
        using var dir = new TempDirectory();
        dir.Dir(Path.Combine("root", "var", "log"));

        var (exit, log, errors) = Run(dir);
        Assert.Equal(0, exit);
        Assert.Contains("No .journal files", log);
        Assert.Equal("", errors);
        Assert.False(Directory.Exists(Path.Combine(dir.Path, "out")));
    }

    [Fact]
    public void An_unreadable_file_is_reported_and_the_rest_still_parsed()
    {
        using var dir = new TempDirectory();
        Journal(dir, "good.journal", w => w.AddEntry(1, 1, w.AddData("MESSAGE", "ok")));
        File.WriteAllText(Path.Combine(dir.Path, "root", "var", "log", "journal", "0123abcd", "junk.journal~"), "not a journal");

        var (exit, log, errors) = Run(dir);
        Assert.Equal(0, exit);
        Assert.Contains("junk.journal~: skipped", errors);
        Assert.Contains("1 entry from 1 file(s)", log);
    }

    [Fact]
    public void Only_unreadable_files_is_a_failure()
    {
        using var dir = new TempDirectory();
        dir.File(Path.Combine("root", "var", "log", "journal", "m", "empty.journal"));

        Assert.Equal(1, Run(dir).Exit);
    }
}

public class AuthEventClassifierTests
{
    // Each case is checked against Parse-LinuxAuth.ps1's output for the same line. The two must agree.
    [Theory]
    [InlineData("Accepted password for root from 203.0.113.9 port 2200 ssh2", "LoginSuccess", "root", "203.0.113.9", "")]
    [InlineData("Failed password for invalid user admin from 2001:db8::5 port 4242 ssh2", "LoginFailed", "admin", "2001:db8::5", "")]
    [InlineData("  bob : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i", "SudoCommand", "bob", "", "/bin/bash -i")]
    [InlineData("pam_unix(sudo:session): session opened for user root(uid=0) by bob(uid=1000)", "SessionOpen", "root", "", "")]
    [InlineData("new user: name=svc, UID=1001, GID=1001, home=/home/svc, shell=/bin/bash, from=none", "AccountCreated", "svc", "", "")]
    [InlineData("something unrelated", "", "", "", "")]
    public void Matches_the_auth_log_parser(string message, string evt, string user, string ip, string command)
    {
        var result = AuthEventClassifier.Classify(message);
        Assert.Equal(evt, result.Event);
        Assert.Equal(user, result.User);
        Assert.Equal(ip, result.SourceIp);
        Assert.Equal(command, result.Command);
    }
}

public class BuiltinsTests
{
    [Fact]
    public void Arguments_are_named_pairs_with_quoted_paths()
    {
        var args = Builtins.ParseArguments(@"--root ""C:\Evidence\web 01"" --out C:\out");
        Assert.Equal(@"C:\Evidence\web 01", args["root"]);
        Assert.Equal(@"C:\out", args["OUT"]);
    }

    [Theory]
    [InlineData("--root")]
    [InlineData("root value")]
    [InlineData("--root \"unterminated")]
    public void Malformed_arguments_are_refused(string line) =>
        Assert.Throws<FormatException>(() => Builtins.ParseArguments(line));

    [Fact]
    public void A_builtin_resolves_as_a_tool_and_an_unknown_one_does_not()
    {
        var tool = ToolResolver.Resolve("builtin:LinuxJournal", []);
        Assert.NotNull(tool);
        Assert.Equal(BuildInfo.InformationalVersion, tool!.Version);
        Assert.Null(ToolResolver.Resolve("builtin:NoSuchParser", []));
    }

    [Fact]
    public async Task A_handler_exception_is_a_failure_with_the_reason_logged()
    {
        using var dir = new TempDirectory();
        var err = Path.Combine(dir.Path, "e.log");
        // --out missing: the handler throws, which must come back as exit 1, not escape.
        var outcome = await Builtins.RunAsync("builtin:LinuxJournal", "--root x", Path.Combine(dir.Path, "o.log"), err, null, CancellationToken.None);

        Assert.Equal(1, outcome.ExitCode);
        Assert.True(outcome.WroteToStderr);
        Assert.Contains("missing --out", File.ReadAllText(err));
    }
}

public class BuiltinEngineTests
{
    private static ModuleDefinition JournalModule() => new()
    {
        Description = "journal",
        Category = "Journal",
        SourcePath = @"C:\modules\LinuxJournal.forge",
        OutputName = "LinuxJournal",
        Processors = [new ProcessorDefinition { Executable = "builtin:LinuxJournal", CommandLine = "--root \"%root%\" --out \"%destinationDirectory%\"" }]
    };

    private static RunConfiguration Config(TempDirectory dir, string root) => new()
    {
        CaseName = "CASE",
        OutputRoot = dir.Dir("out"),
        ToolRoots = [dir.Path],
        Targets =
        [
            new ResolvedTarget
            {
                SelectionPath = root,
                Root = root,
                CollectionName = "HOST",
                Layout = new LayoutProfile
                {
                    Id = "t", Name = "t",
                    Detect = new LayoutDetectRules { Markers = ["x"] },
                    Resolve = new LayoutResolveRules()
                }
            }
        ],
        Modules = [JournalModule()],
        MaxWorkers = 2,
        MaxHeavyWorkers = 1
    };

    [Fact]
    public async Task Runs_through_the_engine_and_is_recorded_as_a_tool()
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        w.AddEntry(1, 1, w.AddData("MESSAGE", "hello"));
        w.WriteTo(Path.Combine(dir.Path, "evidence", "var", "log", "journal", "m", "system.journal"));

        var report = await new RunEngine().RunAsync(Config(dir, Path.Combine(dir.Path, "evidence")));

        var result = Assert.Single(report.Results);
        Assert.Equal(WorkStatus.Completed, result.Status);
        var processor = Assert.Single(result.Processors);
        Assert.Equal("builtin:LinuxJournal", processor.Executable);
        Assert.Equal(BuildInfo.InformationalVersion, processor.ToolVersion);
        Assert.True(File.Exists(Path.Combine(result.Destination, "LinuxJournal_Entries.csv")));
    }

    [Fact]
    public async Task Damage_in_a_journal_is_flagged_for_review()
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        w.AddEntry(1, 1, w.AddData("MESSAGE", "hello"), 8);
        w.WriteTo(Path.Combine(dir.Path, "evidence", "var", "log", "journal", "m", "system.journal"));

        var report = await new RunEngine().RunAsync(Config(dir, Path.Combine(dir.Path, "evidence")));

        Assert.Equal(WorkStatus.CheckLog, Assert.Single(report.Results).Status);
    }
}
