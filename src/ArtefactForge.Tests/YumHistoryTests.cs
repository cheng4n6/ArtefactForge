using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>
/// yum history on RHEL 7. The fixtures are built by Fixtures/yum/make-yum-fixtures.py from the CREATE
/// statements in yum's own history.py: one current database with four transactions, and an
/// older one with the version 1 schema, from before trans_cmdline existed.
/// </summary>
public class YumHistoryExportTests
{
    private static (string Out, StringWriter Log, StringWriter Errors, int Exit) Run(TempDirectory dir, bool passwd = true,
        Action<string>? arrange = null)
    {
        var root = dir.Dir("root");
        var history = dir.Dir(Path.Combine("root", "var", "lib", "yum", "history"));
        foreach (var file in Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "Fixtures", "yum"), "history-*.sqlite"))
            File.Copy(file, Path.Combine(history, Path.GetFileName(file)));
        if (passwd)
        {
            dir.Dir(Path.Combine("root", "etc"));
            File.WriteAllText(Path.Combine(root, "etc", "passwd"),
                "root:x:0:0::/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n");
        }
        arrange?.Invoke(history);
        var output = Path.Combine(dir.Path, "out");
        var log = new StringWriter();
        var errors = new StringWriter();
        var exit = YumHistoryExport.Run(root, output, log, errors, CancellationToken.None);
        return (output, log, errors, exit);
    }

    private static List<Dictionary<string, string>> Csv(string path)
    {
        var lines = File.ReadAllLines(path);
        var header = lines[0].TrimStart('﻿').Trim('"').Split("\",\"");
        return lines.Skip(1).Select(l => header.Zip(l.Trim('"').Split("\",\"")).ToDictionary(p => p.First, p => p.Second)).ToList();
    }

    [Fact]
    public void Every_history_file_is_read_oldest_first()
    {
        using var dir = new TempDirectory();
        var (output, _, errors, exit) = Run(dir);
        Assert.Equal(0, exit);
        Assert.Equal("", errors.ToString());

        var trans = Csv(Path.Combine(output, "LinuxYum_Transactions.csv"));
        Assert.Equal(5, trans.Count);
        // The version 1 database has no trans_cmdline table: the row is kept, the command left blank.
        Assert.Equal("var/lib/yum/history/history-2019-06-01.sqlite", trans[0]["SourceFile"]);
        Assert.Equal("", trans[0]["Commandline"]);
        Assert.Equal("uid 1001", trans[0]["User"]);
        // IDs restart in the newer file.
        Assert.Equal("1", trans[1]["Id"]);
        Assert.Equal("var/lib/yum/history/history-2024-03-01.sqlite", trans[1]["SourceFile"]);
    }

    [Fact]
    public void Transactions_carry_the_command_the_user_and_the_result()
    {
        using var dir = new TempDirectory();
        var trans = Csv(Path.Combine(Run(dir).Out, "LinuxYum_Transactions.csv")).Skip(1).ToList();

        Assert.Equal("update -y openssl", trans[0]["Commandline"]);
        Assert.Equal("(no login session)", trans[0]["User"]);
        Assert.Equal("2024-03-01 09:00:00", trans[0]["BeginUtc"]);
        Assert.Equal("2024-03-01 09:00:45", trans[0]["EndUtc"]);
        Assert.Equal("Success", trans[0]["Result"]);
        Assert.Equal("1", trans[0]["Updated"]);

        Assert.Equal("admin", trans[1]["User"]);
        Assert.Equal("2", trans[1]["Installed"]);

        Assert.Equal("Failure", trans[2]["Result"]);
        Assert.Equal("1", trans[2]["ReturnCode"]);
        Assert.Equal("1", trans[2]["Removed"]);

        // No trans_end row: yum history shows it as Aborted.
        Assert.Equal("Aborted", trans[3]["Result"]);
        Assert.Equal("", trans[3]["EndUtc"]);
        Assert.Equal("root", trans[3]["User"]);
    }

    [Fact]
    public void An_rpmdb_change_outside_yum_is_flagged_as_yum_flags_it()
    {
        using var dir = new TempDirectory();
        var trans = Csv(Path.Combine(Run(dir).Out, "LinuxYum_Transactions.csv")).Skip(1).ToList();

        Assert.Equal("", trans[0]["RpmdbChangedBefore"]);       // first in its file: nothing to compare
        Assert.Equal("True", trans[1]["RpmdbChangedBefore"]);   // 1 ended at 401:bbb, 2 began at 402:ccc
        Assert.Equal("False", trans[2]["RpmdbChangedBefore"]);
        Assert.Equal("False", trans[3]["RpmdbChangedBefore"]);  // 3 failed but still recorded its end version
    }

    [Fact]
    public void Items_keep_yum_state_text_and_done()
    {
        using var dir = new TempDirectory();
        var items = Csv(Path.Combine(Run(dir).Out, "LinuxYum_Items.csv"));

        Assert.Equal(7, items.Count);
        Assert.Contains(items, i => i["Package"] == "nmap-ncat" && i["State"] == "Dep-Install" && i["Epoch"] == "2");
        Assert.Contains(items, i => i["Package"] == "openssl" && i["State"] == "Updated" && i["Release"] == "24.el7_9");
        Assert.Contains(items, i => i["Package"] == "telnet" && i["State"] == "Erase" && i["Done"] == "False");
    }

    [Fact]
    public void Errors_scriptlets_skips_and_problems_are_listed()
    {
        using var dir = new TempDirectory();
        var lines = Csv(Path.Combine(Run(dir).Out, "LinuxYum_Output.csv"));

        Assert.Contains(lines, l => l["Kind"] == "error" && l["TransactionId"] == "3" && l["Line"].StartsWith("Error in PREUN"));
        Assert.Contains(lines, l => l["Kind"] == "scriptlet" && l["Line"] == "Created symlink for ncat.");
        Assert.Contains(lines, l => l["Kind"] == "skipped" && l["Line"] == "telnet-1:0.17-66.el7.x86_64");
        Assert.Contains(lines, l => l["Kind"] == "rpmdb problem" && l["Line"] == "openssl is a duplicate");
    }

    [Fact]
    public void A_leftover_journal_is_reported()
    {
        using var dir = new TempDirectory();
        var (_, _, errors, exit) = Run(dir, arrange: h =>
            File.WriteAllBytes(Path.Combine(h, "history-2024-03-01.sqlite-journal"), new byte[512]));
        Assert.Equal(0, exit);
        Assert.Contains("interrupted write", errors.ToString());
    }

    [Fact]
    public void A_damaged_file_does_not_lose_the_others()
    {
        using var dir = new TempDirectory();
        var (output, _, errors, exit) = Run(dir, arrange: h =>
            File.WriteAllText(Path.Combine(h, "history-2020-01-01.sqlite"), "not a database"));
        Assert.Equal(1, exit);
        Assert.Contains("history-2020-01-01.sqlite: not readable", errors.ToString());
        Assert.Equal(5, Csv(Path.Combine(output, "LinuxYum_Transactions.csv")).Count);
    }

    [Fact]
    public void No_history_is_not_an_error()
    {
        using var dir = new TempDirectory();
        var log = new StringWriter();
        var errors = new StringWriter();
        Assert.Equal(0, YumHistoryExport.Run(dir.Dir("root"), Path.Combine(dir.Path, "out"), log, errors, CancellationToken.None));
        Assert.Contains("No yum history", log.ToString());
        Assert.Equal("", errors.ToString());
    }
}
