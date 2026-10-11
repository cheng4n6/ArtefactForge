using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>
/// Against fixtures built from libdnf's real schema by Fixtures/dnf/make-dnf-fixtures.py. The reader was
/// also checked row for row against Python's sqlite3 on 50,529 rows across page sizes of 512 to
/// 65,536 bytes, UTF-8 and both UTF-16 encodings, every integer width, overflow pages and a WAL.
/// </summary>
public class SqliteReaderTests
{
    private static string Fixture(params string[] parts) =>
        Path.Combine([AppContext.BaseDirectory, "Fixtures", "dnf", .. parts]);

    [Fact]
    public void Reads_tables_by_name_with_the_rowid_alias_filled_in()
    {
        var db = SqliteReader.Open(Fixture("history.sqlite"));
        var trans = db.Rows("trans").ToList();

        Assert.Equal(2, trans.Count);
        Assert.Equal(1L, trans[0]["id"]);
        Assert.Equal("dnf upgrade -y", trans[0]["cmdline"]);
        Assert.Equal(4294967295L, trans[0]["user_id"]);
    }

    [Fact]
    public void A_row_written_before_alter_table_takes_the_column_default()
    {
        var trans = SqliteReader.Open(Fixture("history.sqlite")).Rows("trans").ToList();
        Assert.Equal("", trans[0]["comment"]);
        Assert.Equal(0L, trans[0]["persistence"]);
        Assert.Equal("via ticket", trans[1]["comment"]);
    }

    [Fact]
    public void A_value_spilling_onto_overflow_pages_is_read_whole()
    {
        var cmdline = (string)SqliteReader.Open(Fixture("history.sqlite")).Rows("trans").ToList()[1]["cmdline"]!;
        Assert.StartsWith("dnf install -y nmap socat ", cmdline);
        Assert.Equal(26 + 400 * "--setopt=x ".Length, cmdline.Length);
    }

    [Fact]
    public void Committed_wal_frames_are_applied_and_the_files_are_left_alone()
    {
        var path = Fixture("wal", "history.sqlite");
        var before = File.ReadAllBytes(path + "-wal");

        var db = SqliteReader.Open(path);
        var trans = db.Rows("trans").ToList();

        Assert.Equal(3, trans.Count);
        Assert.Equal("dnf remove -y telnet", trans[2]["cmdline"]);
        Assert.Contains(db.Notes, n => n.Contains("committed frame(s) applied"));
        Assert.Equal(before, File.ReadAllBytes(path + "-wal"));
        Assert.False(File.Exists(path + "-shm"));
    }

    [Fact]
    public void An_unfinished_transaction_in_the_wal_is_not_applied_and_is_reported()
    {
        var db = SqliteReader.Open(Fixture("walcut", "history.sqlite"));
        Assert.Equal(2, db.Rows("trans").Count());
        Assert.Contains(db.Notes, n => n.Contains("after the last commit not applied"));
    }

    [Fact]
    public void A_damaged_wal_frame_stops_the_replay_and_says_where()
    {
        using var dir = new TempDirectory();
        var db = Path.Combine(dir.Path, "history.sqlite");
        File.Copy(Fixture("wal", "history.sqlite"), db);
        var wal = File.ReadAllBytes(Fixture("wal", "history.sqlite-wal"));
        wal[32 + 24 + 100] ^= 0xFF;
        File.WriteAllBytes(db + "-wal", wal);

        var reader = SqliteReader.Open(db);
        Assert.Contains(reader.Notes, n => n.Contains("checksum fails at frame 1"));
    }

    [Fact]
    public void Not_an_sqlite_file_is_refused()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "x.sqlite");
        File.WriteAllText(path, new string('x', 200));
        Assert.Throws<InvalidDataException>(() => SqliteReader.Open(path));
    }

    [Theory]
    [InlineData("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL /* c, d */, x)", "id,name,x", 0)]
    [InlineData("CREATE TABLE t (a, \"odd, name\" TEXT, [b] BLOB, `c`, PRIMARY KEY (a, b))", "a,odd, name,b,c", -1)]
    [InlineData("CREATE TABLE t (k INTEGER PRIMARY KEY DESC, v)", "k,v", -1)]
    [InlineData("CREATE TABLE t (id INT PRIMARY KEY, v)", "id,v", -1)]
    public void Column_lists_and_the_rowid_alias_are_parsed(string sql, string columns, int alias)
    {
        var (names, _, rowid) = SqliteReader.ParseColumns(sql);
        Assert.Equal(columns, string.Join(",", names));
        Assert.Equal(alias, rowid);
    }
}

public class DnfHistoryExportTests
{
    private static (string Root, string Out, StringWriter Log, StringWriter Errors) Run(TempDirectory dir, string variant, bool passwd)
    {
        var root = dir.Dir("root");
        var dnf = dir.Dir(Path.Combine("root", "var", "lib", "dnf"));
        var fixtures = Path.Combine(AppContext.BaseDirectory, "Fixtures", "dnf", variant);
        foreach (var file in Directory.GetFiles(fixtures, "history.sqlite*"))
            File.Copy(file, Path.Combine(dnf, Path.GetFileName(file)));
        if (passwd)
        {
            dir.Dir(Path.Combine("root", "etc"));
            File.WriteAllText(Path.Combine(root, "etc", "passwd"), "root:x:0:0::/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n");
        }
        var output = Path.Combine(dir.Path, "out");
        var log = new StringWriter();
        var errors = new StringWriter();
        DnfHistoryExport.Run(root, output, log, errors, CancellationToken.None);
        return (root, output, log, errors);
    }

    private static List<Dictionary<string, string>> Csv(string path)
    {
        var lines = File.ReadAllLines(path);
        var header = lines[0].TrimStart('﻿').Trim('"').Split("\",\"");
        return lines.Skip(1).Select(l => header.Zip(l.Trim('"').Split("\",\"")).ToDictionary(p => p.First, p => p.Second)).ToList();
    }

    [Fact]
    public void Transactions_carry_the_command_the_user_and_what_changed()
    {
        using var dir = new TempDirectory();
        var (_, output, _, errors) = Run(dir, "", passwd: true);
        Assert.Equal("", errors.ToString());

        var trans = Csv(Path.Combine(output, "LinuxDnf_Transactions.csv"));
        Assert.Equal(2, trans.Count);
        Assert.Equal("(no login session)", trans[0]["User"]);
        Assert.Equal("2024-01-01 00:00:00", trans[0]["BeginUtc"]);
        Assert.Equal("1", trans[0]["Upgraded"]);

        Assert.Equal("admin", trans[1]["User"]);
        Assert.Equal("3", trans[1]["Installed"]);
        // socat came in as a dependency; nmap and the group were asked for.
        Assert.Equal("Install nmap; Install @development", trans[1]["Explicit"]);
    }

    [Fact]
    public void Items_and_console_output_are_listed()
    {
        using var dir = new TempDirectory();
        var (_, output, _, _) = Run(dir, "", passwd: true);

        var items = Csv(Path.Combine(output, "LinuxDnf_Items.csv"));
        Assert.Equal(5, items.Count);
        Assert.Contains(items, i => i["Package"] == "socat" && i["Reason"] == "Dependency" && i["Repo"] == "epel");
        Assert.Contains(items, i => i["Package"] == "openssl" && i["Action"] == "Upgraded" && i["Version"] == "3.0.7");

        var lines = Csv(Path.Combine(output, "LinuxDnf_Output.csv"));
        Assert.Contains(lines, l => l["Stream"] == "stderr" && l["Line"] == "warning: scriptlet");
    }

    [Fact]
    public void The_newest_transaction_is_read_from_the_wal()
    {
        using var dir = new TempDirectory();
        var (_, output, log, _) = Run(dir, "wal", passwd: false);

        var trans = Csv(Path.Combine(output, "LinuxDnf_Transactions.csv"));
        Assert.Equal("dnf remove -y telnet", trans[^1]["Commandline"]);
        Assert.Equal("uid 1001", trans[^1]["User"]);
        Assert.Contains("etc/passwd not collected", log.ToString());
    }

    [Fact]
    public void No_history_database_is_not_an_error()
    {
        using var dir = new TempDirectory();
        var log = new StringWriter();
        var errors = new StringWriter();
        Assert.Equal(0, DnfHistoryExport.Run(dir.Dir("root"), Path.Combine(dir.Path, "out"), log, errors, CancellationToken.None));
        Assert.Contains("history.sqlite", log.ToString());
        Assert.Equal("", errors.ToString());
    }
}
