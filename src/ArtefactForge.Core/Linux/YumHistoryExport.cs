namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxYumHistory module: yum's transaction history on RHEL and CentOS 7,
/// /var/lib/yum/history/history-YYYY-MM-DD.sqlite.
///
///   LinuxYum_Transactions.csv  one row per yum run: when, who, the command line, the result
///   LinuxYum_Items.csv         one row per package per transaction, with yum's own state text
///   LinuxYum_Output.csv        scriptlet output, errors, skipped packages and rpmdb problems
///
/// Schema taken from yum's source (yum/history.py: _create_db_file, _update_ops_2 and 3), not from
/// memory. Every history-*.sqlite is read, not only the newest yum itself uses: 'yum history new'
/// starts a fresh file and transaction IDs restart at 1, so SourceFile is part of a row's identity.
///
/// Following yum's own reading of the same data:
///   - no trans_end row means yum was interrupted, shown by 'yum history' as Aborted;
///   - loginuid is the audit login UID, which sudo does not change, as in dnf;
///   - when one transaction ends at an rpmdb version the next does not start from, the package
///     database changed between them without yum (rpm -i, rpm -e): 'yum history' marks these, and
///     so does RpmdbChangedBefore. Only consecutive IDs in the same file are compared, as yum does.
/// </summary>
public static class YumHistoryExport
{
    private static readonly string[] InstallStates = ["Install", "True-Install", "Dep-Install"];

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var directory = Path.Combine(root, "var", "lib", "yum", "history");
        var files = Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, "history-*.sqlite*")
                .Where(f => f.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".sqlite.old", StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal)
                .ToList()
            : [];
        if (files.Count == 0)
        {
            log.WriteLine($"No yum history databases in {Path.Combine("var", "lib", "yum", "history")} under {root}");
            return 0;
        }

        var users = DnfHistoryExport.Passwd(root);
        Directory.CreateDirectory(outputDirectory);
        using var transCsv = new CsvFile(Path.Combine(outputDirectory, "LinuxYum_Transactions.csv"),
            "Id", "BeginUtc", "EndUtc", "LoginUid", "User", "Commandline", "Result", "ReturnCode",
            "Installed", "Updated", "Downgraded", "Removed", "Reinstalled", "Obsoleted", "RpmdbChangedBefore",
            "RpmdbVersionBegin", "RpmdbVersionEnd", "SourceFile");
        using var itemCsv = new CsvFile(Path.Combine(outputDirectory, "LinuxYum_Items.csv"),
            "TransactionId", "BeginUtc", "User", "State", "Package", "Epoch", "Version", "Release", "Arch",
            "Done", "SourceFile");
        using var outputCsv = new CsvFile(Path.Combine(outputDirectory, "LinuxYum_Output.csv"),
            "TransactionId", "BeginUtc", "Kind", "Line", "SourceFile");

        var failed = false;
        foreach (var path in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = Path.GetRelativePath(root, path).Replace('\\', '/');
            if (!ReadOne(path, source, users, transCsv, itemCsv, outputCsv, log, errors, cancellationToken))
                failed = true;
        }

        foreach (var csv in new[] { transCsv, itemCsv, outputCsv })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-30} {csv.Rows} row(s)");
        if (users.Count == 0) log.WriteLine("  etc/passwd not collected - users shown as UIDs only");
        return failed ? 1 : 0;
    }

    private static bool ReadOne(string path, string source, Dictionary<long, string> users,
        CsvFile transCsv, CsvFile itemCsv, CsvFile outputCsv, TextWriter log, TextWriter errors,
        CancellationToken cancellationToken)
    {
        var name = Path.GetFileName(path);
        log.WriteLine(source);

        // yum used a rollback journal, not a WAL. One left behind means a write was interrupted and
        // the database may hold pages SQLite would have rolled back. It is read as found, and said so.
        var journal = new FileInfo(path + "-journal");
        if (journal.Exists && journal.Length > 0)
            errors.WriteLine($"{name}: a {journal.Length}-byte {journal.Name} is beside it - an interrupted write; "
                             + "rows are read as found, without rolling the journal back");

        SqliteReader db;
        try { db = SqliteReader.Open(path); }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            errors.WriteLine($"{name}: not readable - {ex.Message}");
            return false;
        }
        foreach (var note in db.Notes) log.WriteLine("  " + note);

        var ok = true;
        List<Dictionary<string, object?>> Read(string table)
        {
            try
            {
                return db.Table(table) is null ? [] : db.Rows(table).ToList();
            }
            catch (InvalidDataException ex)
            {
                errors.WriteLine($"{name}: table {table} could not be read in full - {ex.Message}");
                ok = false;
                return [];
            }
        }

        var begins = Read("trans_beg").Where(r => Long(r, "tid") is not null)
                                      .OrderBy(r => Long(r, "tid")).ToList();
        if (begins.Count == 0)
        {
            log.WriteLine("  no transactions");
            return ok;
        }

        var ends = Read("trans_end").Where(r => Long(r, "tid") is not null)
                                    .GroupBy(r => Long(r, "tid")!.Value).ToDictionary(g => g.Key, g => g.First());
        var cmdlines = Read("trans_cmdline").Where(r => Long(r, "tid") is not null)
                                            .GroupBy(r => Long(r, "tid")!.Value)
                                            .ToDictionary(g => g.Key, g => string.Join(" | ", g.Select(r => Str(r, "cmdline"))));
        var pkgs = Read("pkgtups").Where(r => Long(r, "pkgtupid") is not null)
                                  .ToDictionary(r => Long(r, "pkgtupid")!.Value);
        var data = Read("trans_data_pkgs").GroupBy(r => Long(r, "tid") ?? -1).ToDictionary(g => g.Key, g => g.ToList());

        var beginTimes = new Dictionary<long, string>();
        Dictionary<string, object?>? previous = null;
        foreach (var t in begins)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var tid = Long(t, "tid")!.Value;
            var begin = Time(Long(t, "timestamp"));
            beginTimes[tid] = begin;
            var uid = Long(t, "loginuid");
            var user = DnfHistoryExport.UserName(uid, users);
            var end = ends.GetValueOrDefault(tid);
            var rc = end is null ? null : Long(end, "return_code");
            var result = end is null ? "Aborted" : rc == 0 ? "Success" : "Failure";

            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in data.GetValueOrDefault(tid) ?? [])
            {
                var state = Str(item, "state");
                counts[state] = counts.GetValueOrDefault(state) + 1;
                var pkg = pkgs.GetValueOrDefault(Long(item, "pkgtupid") ?? -1);
                itemCsv.Write(tid.ToString(), begin, user, state,
                    pkg is null ? $"pkgtup {Long(item, "pkgtupid")}" : Str(pkg, "name"),
                    pkg is null ? "" : Str(pkg, "epoch"), pkg is null ? "" : Str(pkg, "version"),
                    pkg is null ? "" : Str(pkg, "release"), pkg is null ? "" : Str(pkg, "arch"),
                    Done(item.GetValueOrDefault("done")), source);
            }

            transCsv.Write(tid.ToString(), begin, end is null ? "" : Time(Long(end, "timestamp")),
                uid?.ToString() ?? "", user, cmdlines.GetValueOrDefault(tid, ""), result, rc?.ToString() ?? "",
                InstallStates.Sum(s => counts.GetValueOrDefault(s)).ToString(),
                counts.GetValueOrDefault("Update").ToString(), counts.GetValueOrDefault("Downgrade").ToString(),
                counts.GetValueOrDefault("Erase").ToString(), counts.GetValueOrDefault("Reinstall").ToString(),
                counts.GetValueOrDefault("Obsoleted").ToString(),
                ChangedBefore(previous, t, ends), Str(t, "rpmdb_version"),
                end is null ? "" : Str(end, "rpmdb_version"), source);
            previous = t;
        }

        void Lines(string table, string order, string column, string kind)
        {
            foreach (var r in Read(table).OrderBy(r => Long(r, order)))
            {
                var tid = Long(r, "tid") ?? 0;
                outputCsv.Write(tid.ToString(), beginTimes.GetValueOrDefault(tid, ""), kind, Str(r, column), source);
            }
        }
        Lines("trans_error", "mid", "msg", "error");
        Lines("trans_script_stdout", "lid", "line", "scriptlet");
        Lines("trans_rpmdb_problems", "rpid", "msg", "rpmdb problem");
        foreach (var r in Read("trans_skip_pkgs"))
        {
            var tid = Long(r, "tid") ?? 0;
            var pkg = pkgs.GetValueOrDefault(Long(r, "pkgtupid") ?? -1);
            var nevra = pkg is null
                ? $"pkgtup {Long(r, "pkgtupid")}"
                : $"{Str(pkg, "name")}-{Str(pkg, "epoch")}:{Str(pkg, "version")}-{Str(pkg, "release")}.{Str(pkg, "arch")}";
            outputCsv.Write(tid.ToString(), beginTimes.GetValueOrDefault(tid, ""), "skipped", nevra, source);
        }
        return ok;
    }

    /// <summary>yum's own test (history.py, old()): consecutive IDs, both versions known, and different.</summary>
    private static string ChangedBefore(Dictionary<string, object?>? previous, Dictionary<string, object?> current,
        Dictionary<long, Dictionary<string, object?>> ends)
    {
        if (previous is null || Long(previous, "tid") + 1 != Long(current, "tid")) return "";
        var before = ends.GetValueOrDefault(Long(previous, "tid")!.Value) is { } end ? Str(end, "rpmdb_version") : "";
        var now = Str(current, "rpmdb_version");
        if (before.Length == 0 || now.Length == 0) return "";
        return before == now ? "False" : "True";
    }

    /// <summary>yum writes 'TRUE' and 'FALSE' as text; a newer SQLite stores the column default as 0.</summary>
    private static string Done(object? value) => value switch
    {
        string s when s.Equals("TRUE", StringComparison.OrdinalIgnoreCase) => "True",
        string s when s.Equals("FALSE", StringComparison.OrdinalIgnoreCase) => "False",
        long l => l != 0 ? "True" : "False",
        null => "",
        var v => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? ""
    };

    private static string Time(long? s) => DnfHistoryExport.Time(s);
    private static long? Long(Dictionary<string, object?> row, string column) => DnfHistoryExport.Long(row, column);
    private static string Str(Dictionary<string, object?> row, string column) => DnfHistoryExport.Str(row, column);
}
