namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxDnfHistory module: dnf's own transaction database, /var/lib/dnf/history.sqlite.
///
///   LinuxDnf_Transactions.csv  one row per dnf run: when, who, the command line, and what changed
///   LinuxDnf_Items.csv         one row per package (or group) per transaction
///   LinuxDnf_Output.csv        what dnf printed during each transaction, where it was recorded
///
/// This is the RHEL counterpart of apt's history.log, and the part dnf.rpm.log lacks: the command
/// line and the user. The user is the loginuid dnf records (dnf/db/history.py, beg()), which sudo
/// does not change, so an install run through sudo is attributed to the person who logged in rather
/// than to root. It is resolved to a name through etc/passwd where that was collected.
///
/// Schema and enum values are taken from libdnf's source (transaction/sql/create_tables.sql, the
/// 1.2 and 1.3 migrations, transaction/Types.hpp and TransactionItemReason.hpp), not from memory.
/// Read with ArtefactForge's own SQLite reader, which applies a -wal beside the database without
/// modifying either file. yum's older history (RHEL 7, /var/lib/yum/history/) is a different
/// schema, read by <see cref="YumHistoryExport"/>.
/// </summary>
public static class DnfHistoryExport
{
    // TransactionItemAction, libdnf transaction/Types.hpp
    private static readonly Dictionary<long, string> Actions = new()
    {
        [1] = "Install", [2] = "Downgrade", [3] = "Downgraded", [4] = "Obsolete", [5] = "Obsoleted",
        [6] = "Upgrade", [7] = "Upgraded", [8] = "Remove", [9] = "Reinstall", [10] = "Reinstalled",
        [11] = "Reason change"
    };

    // TransactionItemReason, libdnf transaction/TransactionItemReason.hpp
    private static readonly Dictionary<long, string> Reasons = new()
    {
        [0] = "Unknown", [1] = "Dependency", [2] = "User", [3] = "Clean", [4] = "Weak dependency", [5] = "Group"
    };

    // TransactionState and TransactionItemState, libdnf transaction/Types.hpp
    private static readonly Dictionary<long, string> States = new() { [0] = "Unknown", [1] = "Done", [2] = "Error" };

    /// <summary>What the loginuid holds when no login session set it: a service, a boot-time job.</summary>
    private const long UnsetLoginUid = 4294967295;

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var path = Path.Combine(root, "var", "lib", "dnf", "history.sqlite");
        if (!File.Exists(path))
        {
            log.WriteLine($"No {Path.Combine("var", "lib", "dnf", "history.sqlite")} under {root}");
            return 0;
        }

        SqliteReader db;
        try { db = SqliteReader.Open(path); }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            errors.WriteLine($"history.sqlite: not readable - {ex.Message}");
            return 1;
        }
        foreach (var note in db.Notes) log.WriteLine("  " + note);

        var users = Passwd(root);
        var source = Path.GetRelativePath(root, path).Replace('\\', '/');

        // Each table is read independently, so damage in one does not lose the others.
        List<Dictionary<string, object?>> Read(string table)
        {
            try
            {
                return db.Table(table) is null ? [] : db.Rows(table).ToList();
            }
            catch (InvalidDataException ex)
            {
                errors.WriteLine($"history.sqlite: table {table} could not be read in full - {ex.Message}");
                return [];
            }
        }

        var transRows = Read("trans");
        if (transRows.Count == 0)
        {
            log.WriteLine("history.sqlite holds no transactions");
            return 0;
        }

        var names = new Dictionary<long, (string Name, long? Epoch, string Version, string Release, string Arch)>();
        foreach (var r in Read("rpm"))
            if (Long(r, "item_id") is { } id)
                names[id] = (Str(r, "name"), Long(r, "epoch"), Str(r, "version"), Str(r, "release"), Str(r, "arch"));
        foreach (var r in Read("comps_group"))
            if (Long(r, "item_id") is { } id) names[id] = ("@" + Str(r, "groupid"), null, "", "", "");
        foreach (var r in Read("comps_environment"))
            if (Long(r, "item_id") is { } id) names[id] = ("@^" + Str(r, "environmentid"), null, "", "", "");

        var repos = Read("repo").Where(r => Long(r, "id") is not null)
                                .ToDictionary(r => Long(r, "id")!.Value, r => Str(r, "repoid"));
        var items = Read("trans_item").GroupBy(r => Long(r, "trans_id") ?? -1).ToDictionary(g => g.Key, g => g.ToList());

        Directory.CreateDirectory(outputDirectory);
        using var transCsv = new CsvFile(Path.Combine(outputDirectory, "LinuxDnf_Transactions.csv"),
            "Id", "BeginUtc", "EndUtc", "LoginUid", "User", "Commandline", "State", "Installed", "Upgraded",
            "Downgraded", "Removed", "Reinstalled", "Obsoleted", "Explicit", "Releasever", "Comment", "SourceFile");
        using var itemCsv = new CsvFile(Path.Combine(outputDirectory, "LinuxDnf_Items.csv"),
            "TransactionId", "BeginUtc", "User", "Action", "Reason", "Package", "Epoch", "Version", "Release",
            "Arch", "Repo", "State", "SourceFile");
        using var outputCsv = new CsvFile(Path.Combine(outputDirectory, "LinuxDnf_Output.csv"),
            "TransactionId", "BeginUtc", "Stream", "Line", "SourceFile");

        var begins = new Dictionary<long, string>();
        foreach (var t in transRows.OrderBy(t => Long(t, "id")))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var id = Long(t, "id") ?? 0;
            var begin = Time(Long(t, "dt_begin"));
            begins[id] = begin;
            var uid = Long(t, "user_id");
            var user = UserName(uid, users);

            var counts = new Dictionary<string, int>();
            var explicitItems = new List<string>();
            foreach (var item in items.GetValueOrDefault(id) ?? [])
            {
                var action = Actions.GetValueOrDefault(Long(item, "action") ?? 0, $"Action {Long(item, "action")}");
                var name = names.TryGetValue(Long(item, "item_id") ?? -1, out var n) ? n : ($"item {Long(item, "item_id")}", null, "", "", "");
                counts[action] = counts.GetValueOrDefault(action) + 1;

                // The outgoing half of an upgrade, downgrade or reinstall is not something anyone asked for.
                if (Long(item, "reason") == 2 && action is "Install" or "Upgrade" or "Downgrade" or "Remove" or "Reinstall")
                    explicitItems.Add($"{action} {name.Name}");

                itemCsv.Write(id.ToString(), begin, user, action,
                    Reasons.GetValueOrDefault(Long(item, "reason") ?? 0, $"Reason {Long(item, "reason")}"),
                    name.Name, name.Epoch?.ToString() ?? "", name.Version, name.Release, name.Arch,
                    repos.GetValueOrDefault(Long(item, "repo_id") ?? -1, ""),
                    States.GetValueOrDefault(Long(item, "state") ?? 0, ""), source);
            }

            transCsv.Write(id.ToString(), begin, Time(Long(t, "dt_end")), uid?.ToString() ?? "", user,
                Str(t, "cmdline"), States.GetValueOrDefault(Long(t, "state") ?? 0, $"State {Long(t, "state")}"),
                Count(counts, "Install"), Count(counts, "Upgrade"), Count(counts, "Downgrade"),
                Count(counts, "Remove"), Count(counts, "Reinstall"), Count(counts, "Obsoleted"),
                string.Join("; ", explicitItems), Str(t, "releasever"), Str(t, "comment"), source);
        }

        foreach (var line in Read("console_output").OrderBy(r => Long(r, "id")))
        {
            var tid = Long(line, "trans_id") ?? 0;
            outputCsv.Write(tid.ToString(), begins.GetValueOrDefault(tid, ""),
                Long(line, "file_descriptor") switch { 1 => "stdout", 2 => "stderr", var fd => fd?.ToString() ?? "" },
                Str(line, "line"), source);
        }

        foreach (var csv in new[] { transCsv, itemCsv, outputCsv })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-30} {csv.Rows} row(s)");
        if (users.Count == 0) log.WriteLine("  etc/passwd not collected - users shown as UIDs only");
        return 0;
    }

    private static string Count(Dictionary<string, int> counts, string action) => counts.GetValueOrDefault(action).ToString();

    internal static string UserName(long? uid, Dictionary<long, string> users) => uid switch
    {
        null => "",
        var u when u == UnsetLoginUid || u == -1 => "(no login session)",
        _ => users.TryGetValue(uid.Value, out var name) ? name : $"uid {uid}"
    };

    internal static Dictionary<long, string> Passwd(string root)
    {
        var users = new Dictionary<long, string>();
        var path = Path.Combine(root, "etc", "passwd");
        if (!File.Exists(path)) return users;
        try
        {
            foreach (var line in File.ReadLines(path))
            {
                var f = line.Split(':');
                if (f.Length >= 3 && long.TryParse(f[2], out var uid)) users.TryAdd(uid, f[0]);
            }
        }
        catch (IOException) { }
        return users;
    }

    internal static string Time(long? unixSeconds) =>
        unixSeconds is { } s and > 0
            ? DateTimeOffset.FromUnixTimeSeconds(s).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss")
            : "";

    internal static long? Long(Dictionary<string, object?> row, string column) =>
        row.GetValueOrDefault(column) switch { long l => l, double d => (long)d, string s when long.TryParse(s, out var v) => v, _ => null };

    internal static string Str(Dictionary<string, object?> row, string column) =>
        row.GetValueOrDefault(column) switch { null => "", byte[] b => Convert.ToHexString(b), var v => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "" };
}
