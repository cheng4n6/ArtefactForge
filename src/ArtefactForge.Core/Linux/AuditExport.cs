using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxAudit module: the Linux audit daemon's log, /var/log/audit/audit.log and its rotations.
///
///   LinuxAudit_Events.csv     one row per audit event: the records that share an event ID
///                             (SYSCALL, EXECVE, CWD, PATH, PROCTITLE...) merged, with the command
///                             line decoded and user IDs named
///   LinuxAudit_KeyEvents.csv  the events an investigation starts from: logins and failed
///                             authentication, sudo commands, account and group changes, audit
///                             being reconfigured or stopped, SELinux denials, crashes
///
/// auditd writes one event as several records on separate lines, joined by
/// msg=audit(&lt;epoch&gt;:&lt;serial&gt;). Values that could hold spaces or quotes (the command
/// line, file names, sudo's command) are written as hex when they need to be, so they are decoded
/// here; a quoted value is literal. In the ENRICHED log format the names auditd resolved follow a
/// 0x1D separator and are used in preference to the collected /etc/passwd.
///
/// Times are UTC: the event ID is seconds since the epoch.
/// </summary>
public static partial class AuditExport
{
    /// <summary>Fields auditd hex-encodes when the value is not safe to print (audit-userspace's "untrusted" strings).</summary>
    private static readonly HashSet<string> Encoded = new(StringComparer.Ordinal)
    {
        "proctitle", "cmd", "comm", "cwd", "data", "dir", "exe", "file", "key", "name", "path",
        "acct", "new-disk", "old-disk", "vm", "watch"
    };

    /// <summary>The record types that make an event worth listing on its own, and what to call it.</summary>
    private static readonly Dictionary<string, string> KeyTypes = new(StringComparer.Ordinal)
    {
        ["USER_LOGIN"] = "Login", ["USER_AUTH"] = "Authentication", ["USER_CMD"] = "sudo command",
        ["ADD_USER"] = "Account added", ["DEL_USER"] = "Account deleted", ["USER_MGMT"] = "Account changed",
        ["USER_CHAUTHTOK"] = "Password changed", ["ADD_GROUP"] = "Group added", ["DEL_GROUP"] = "Group deleted",
        ["GRP_MGMT"] = "Group changed", ["ROLE_ASSIGN"] = "SELinux role assigned",
        ["CONFIG_CHANGE"] = "Audit rules changed", ["DAEMON_END"] = "Audit daemon stopped",
        ["DAEMON_ABORT"] = "Audit daemon aborted", ["DAEMON_START"] = "Audit daemon started",
        ["AVC"] = "SELinux/AppArmor denial", ["ANOM_ABEND"] = "Process crashed",
        ["ANOM_PROMISCUOUS"] = "Interface set promiscuous", ["MAC_STATUS"] = "SELinux mode changed",
        ["SERVICE_START"] = "Service started", ["SERVICE_STOP"] = "Service stopped",
        ["KERN_MODULE"] = "Kernel module loaded"
    };

    private static readonly string[] EventHeader =
    [
        "TimestampUtc", "EventId", "RecordTypes", "Syscall", "Success", "Exit", "PID", "PPID",
        "AuditUser", "User", "EffectiveUser", "Exe", "Comm", "CommandLine", "Cwd", "Paths", "Key",
        "Terminal", "Session", "Operation", "Account", "Address", "Result", "SourceFile"
    ];

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var dir = new DirectoryInfo(Path.Combine(root, "var", "log", "audit"));
        var files = dir.Exists
            ? RotatedLogs.Order(dir.EnumerateFiles("audit.log*")).ToList()
            : [];
        if (files.Count == 0)
        {
            log.WriteLine($"No audit.log under {dir.FullName}");
            return 0;
        }

        var users = Passwd(root);
        Directory.CreateDirectory(outputDirectory);
        using var events = new CsvFile(Path.Combine(outputDirectory, "LinuxAudit_Events.csv"), EventHeader);
        using var keys = new CsvFile(Path.Combine(outputDirectory, "LinuxAudit_KeyEvents.csv"),
            ["Event", .. EventHeader[..3], "Detail", .. EventHeader[3..]]);

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
            // Records of one event are written together but can interleave with another event's,
            // so they are gathered by event ID and written in the order each event first appeared.
            var pending = new Dictionary<string, Event>(StringComparer.Ordinal);
            var order = new List<string>();
            var unread = 0;
            try
            {
                foreach (var line in RotatedLogs.ReadLines(file))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var record = Parse(line);
                    if (record is null) { unread++; continue; }
                    if (!pending.TryGetValue(record.Id, out var e))
                    {
                        pending[record.Id] = e = new Event(record.Id, record.Time);
                        order.Add(record.Id);
                    }
                    e.Records.Add(record);

                    // Bound the memory a huge log can take: an event's records are never far apart.
                    if (order.Count > 20_000)
                    {
                        foreach (var id in order.Take(10_000)) { Emit(pending[id], users, source, events, keys); pending.Remove(id); }
                        order.RemoveRange(0, 10_000);
                    }
                }
            }
            catch (InvalidDataException ex)
            {
                errors.WriteLine($"{source}: {ex.Message}");
            }

            foreach (var id in order) Emit(pending[id], users, source, events, keys);
            if (unread > 0)
                errors.WriteLine($"{source}: {unread} line(s) not in auditd's type=... msg=audit(...) format - not parsed");
        }

        foreach (var csv in new[] { events, keys })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-32} {csv.Rows} row(s)");
        if (events.Rows == 0) log.WriteLine("audit.log present but holds no events");
        return 0;
    }

    internal sealed record Record(string Type, string Id, DateTime Time, Dictionary<string, string> Fields, Dictionary<string, string> Names);

    private sealed record Event(string Id, DateTime Time)
    {
        public List<Record> Records { get; } = [];
    }

    /// <summary>One line: [node=host ]type=TYPE msg=audit(1697011200.123:456): field=value ...</summary>
    internal static Record? Parse(string line)
    {
        var header = Header().Match(line);
        if (!header.Success) return null;

        var seconds = double.Parse(header.Groups[2].Value, CultureInfo.InvariantCulture);
        var time = DateTime.UnixEpoch.AddTicks((long)Math.Round(seconds * TimeSpan.TicksPerSecond));
        var body = line[(header.Index + header.Length)..];

        // ENRICHED format: the raw fields, then 0x1D, then names auditd resolved (AUID="alice").
        var split = body.IndexOf('\x1d');
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (split >= 0)
        {
            foreach (var (k, v) in Fields(body[(split + 1)..])) names[k] = v.Text;
            body = body[..split];
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in Fields(body))
        {
            // User-space records carry their detail inside msg='...'.
            if (key == "msg" && value.Quote == '\'')
            {
                foreach (var (k, v) in Fields(value.Text)) fields.TryAdd(k, Decode(header.Groups[1].Value, k, v));
                continue;
            }
            fields.TryAdd(key, Decode(header.Groups[1].Value, key, value));
        }
        return new Record(header.Groups[1].Value, header.Groups[2].Value + ":" + header.Groups[3].Value, time, fields, names);
    }

    [GeneratedRegex(@"^(?:node=\S+\s+)?type=(\S+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*")]
    private static partial Regex Header();

    private readonly record struct Value(string Text, char Quote);

    /// <summary>key=value pairs, where a value may be "double quoted", 'single quoted' or bare.</summary>
    private static IEnumerable<(string Key, Value Value)> Fields(string text)
    {
        var i = 0;
        while (i < text.Length)
        {
            while (i < text.Length && text[i] == ' ') i++;
            var eq = text.IndexOf('=', i);
            if (eq < 0) yield break;
            var key = text[i..eq].Trim();
            i = eq + 1;
            if (i < text.Length && text[i] is '"' or '\'')
            {
                var quote = text[i];
                var close = text.IndexOf(quote, i + 1);
                if (close < 0) close = text.Length;
                yield return (key, new Value(text[(i + 1)..close], quote));
                i = close + 1;
            }
            else
            {
                var end = text.IndexOf(' ', i);
                if (end < 0) end = text.Length;
                yield return (key, new Value(text[i..end], '\0'));
                i = end;
            }
        }
    }

    /// <summary>
    /// A bare value of an untrusted field is hex when auditd had to encode it. EXECVE's a0, a1...
    /// are the arguments; SYSCALL's a0-a3 are register values and are left alone.
    /// </summary>
    private static string Decode(string type, string key, Value value)
    {
        if (value.Quote != '\0') return value.Text;
        var encoded = Encoded.Contains(key) || (type == "EXECVE" && ArgKey().IsMatch(key));
        if (!encoded || value.Text.Length < 2 || value.Text.Length % 2 != 0 || !HexOnly().IsMatch(value.Text))
            return value.Text;
        var bytes = Convert.FromHexString(value.Text);
        // proctitle separates arguments with NUL.
        return Encoding.UTF8.GetString(bytes).Replace('\0', ' ').TrimEnd();
    }

    [GeneratedRegex(@"^a\d+(\[\d+\])?$")]
    private static partial Regex ArgKey();

    [GeneratedRegex(@"^[0-9A-Fa-f]+$")]
    private static partial Regex HexOnly();

    private static void Emit(Event e, Dictionary<string, string> users, string source, CsvFile events, CsvFile keys)
    {
        string Get(string key) =>
            e.Records.Select(r => r.Fields.GetValueOrDefault(key)).FirstOrDefault(v => !string.IsNullOrEmpty(v)) ?? "";
        string Named(string key)
        {
            var id = Get(key);
            var resolved = e.Records.Select(r => r.Names.GetValueOrDefault(key)).FirstOrDefault(v => !string.IsNullOrEmpty(v));
            if (id is "" or "4294967295" or "-1") return id is "" ? "" : "(unset)";
            var name = resolved ?? users.GetValueOrDefault(id);
            return name is null ? id : $"{name} ({id})";
        }

        var types = e.Records.Select(r => r.Type).Distinct().ToList();
        var execve = e.Records.FirstOrDefault(r => r.Type == "EXECVE");
        var commandLine = execve is not null
            ? string.Join(' ', execve.Fields.Where(f => ArgKey().IsMatch(f.Key)).Select(f => f.Value))
            : Get("proctitle");
        var paths = string.Join("; ", e.Records.Where(r => r.Type == "PATH")
                                               .Select(r => r.Fields.GetValueOrDefault("name", ""))
                                               .Where(n => n.Length > 0 && n != "(null)"));
        var syscall = Get("syscall");
        var syscallName = e.Records.Select(r => r.Names.GetValueOrDefault("SYSCALL")).FirstOrDefault(v => v is not null)
                          ?? (Get("arch") == "c000003e" ? Syscalls.GetValueOrDefault(syscall) : null);
        var time = e.Time.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
        var result = Get("res");
        var success = Get("success");

        string[] row =
        [
            time, e.Id, string.Join(",", types),
            syscallName is null ? syscall : $"{syscallName} ({syscall})",
            success, Get("exit"), Get("pid"), Get("ppid"), Named("auid"), Named("uid"), Named("euid"),
            Get("exe"), Get("comm"), commandLine, Get("cwd"), paths, Get("key"),
            Get("terminal") is { Length: > 0 } t ? t : Get("tty"), Get("ses"), Get("op"), Get("acct"),
            Get("addr") is { Length: > 0 } a ? a : Get("hostname"), result, source
        ];
        events.Write(row);

        var key = types.FirstOrDefault(KeyTypes.ContainsKey);
        if (key is null) return;
        var detail = key switch
        {
            "USER_CMD" => Get("cmd"),
            "CONFIG_CHANGE" => string.Join(" ", new[] { Get("op"), Get("key"), Get("list") }.Where(v => v.Length > 0)),
            "AVC" => string.Join(" ", new[] { Get("apparmor"), Get("denied"), Get("operation"), Get("name") }.Where(v => v.Length > 0)),
            "KERN_MODULE" => Get("name"),
            "SERVICE_START" or "SERVICE_STOP" => Get("unit"),
            _ => string.Join(" ", new[] { Get("acct"), Get("id") }.Where(v => v.Length > 0))
        };
        var label = KeyTypes[key] + (result is "failed" ? " failed" : "");
        keys.Write([label, .. row[..3], detail, .. row[3..]]);
    }

    /// <summary>uid to name, from the collected /etc/passwd.</summary>
    private static Dictionary<string, string> Passwd(string root)
    {
        var users = new Dictionary<string, string>(StringComparer.Ordinal);
        var path = Path.Combine(root, "etc", "passwd");
        if (!File.Exists(path)) return users;
        foreach (var line in File.ReadLines(path))
        {
            var f = line.Split(':');
            if (f.Length >= 3) users.TryAdd(f[2], f[0]);
        }
        return users;
    }

    /// <summary>
    /// x86_64 numbers for the system calls audit rules usually watch. Other architectures, and the
    /// rest, are left as numbers; the ENRICHED format names them itself.
    /// </summary>
    private static readonly Dictionary<string, string> Syscalls = new(StringComparer.Ordinal)
    {
        ["2"] = "open", ["4"] = "stat", ["41"] = "socket", ["42"] = "connect", ["43"] = "accept",
        ["49"] = "bind", ["50"] = "listen", ["56"] = "clone", ["57"] = "fork", ["59"] = "execve",
        ["62"] = "kill", ["82"] = "rename", ["84"] = "rmdir", ["86"] = "link", ["87"] = "unlink",
        ["88"] = "symlink", ["90"] = "chmod", ["92"] = "chown", ["101"] = "ptrace", ["105"] = "setuid",
        ["106"] = "setgid", ["165"] = "mount", ["175"] = "init_module", ["176"] = "delete_module",
        ["257"] = "openat", ["263"] = "unlinkat", ["268"] = "fchmodat", ["288"] = "accept4",
        ["313"] = "finit_module", ["322"] = "execveat"
    };
}
