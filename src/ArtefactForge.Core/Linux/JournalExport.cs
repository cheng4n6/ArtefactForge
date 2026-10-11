using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxJournal module: every journal file under a Linux root, merged into one timeline.
///
/// Writes four files:
///   LinuxJournal_Entries.csv    one row per entry, the columns an analyst filters on
///   LinuxJournal_Entries.jsonl  one object per entry with every field, shaped like journalctl -o json
///   LinuxJournal_Auth.csv       authentication entries, classified as LinuxAuth classifies auth.log
///   LinuxJournal_KeyEvents.csv  the subset of those worth reading first
///
/// Timestamps are UTC, from the entry's own realtime clock - unlike syslog text, the journal
/// records a full timestamp, so there is no year to infer and no local time to convert.
/// </summary>
public static class JournalExport
{
    private static readonly string[] SearchRoots = ["var/log/journal", "run/log/journal"];

    private static readonly HashSet<string> AuthIdentifiers = new(StringComparer.Ordinal)
    {
        "sshd", "sshd-session", "sudo", "su", "login", "systemd-logind", "useradd", "userdel", "usermod",
        "groupadd", "groupdel", "groupmod", "passwd", "chpasswd", "chage", "gpasswd", "unix_chkpwd",
        "polkitd", "pkexec", "newgrp", "gdm-password", "lightdm"
    };

    // LOG_AUTH and LOG_AUTHPRIV: what rsyslog routes to auth.log and secure.
    private static readonly HashSet<string> AuthFacilities = ["4", "10"];

    private static readonly string[] PriorityNames = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];

    private static readonly UTF8Encoding Utf8Bom = new(encoderShouldEmitUTF8Identifier: true);
    private static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    public static IReadOnlyList<string> FindJournals(string root)
    {
        var found = new List<string>();
        foreach (var relative in SearchRoots)
        {
            var dir = Path.Combine(root, relative);
            if (!Directory.Exists(dir)) continue;
            try
            {
                found.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
                    .Where(f => f.EndsWith(".journal", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".journal~", StringComparison.OrdinalIgnoreCase)));
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
        return found.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Returns the process-style exit code: 0 unless nothing could be done at all.</summary>
    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var paths = FindJournals(root);
        if (paths.Count == 0)
        {
            log.WriteLine($"No .journal files under {Path.Combine(root, "var", "log", "journal")} or run/log/journal");
            return 0;
        }

        Directory.CreateDirectory(outputDirectory);

        var files = new List<JournalFile>();
        foreach (var path in paths)
        {
            try { files.Add(JournalFile.Open(path)); }
            catch (Exception ex) { errors.WriteLine($"{Path.GetFileName(path)}: skipped - {ex.Message}"); }
        }

        try
        {
            if (files.Count == 0) return 1;
            return Export(files, outputDirectory, log, errors, cancellationToken);
        }
        finally
        {
            foreach (var file in files) file.Dispose();
        }
    }

    private static int Export(List<JournalFile> files, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var perFile = new int[files.Count];
        var authRows = 0;
        var keyRows = 0;
        var total = 0;

        // Each file is already in write order, so a k-way merge gives one timeline without holding
        // the journal in memory. Ties break by file, then sequence number, so output is stable.
        var queue = new PriorityQueue<(IEnumerator<JournalEntry> Cursor, int File), (ulong Time, int File, ulong Seq)>();
        var cursors = new List<IEnumerator<JournalEntry>>();
        try
        {
            for (var i = 0; i < files.Count; i++)
            {
                var cursor = files[i].ReadEntries(cancellationToken).GetEnumerator();
                cursors.Add(cursor);
                if (cursor.MoveNext())
                    queue.Enqueue((cursor, i), (cursor.Current.RealtimeUsec, i, cursor.Current.Seqnum));
            }

            using var entriesCsv = new StreamWriter(Path.Combine(outputDirectory, "LinuxJournal_Entries.csv"), false, Utf8Bom);
            using var jsonStream = new FileStream(Path.Combine(outputDirectory, "LinuxJournal_Entries.jsonl"), FileMode.Create);
            using var json = new Utf8JsonWriter(jsonStream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            StreamWriter? authCsv = null;
            StreamWriter? keyCsv = null;

            CsvFile.WriteRow(entriesCsv, "TimestampUtc", "Hostname", "Priority", "SyslogIdentifier", "PID", "UID", "Comm",
                "Unit", "SubjectUnit", "Transport", "Message", "Exe", "CommandLine", "BootId", "Seqnum", "SourceFile");

            try
            {
                while (queue.TryDequeue(out var next, out _))
                {
                    var entry = next.Cursor.Current;
                    perFile[next.File]++;
                    total++;

                    var timestamp = entry.RealtimeUtc.ToString("yyyy-MM-dd HH:mm:ss.ffffff");
                    var host = Text(entry, "_HOSTNAME");
                    var identifier = Text(entry, "SYSLOG_IDENTIFIER");
                    var comm = Text(entry, "_COMM");
                    var pid = First(Text(entry, "SYSLOG_PID"), Text(entry, "_PID"));
                    var message = Text(entry, "MESSAGE");

                    CsvFile.WriteRow(entriesCsv,
                        timestamp, host, Priority(Text(entry, "PRIORITY")), identifier, pid, Text(entry, "_UID"), comm,
                        First(Text(entry, "_SYSTEMD_UNIT"), Text(entry, "_SYSTEMD_USER_UNIT")),
                        First(Text(entry, "UNIT"), Text(entry, "USER_UNIT")),
                        Text(entry, "_TRANSPORT"), message, Text(entry, "_EXE"), Text(entry, "_CMDLINE"),
                        entry.BootId, entry.Seqnum.ToString(), entry.SourceFile);

                    WriteJson(json, jsonStream, entry);

                    var process = First(identifier, comm);
                    if (AuthFacilities.Contains(Text(entry, "SYSLOG_FACILITY")) || AuthIdentifiers.Contains(process))
                    {
                        var auth = AuthEventClassifier.Classify(message);
                        var row = new[]
                        {
                            timestamp, host, process, pid, auth.Event, auth.User, auth.SourceIp, auth.Command,
                            message, entry.SourceFile
                        };

                        if (authCsv is null)
                        {
                            authCsv = new StreamWriter(Path.Combine(outputDirectory, "LinuxJournal_Auth.csv"), false, Utf8Bom);
                            CsvFile.WriteRow(authCsv, AuthHeader);
                        }
                        CsvFile.WriteRow(authCsv, row);
                        authRows++;

                        if (AuthEventClassifier.KeyEvents.Contains(auth.Event))
                        {
                            if (keyCsv is null)
                            {
                                keyCsv = new StreamWriter(Path.Combine(outputDirectory, "LinuxJournal_KeyEvents.csv"), false, Utf8Bom);
                                CsvFile.WriteRow(keyCsv, AuthHeader);
                            }
                            CsvFile.WriteRow(keyCsv, row);
                            keyRows++;
                        }
                    }

                    if (next.Cursor.MoveNext())
                        queue.Enqueue(next, (next.Cursor.Current.RealtimeUsec, next.File, next.Cursor.Current.Seqnum));
                }
            }
            finally
            {
                authCsv?.Dispose();
                keyCsv?.Dispose();
            }
        }
        finally
        {
            foreach (var cursor in cursors) cursor.Dispose();
        }

        // Per-file account: what the header claimed against what was read. A file that was open when
        // it was copied routinely holds more than its header says - those are recovered, not errors.
        log.WriteLine($"  {"File",-60} {"State",-8} {"Header",8} {"Read",8}");
        for (var i = 0; i < files.Count; i++)
        {
            var f = files[i];
            var state = f.State switch { 0 => "offline", 1 => "online", 2 => "archived", _ => f.State.ToString() };
            log.WriteLine($"  {f.Name,-60} {state,-8} {f.HeaderEntryCount,8} {perFile[i],8}" +
                          (f.Compact ? "  compact" : "") +
                          ((ulong)perFile[i] > f.HeaderEntryCount ? "  (recovered beyond header count)"
                           : (ulong)perFile[i] < f.HeaderEntryCount ? "  (fewer than the header count - see the .err.log)" : ""));

            foreach (var warning in f.Warnings) errors.WriteLine($"{f.Name}: {warning}");
            if (f.UndecodedFields > 0)
                errors.WriteLine($"{f.Name}: {f.UndecodedFields} XZ-compressed field(s) not decoded; values replaced with __AF_UNDECODED");
        }

        log.WriteLine();
        log.WriteLine($"  LinuxJournal_Entries.csv / .jsonl  {total} entr{(total == 1 ? "y" : "ies")} from {files.Count} file(s)");
        if (authRows > 0) log.WriteLine($"  LinuxJournal_Auth.csv             {authRows} row(s)");
        if (keyRows > 0) log.WriteLine($"  LinuxJournal_KeyEvents.csv        {keyRows} row(s)");
        return 0;
    }

    private static readonly string[] AuthHeader =
        ["TimestampUtc", "Host", "Process", "PID", "Event", "User", "SourceIP", "Command", "Message", "SourceFile"];

    private static string First(string a, string b) => a.Length > 0 ? a : b;

    private static string Priority(string value) =>
        int.TryParse(value, out var p) && p >= 0 && p < PriorityNames.Length ? PriorityNames[p] : value;

    /// <summary>A field as text for a CSV cell. Invalid UTF-8 is replaced rather than dropped.</summary>
    private static string Text(JournalEntry entry, string name)
    {
        var value = entry.Get(name);
        return value is null ? "" : Encoding.UTF8.GetString(value).Replace("\0", "");
    }

    /// <summary>
    /// Mirrors journalctl -o json: a field that occurs more than once becomes an array, and a value
    /// that is not printable UTF-8 becomes an array of byte values. _BOOT_ID comes from the entry
    /// header, as journalctl takes it. __SEQNUM and __SOURCE_FILE are additions.
    /// </summary>
    private static void WriteJson(Utf8JsonWriter json, Stream stream, JournalEntry entry)
    {
        var grouped = new Dictionary<string, List<byte[]>>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var (name, value) in entry.Fields)
        {
            if (name == "_BOOT_ID") continue;
            if (!grouped.TryGetValue(name, out var list))
            {
                grouped[name] = list = [];
                order.Add(name);
            }
            list.Add(value);
        }

        json.WriteStartObject();
        json.WriteString("__REALTIME_TIMESTAMP", entry.RealtimeUsec.ToString());
        json.WriteString("__MONOTONIC_TIMESTAMP", entry.MonotonicUsec.ToString());
        json.WriteString("_BOOT_ID", entry.BootId);
        json.WriteString("__SEQNUM", entry.Seqnum.ToString());
        json.WriteString("__SOURCE_FILE", entry.SourceFile);

        foreach (var name in order)
        {
            var values = grouped[name];
            json.WritePropertyName(name);
            if (values.Count == 1) WriteValue(json, values[0]);
            else
            {
                json.WriteStartArray();
                foreach (var value in values) WriteValue(json, value);
                json.WriteEndArray();
            }
        }
        json.WriteEndObject();
        json.Flush();
        stream.WriteByte((byte)'\n');
        json.Reset();
    }

    private static void WriteValue(Utf8JsonWriter json, byte[] value)
    {
        var text = PrintableText(value);
        if (text is not null) { json.WriteStringValue(text); return; }

        json.WriteStartArray();
        foreach (var b in value) json.WriteNumberValue(b);
        json.WriteEndArray();
    }

    /// <summary>systemd's utf8_is_printable: valid UTF-8, and no control characters bar tab and newline.</summary>
    private static string? PrintableText(byte[] value)
    {
        string text;
        try { text = StrictUtf8.GetString(value); }
        catch (DecoderFallbackException) { return null; }

        foreach (var rune in text.EnumerateRunes())
        {
            var c = rune.Value;
            if ((c < 0x20 && c != '\t' && c != '\n') || (c >= 0x7F && c <= 0x9F)) return null;
        }
        return text;
    }
}
