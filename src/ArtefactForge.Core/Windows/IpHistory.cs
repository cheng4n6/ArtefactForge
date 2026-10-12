using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// Builds a history of which machine had which IP address, and when, from what a domain
/// controller (or a DHCP server) records, and rolls it up for the case.
///
/// Runs after the modules, because it reads their output rather than the evidence: zips may
/// already be deleted by then, and the parsing proper is done once, by the modules.
///
///   &lt;collection&gt;\IpHistory\IpHistory.csv         that collection's history (columns: IpHistoryRecord)
///   &lt;collection&gt;\IpHistory\IpHistorySources.csv  each source: used, empty or not present, and the
///                                                   time range it covers
///   &lt;case&gt;\IpHistory.csv                          every collection's history merged, plus each
///                                                   host's own addresses from SystemInfo
///
/// Sources, in order of value:
///   Kerberos   4768 and 4769 in the DC's Security log, from EvtxECmd's output. A HOST$ account
///              with a client address ties a machine to an address at a moment. Successful
///              requests only: a failed one shows what was claimed, not who had the address.
///   DHCP       the WindowsDhcpServerLog module's output, when the DC (or this host) runs DHCP.
///   DNS audit  record create and delete events (515, 516, 519, 520) from
///              Microsoft-Windows-DNSServer/Audit, when that log was collected and parsed.
///   SystemInfo each host's own addresses at collection time (case roll-up only).
///
/// A collection is treated as a domain controller when its SystemInfo summary says so (the SYSTEM
/// hive's ProductType is LanmanNT) or, with no summary, when its Security log holds 4768/4769
/// events, which only a DC writes. A host that is not a DC but has DHCP server output gets a
/// history from that alone.
///
/// Generated files only: each collection's file is rebuilt when one of its inputs is newer, the
/// case file is rebuilt from the collections' files every time, and nothing else is written.
/// </summary>
public static class IpHistory
{
    public const string Folder = "IpHistory";
    public const string FileName = "IpHistory.csv";
    public const string SourcesFileName = "IpHistorySources.csv";
    public const string ModuleName = "IpHistory";

    public static readonly string[] SourceColumns =
        ["Source", "Status", "Events", "FirstSeenUtc", "LastSeenUtc", "Input"];

    private const string DomainControllerRole = "Domain controller";

    /// <summary>
    /// Builds every collection's history that is missing or out of date, then the case roll-up.
    /// Returns one result per collection that is a DC or DHCP server, for the run's results and
    /// manifest. Never throws for one bad collection: that collection's result is Failed.
    /// </summary>
    public static List<WorkResult> Build(string caseDirectory, CancellationToken cancellationToken = default)
    {
        var results = new List<WorkResult>();
        if (!Directory.Exists(caseDirectory) || cancellationToken.IsCancellationRequested) return results;

        foreach (var collectionDir in Directory.EnumerateDirectories(caseDirectory)
                                               .OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            if (Path.GetFileName(collectionDir).StartsWith('_')) continue;   // _Logs, _Extracted
            try
            {
                var result = BuildCollection(collectionDir, cancellationToken);
                if (result is not null) results.Add(result);
            }
            catch (OperationCanceledException)
            {
                return results;
            }
        }

        try { BuildCase(caseDirectory); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            results.Add(new WorkResult
            {
                Collection = Path.GetFileName(caseDirectory),
                Module = ModuleName,
                Category = Folder,
                Status = WorkStatus.Failed,
                Reason = "could not write the case IpHistory.csv: " + ex.Message,
                Destination = caseDirectory,
                Started = DateTimeOffset.Now
            });
        }
        return results;
    }

    /// <summary>
    /// One collection's history. Null when the collection is neither a DC nor a DHCP server, so
    /// workstations add nothing to the results.
    /// </summary>
    public static WorkResult? BuildCollection(string collectionDir, CancellationToken cancellationToken = default)
    {
        var name = Path.GetFileName(collectionDir);
        var outDir = Path.Combine(collectionDir, Folder);
        var outFile = Path.Combine(outDir, FileName);
        var sourcesFile = Path.Combine(outDir, SourcesFileName);

        var systemInfo = Path.Combine(collectionDir, "SystemInfo", "SystemInfo.csv");
        var facts = File.Exists(systemInfo) ? ReadFacts(systemInfo) : [];
        var role = facts.GetValueOrDefault("ComputerRole", "");
        var dcByRole = role.Equals(DomainControllerRole, StringComparison.OrdinalIgnoreCase);
        var evtx = Newest(Path.Combine(collectionDir, "EventLogs"), "EvtxECmd*.csv");
        var dhcp = Newest(outDir, Path.GetFileNameWithoutExtension(DhcpServerLogExport.OutputFile) + "*.csv");

        // A summary that names another role settles it; without one, only the Security log can.
        if (!dcByRole && dhcp is null && (role.Length > 0 || evtx is null)) return null;

        var stopwatch = Stopwatch.StartNew();
        var started = DateTimeOffset.Now;
        WorkResult Result(WorkStatus status, string reason) => new()
        {
            Collection = name, Module = ModuleName, Category = Folder, Status = status, Reason = reason,
            Destination = outDir, Started = started, DurationSeconds = stopwatch.Elapsed.TotalSeconds
        };

        var inputs = new[] { evtx, dhcp, File.Exists(systemInfo) ? systemInfo : null }.OfType<string>().ToList();
        if (UpToDate(outFile, sourcesFile, inputs))
            return Result(WorkStatus.Skipped,
                $"unchanged since {Path.Combine(Folder, FileName)} was built - sources in {Path.Combine(Folder, SourcesFileName)}");

        if (dcByRole && evtx is null && dhcp is null)
            return Result(WorkStatus.Skipped,
                "domain controller, but not present: EvtxECmd output (EventLogs\\EvtxECmd_EventLogs.csv) - run EvtxECmd for the Kerberos events");

        try
        {
            // A member server running DHCP has no Kerberos history to read; skip its event log.
            var events = evtx is null || (role.Length > 0 && !dcByRole)
                ? new EventLogSources()
                : ReadEventLog(evtx, name, cancellationToken);
            var isDc = dcByRole || events.Kerberos.Events > 0;
            if (!isDc && dhcp is null) return null;

            var dhcpSources = dhcp is null ? null : ReadDhcp(dhcp, name, cancellationToken);
            var dhcpV4 = dhcpSources?.V4 ?? new SourceTally("DHCP");
            var dhcpV6 = dhcpSources?.V6 ?? new SourceTally("DHCPv6");

            var sources = new List<SourceRow>
            {
                Describe(events.Kerberos, evtx is null ? null : Relative(collectionDir, evtx),
                    !isDc ? "not applicable: not identified as a domain controller"
                    : evtx is null ? "not present: no EvtxECmd output"
                    : !events.SecuritySeen ? "not present: no Security log events in the EvtxECmd output"
                    : "no events: the Security log holds no successful 4768/4769 (Kerberos auditing off, or the log rolled over?)"),
                Describe(dhcpV4, dhcp is null ? null : Relative(collectionDir, dhcp),
                    dhcp is null ? "not present: no DHCP server audit logs (WindowsDhcpServerLog)" : "no events"),
                Describe(dhcpV6, dhcp is null ? null : Relative(collectionDir, dhcp),
                    dhcp is null ? "not present: no DHCP server audit logs (WindowsDhcpServerLog)" : "not present: no IPv6 lease events"),
                Describe(events.Dns, evtx is null ? null : Relative(collectionDir, evtx),
                    events.DnsAuditSeen ? "no events: the DNS Server audit log holds no record changes"
                    : "not present: no Microsoft-Windows-DNSServer/Audit events in the EvtxECmd output")
            };

            var rows = events.Kerberos.Rows.Concat(events.Dns.Rows)
                .Concat(dhcpV4.Rows).Concat(dhcpV6.Rows)
                .ToList();

            Directory.CreateDirectory(outDir);
            WriteSources(sourcesFile, sources);
            if (rows.Count > 0) IpHistoryRecord.Write(outFile, rows);
            else if (File.Exists(outFile)) File.Delete(outFile);   // our own file, now stale

            var reason = new StringBuilder(isDc
                ? "domain controller (" + (dcByRole ? "SystemInfo" : "Kerberos events in its Security log") + ")"
                : "DHCP server");
            reason.Append($"; {rows.Count:N0} rows");
            foreach (var s in sources) reason.Append($"; {s.Source}: {s.Summary}");

            if (rows.Count == 0) return Result(WorkStatus.NoOutput, reason.ToString());
            if (isDc && events.Kerberos.Events == 0) return Result(WorkStatus.CheckLog, reason.ToString());
            return Result(WorkStatus.Completed, reason.ToString());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return Result(WorkStatus.Failed, "could not build the IP history: " + ex.Message);
        }
    }

    /// <summary>
    /// Merges every collection's IpHistory.csv, and each host's own addresses from its summary,
    /// into IpHistory.csv at the case root. Rows that agree on address, host, account, MAC and
    /// source are one row, whichever DCs saw them. Does nothing when no collection has a history,
    /// so a case with no DC or DHCP server gets no file.
    /// </summary>
    public static string? BuildCase(string caseDirectory)
    {
        var collections = Directory.EnumerateDirectories(caseDirectory)
            .Where(d => !Path.GetFileName(d).StartsWith('_'))
            .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var histories = collections.Select(d => Path.Combine(d, Folder, FileName)).Where(File.Exists).ToList();
        if (histories.Count == 0) return null;

        var rows = histories.SelectMany(IpHistoryRecord.Read).ToList();
        foreach (var collectionDir in collections)
        {
            var summary = Path.Combine(collectionDir, "SystemInfo", "SystemInfo.csv");
            if (!File.Exists(summary)) continue;
            var facts = ReadFacts(summary);
            var host = facts.GetValueOrDefault("Hostname", "");
            foreach (var address in facts.GetValueOrDefault("IPAddresses", "").Split([',', ' '], StringSplitOptions.RemoveEmptyEntries))
            {
                if (!IPAddress.TryParse(address, out var ip) || IPAddress.IsLoopback(ip)) continue;
                rows.Add(new IpHistoryRecord(IpHistoryRecord.Normalise(address), host, "", "", null, null,
                                             "SystemInfo", null, Path.GetFileName(collectionDir)));
            }
        }

        var path = Path.Combine(caseDirectory, FileName);
        IpHistoryRecord.Write(path, Merge(rows));
        return path;
    }

    /// <summary>Rows that agree on everything but time, count and collection become one.</summary>
    public static IEnumerable<IpHistoryRecord> Merge(IEnumerable<IpHistoryRecord> rows) =>
        rows.GroupBy(r => (IpHistoryRecord.Normalise(r.IpAddress), r.HostName.ToUpperInvariant(),
                           r.Account.ToUpperInvariant(), r.MacAddress.ToUpperInvariant(), r.Source))
            .Select(g => g.First() with
            {
                FirstSeenUtc = g.Min(r => r.FirstSeenUtc),
                LastSeenUtc = g.Max(r => r.LastSeenUtc),
                EventCount = g.All(r => r.EventCount is null) ? null : g.Sum(r => r.EventCount ?? 0),
                Collection = string.Join("; ", g.SelectMany(r => r.Collection.Split("; "))
                                                .Where(c => c.Length > 0)
                                                .Distinct(StringComparer.OrdinalIgnoreCase)
                                                .Order(StringComparer.OrdinalIgnoreCase))
            });

    // --- event log --------------------------------------------------------------------------------

    /// <summary>What one pass over EvtxECmd's CSV found.</summary>
    public sealed class EventLogSources
    {
        public SourceTally Kerberos { get; } = new("Kerberos");
        public SourceTally Dns { get; } = new("DNS audit");
        /// <summary>The Security log is in the output at all, so "no 4768" means something.</summary>
        public bool SecuritySeen { get; set; }
        public bool DnsAuditSeen { get; set; }
    }

    /// <summary>
    /// Reads Kerberos and DNS audit events from EvtxECmd's CSV, by column name. The event fields
    /// come from the Payload column (the event's own EventData), not from the map-dependent
    /// PayloadData columns, so a change to EvtxECmd's maps cannot move them.
    /// </summary>
    public static EventLogSources ReadEventLog(string path, string collection, CancellationToken cancellationToken = default)
    {
        var found = new EventLogSources();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return found;

        int Column(string n) => header.FindIndex(h => h.Trim().Equals(n, StringComparison.OrdinalIgnoreCase));
        var timeCol = Column("TimeCreated");
        var idCol = Column("EventId");
        var channelCol = Column("Channel");
        var providerCol = Column("Provider");
        var payloadCol = Column("Payload");
        if (timeCol < 0 || idCol < 0 || channelCol < 0 || payloadCol < 0)
            throw new InvalidDataException($"{Path.GetFileName(path)} is not EvtxECmd output: TimeCreated, EventId, Channel or Payload column missing");

        var rows = 0;
        while (reader.ReadRecord() is { } fields)
        {
            if ((++rows & 0xFFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (fields.Count <= Math.Max(Math.Max(timeCol, idCol), Math.Max(channelCol, payloadCol))) continue;

            var channel = fields[channelCol];
            var isSecurity = channel.Equals("Security", StringComparison.OrdinalIgnoreCase);
            var isDnsAudit = channel.Contains("DNSServer/Audit", StringComparison.OrdinalIgnoreCase)
                             || (providerCol >= 0 && fields[providerCol].Contains("DNSServer", StringComparison.OrdinalIgnoreCase)
                                 && channel.Contains("Audit", StringComparison.OrdinalIgnoreCase));
            if (!isSecurity && !isDnsAudit) continue;
            if (isSecurity) found.SecuritySeen = true;
            if (isDnsAudit) found.DnsAuditSeen = true;

            var id = fields[idCol].Trim();
            if (isSecurity && id is "4768" or "4769")
                AddKerberos(found.Kerberos, fields[timeCol], EventData(fields[payloadCol]), collection);
            else if (isDnsAudit && id is "515" or "516" or "519" or "520")
                AddDns(found.Dns, fields[timeCol], EventData(fields[payloadCol]), collection);
        }

        return found;
    }

    private static void AddKerberos(SourceTally tally, string time, Dictionary<string, string> data, string collection)
    {
        // 0x0 is success. Anything else is a request that was refused, which proves only that
        // something at that address asked as that account.
        var status = data.GetValueOrDefault("Status", "0x0").Trim();
        if (!status.Equals("0x0", StringComparison.OrdinalIgnoreCase) && status != "0") return;

        var address = data.GetValueOrDefault("IpAddress", "").Trim();
        if (!IPAddress.TryParse(address, out var ip)) return;   // "-" or empty: a local request
        if (IPAddress.IsLoopback(ip)) return;
        if (ip.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(ip.MapToIPv4())) return;

        // 4769 writes the client as HOST01$@CORP.EXAMPLE; 4768 as HOST01$ with the realm apart.
        var account = data.GetValueOrDefault("TargetUserName", "").Trim();
        var at = account.IndexOf('@');
        if (at >= 0) account = account[..at];
        if (account.Length == 0) return;

        var host = account.EndsWith('$') ? account[..^1].ToUpperInvariant() : "";
        tally.Add(IpHistoryRecord.Normalise(address), host, account, "", ParseEventTime(time), collection);
    }

    private static void AddDns(SourceTally tally, string time, Dictionary<string, string> data, string collection)
    {
        var type = data.GetValueOrDefault("Type", "").Trim();
        if (type is not ("1" or "28")) return;   // A and AAAA; the rest do not map a name to an address

        var name = data.GetValueOrDefault("NAME", "").Trim().TrimEnd('.');
        var address = DnsRecordAddress(data.GetValueOrDefault("RDATA", ""));
        if (name.Length == 0 || address is null) return;
        tally.Add(address, name, "", "", ParseEventTime(time), collection);
    }

    /// <summary>
    /// The address in a DNS audit event's RDATA. The event writes A and AAAA data as hex
    /// (0x0A000005 for 10.0.0.5); a dotted address is taken as it is.
    /// </summary>
    public static string? DnsRecordAddress(string rdata)
    {
        var text = rdata.Trim();
        if (IPAddress.TryParse(text, out _) && !text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && (text.Contains('.') || text.Contains(':')))
            return IpHistoryRecord.Normalise(text);

        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        if (text.Length is not (8 or 32) || !text.All(char.IsAsciiHexDigit)) return null;
        return new IPAddress(Convert.FromHexString(text)).ToString();
    }

    /// <summary>EventData Name -> value from EvtxECmd's Payload JSON. Empty when it holds none.</summary>
    public static Dictionary<string, string> EventData(string payload)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(payload)) return data;
        try
        {
            using var doc = JsonDocument.Parse(payload);
            if (!doc.RootElement.TryGetProperty("EventData", out var eventData)
                || !eventData.TryGetProperty("Data", out var items)) return data;

            // One <Data> element comes through as an object, several as an array, unnamed text as a string.
            var list = items.ValueKind switch
            {
                JsonValueKind.Array => items.EnumerateArray().ToList(),
                JsonValueKind.Object => [items],
                _ => []
            };
            foreach (var item in list)
            {
                if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("@Name", out var n)) continue;
                data[n.GetString() ?? ""] = item.TryGetProperty("#text", out var t) ? t.ToString() : "";
            }
        }
        catch (JsonException) { }
        return data;
    }

    internal static DateTime? ParseEventTime(string text) =>
        text.Length >= 19 ? IpHistoryRecord.ParseTime(text[..19]) : null;

    // --- DHCP -------------------------------------------------------------------------------------

    public sealed record DhcpSources(SourceTally V4, SourceTally V6);

    /// <summary>Reads the WindowsDhcpServerLog module's CSV.</summary>
    public static DhcpSources ReadDhcp(string path, string collection, CancellationToken cancellationToken = default)
    {
        var sources = new DhcpSources(new SourceTally("DHCP"), new SourceTally("DHCPv6"));
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return sources;
        var index = header.Select((n, i) => (n, i)).ToDictionary(p => p.n.Trim(), p => p.i, StringComparer.OrdinalIgnoreCase);

        while (reader.ReadRecord() is { } fields)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string Cell(string n) => index.TryGetValue(n, out var i) && i < fields.Count ? fields[i] : "";
            var address = Cell("IpAddress");
            if (!IPAddress.TryParse(address, out _)) continue;
            var tally = Cell("Protocol").Equals("DHCPv6", StringComparison.OrdinalIgnoreCase) ? sources.V6 : sources.V4;
            tally.Add(IpHistoryRecord.Normalise(address), Cell("HostName"), "", Cell("MacAddress"),
                      IpHistoryRecord.ParseTime(Cell("TimeUtc")), collection);
        }
        return sources;
    }

    // --- shared -----------------------------------------------------------------------------------

    /// <summary>Events from one source, gathered into first/last-seen rows as they are read.</summary>
    public sealed class SourceTally(string source)
    {
        private readonly Dictionary<(string, string, string, string), Seen> _rows = [];
        private string _collection = "";

        public string Source { get; } = source;
        public int Events { get; private set; }
        public DateTime? First { get; private set; }
        public DateTime? Last { get; private set; }

        public void Add(string address, string host, string account, string mac, DateTime? time, string collection)
        {
            _collection = collection;
            Events++;
            First = Earlier(First, time);
            Last = Later(Last, time);

            var key = (address, host.ToUpperInvariant(), account.ToUpperInvariant(), mac.ToUpperInvariant());
            if (_rows.TryGetValue(key, out var seen))
            {
                seen.First = Earlier(seen.First, time);
                seen.Last = Later(seen.Last, time);
                seen.Count++;
            }
            else _rows[key] = new Seen { Host = host, Account = account, Mac = mac, First = time, Last = time, Count = 1 };
        }

        public IEnumerable<IpHistoryRecord> Rows => _rows.Select(p => new IpHistoryRecord(
            p.Key.Item1, p.Value.Host, p.Value.Account, p.Value.Mac, p.Value.First, p.Value.Last,
            Source, p.Value.Count, _collection));

        private sealed class Seen
        {
            public required string Host { get; init; }
            public required string Account { get; init; }
            public required string Mac { get; init; }
            public DateTime? First { get; set; }
            public DateTime? Last { get; set; }
            public int Count { get; set; }
        }

        private static DateTime? Earlier(DateTime? a, DateTime? b) => a is null ? b : b is null ? a : a < b ? a : b;
        private static DateTime? Later(DateTime? a, DateTime? b) => a is null ? b : b is null ? a : a > b ? a : b;
    }

    private sealed record SourceRow(string Source, string Status, int Events, DateTime? First, DateTime? Last, string Input)
    {
        public string Summary => Events > 0
            ? $"{Events:N0} events" + (First is null ? "" : $" {IpHistoryRecord.Format(First)} to {IpHistoryRecord.Format(Last)} UTC")
            : Status;
    }

    private static SourceRow Describe(SourceTally tally, string? input, string whenEmpty) =>
        tally.Events > 0
            ? new SourceRow(tally.Source, "used", tally.Events, tally.First, tally.Last, input ?? "")
            : new SourceRow(tally.Source, whenEmpty, 0, null, null, input ?? "");

    private static void WriteSources(string path, IEnumerable<SourceRow> sources)
    {
        using var csv = new StreamWriter(path, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        CsvFile.WriteRow(csv, SourceColumns);
        foreach (var s in sources)
            CsvFile.WriteRow(csv, s.Source, s.Status, s.Events.ToString(CultureInfo.InvariantCulture),
                             IpHistoryRecord.Format(s.First), IpHistoryRecord.Format(s.Last), s.Input);
    }

    /// <summary>Both outputs exist and are newer than every input, so a rebuild would write the same.</summary>
    private static bool UpToDate(string outFile, string sourcesFile, IReadOnlyList<string> inputs)
    {
        if (!File.Exists(sourcesFile)) return false;
        var built = File.GetLastWriteTimeUtc(sourcesFile);
        if (File.Exists(outFile) && File.GetLastWriteTimeUtc(outFile) < built) built = File.GetLastWriteTimeUtc(outFile);
        return inputs.All(i => File.GetLastWriteTimeUtc(i) <= built);
    }

    /// <summary>
    /// The most recent file matching the pattern. A module re-run writes its output beside the
    /// old file (EvtxECmd_EventLogs_2.csv), and the newer one is the complete one.
    /// </summary>
    private static string? Newest(string directory, string pattern) =>
        Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, pattern)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault()
            : null;

    private static string Relative(string collectionDir, string path) => Path.GetRelativePath(collectionDir, path);

    /// <summary>Item -> Value from a SystemInfo summary (Category, Item, Value, Source).</summary>
    internal static Dictionary<string, string> ReadFacts(string path)
    {
        var facts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var reader = new CsvRecordReader(path);
            var header = reader.ReadRecord();
            if (header is null) return facts;
            var item = header.FindIndex(h => h.Trim().Equals("Item", StringComparison.OrdinalIgnoreCase));
            var value = header.FindIndex(h => h.Trim().Equals("Value", StringComparison.OrdinalIgnoreCase));
            if (item < 0 || value < 0) return facts;
            while (reader.ReadRecord() is { } fields)
                if (fields.Count > Math.Max(item, value) && fields[value].Length > 0)
                    facts[fields[item]] = fields[value];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return facts;
    }
}
