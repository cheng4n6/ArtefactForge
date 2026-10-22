using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// Builds each Windows host's remote access file: the few thousand events and artefacts about
/// Remote Desktop connections, out of EvtxECmd output that can run to gigabytes. The RDP trace
/// reads these files, so a trace takes a second rather than a pass over every host's event log.
///
///   &lt;collection&gt;\RemoteAccess\RemoteAccess.csv         the events (columns: RemoteAccessEvent)
///   &lt;collection&gt;\RemoteAccess\RemoteAccessSources.csv  each log and artefact: used or not present,
///                                                       the time it covers, and when it was cleared
///
/// Inbound (this host received a connection):
///   Security 4624 logon type 10, 4778 reconnect, 4779 disconnect, 4634 logoff of a type 10 logon
///   TerminalServices-RemoteConnectionManager 1149 (network authentication succeeded)
///   TerminalServices-LocalSessionManager 21 logon, 23 logoff, 24 disconnect, 25 reconnect
///   RemoteDesktopServices-RdpCoreTS 131 (TCP connection accepted)
/// Outbound (this host connected to another):
///   TerminalServices-RDPClient 1024 (connecting to a server name) and 1102 (to an address)
///   NTUSER Terminal Server Client Default MRU and Servers keys (RECmd)
///   mstsc.exe in Prefetch (PECmd), Amcache (AmcacheParser) and its jump list (JLECmd)
///
/// Derived files only: a host's files are rebuilt when one of its inputs is newer, and a trace
/// builds them for hosts processed before this existed. Nothing else is written.
/// </summary>
public static class RemoteAccess
{
    public const string Folder = "RemoteAccess";
    public const string FileName = "RemoteAccess.csv";
    public const string SourcesFileName = "RemoteAccessSources.csv";
    public const string ModuleName = "RemoteAccess";

    public static readonly string[] SourceColumns =
        ["Log", "Status", "Events", "FirstEventUtc", "LastEventUtc", "ClearedUtc", "Input"];

    public const string SecurityLog = "Security";
    public const string SystemLog = "System";
    public const string RcmLog = "RemoteConnectionManager";
    public const string LsmLog = "LocalSessionManager";
    public const string RdpCoreLog = "RdpCoreTS";
    public const string ClientLog = "RDPClient";

    private const string RcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
    private const string LsmChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    private const string RdpCoreChannel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
    private const string ClientChannel = "Microsoft-Windows-TerminalServices-RDPClient/Operational";

    // The Remote Desktop Connection jump list (mstsc.exe's AppID).
    private const string MstscAppId = "1bc392b8e104a00e";

    private static readonly Regex MstscTarget = new(@"/v:\s*""?([^\s""]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Builds every collection's file that is missing or out of date. Returns one result per
    /// collection that was built, or that has Windows artefacts but no event log to read.
    /// </summary>
    public static List<WorkResult> Build(string caseDirectory, CancellationToken cancellationToken = default)
    {
        var results = new List<WorkResult>();
        if (!Directory.Exists(caseDirectory)) return results;
        foreach (var collectionDir in Directory.EnumerateDirectories(caseDirectory)
                                               .Where(d => !Path.GetFileName(d).StartsWith('_'))
                                               .OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            if (cancellationToken.IsCancellationRequested) break;
            try
            {
                if (BuildCollection(collectionDir, cancellationToken) is { } result) results.Add(result);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
        return results;
    }

    /// <summary>
    /// One collection's file. Null when it has nothing to read, or nothing changed since it was
    /// built, so hosts with no Windows output add nothing to the results.
    /// </summary>
    public static WorkResult? BuildCollection(string collectionDir, CancellationToken cancellationToken = default)
    {
        var name = Path.GetFileName(collectionDir);
        var outDir = Path.Combine(collectionDir, Folder);
        var outFile = Path.Combine(outDir, FileName);
        var sourcesFile = Path.Combine(outDir, SourcesFileName);

        var inputs = FindInputs(collectionDir);
        if (inputs.All.Count == 0) return null;
        if (UpToDate(outFile, sourcesFile, inputs.All)) return null;

        var stopwatch = Stopwatch.StartNew();
        var started = DateTimeOffset.Now;
        WorkResult Result(WorkStatus status, string reason) => new()
        {
            Collection = name, Module = ModuleName, Category = Folder, Status = status, Reason = reason,
            Destination = outDir, Started = started, DurationSeconds = stopwatch.Elapsed.TotalSeconds
        };

        try
        {
            var events = new List<RemoteAccessEvent>();
            var sources = new List<SourceRow>();

            if (inputs.EventLog is { } evtx)
            {
                var read = ReadEventLog(evtx, cancellationToken);
                events.AddRange(read.Events);
                var input = Path.GetRelativePath(collectionDir, evtx);
                foreach (var log in new[] { SecurityLog, SystemLog, RcmLog, LsmLog, RdpCoreLog, ClientLog })
                {
                    var c = read.Coverage.GetValueOrDefault(log);
                    sources.Add(c is null
                        ? new SourceRow(log, "not present: no events from this log in the EvtxECmd output", 0, null, null, [], input)
                        : new SourceRow(log, "used", c.Events, c.First, c.Last, c.Cleared, input));
                }
            }
            else
            {
                sources.Add(new SourceRow("Event logs", "not present: no EvtxECmd output (EventLogs\\EvtxECmd_EventLogs.csv) - run EvtxECmd for the RDP events",
                                          0, null, null, [], ""));
            }

            AddArtefacts(sources, events, "Registry MRU", inputs.Registry, collectionDir, f => ReadRegistry(f, cancellationToken),
                         "RECmd_NTUSER");
            AddArtefacts(sources, events, "Prefetch", inputs.Prefetch, collectionDir, f => ReadPrefetch(f, cancellationToken), "PECmd");
            AddArtefacts(sources, events, "Amcache", inputs.Amcache, collectionDir, f => ReadAmcache(f, cancellationToken), "AmcacheParser");
            AddArtefacts(sources, events, "Jump list", inputs.JumpLists, collectionDir, f => ReadJumpList(f, cancellationToken), "JLECmd");

            Directory.CreateDirectory(outDir);
            WriteSources(sourcesFile, sources);
            RemoteAccessEvent.Write(outFile, events);

            var inbound = events.Count(e => e.Direction == RemoteAccessEvent.Inbound);
            var outbound = events.Count - inbound;
            var reason = $"{inbound:N0} inbound and {outbound:N0} outbound RDP events and artefacts";
            if (inputs.EventLog is null)
                return Result(WorkStatus.CheckLog, reason + "; no EvtxECmd output, so no RDP events - run EvtxECmd to trace RDP through this host");
            var cleared = sources.Where(s => s.Cleared.Count > 0).ToList();
            if (cleared.Count > 0)
                reason += "; log cleared: " + string.Join(", ", cleared.Select(s => $"{s.Log} at {string.Join(", ", s.Cleared.Select(t => IpHistoryRecord.Format(t)))} UTC"));
            return Result(WorkStatus.Completed, reason);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return Result(WorkStatus.Failed, "could not build the remote access file: " + ex.Message);
        }
    }

    /// <summary>A host's remote access file, built first if missing or out of date.</summary>
    public static RemoteAccessHost Load(string collectionDir, CancellationToken cancellationToken = default)
    {
        var built = BuildCollection(collectionDir, cancellationToken);
        var file = Path.Combine(collectionDir, Folder, FileName);
        var sourcesFile = Path.Combine(collectionDir, Folder, SourcesFileName);
        var events = File.Exists(file) ? RemoteAccessEvent.Read(file) : [];
        var coverage = File.Exists(sourcesFile) ? ReadSources(sourcesFile) : [];

        var summary = Path.Combine(collectionDir, "SystemInfo", "SystemInfo.csv");
        var facts = File.Exists(summary) ? IpHistory.ReadFacts(summary) : [];
        var name = facts.GetValueOrDefault("Hostname", "");
        // No summary: the name the host wrote into its own events, else the collection folder.
        if (name.Length == 0)
            name = events.Where(e => e.Computer.Length > 0)
                         .GroupBy(e => e.Computer.Split('.')[0].ToUpperInvariant())
                         .OrderByDescending(g => g.Count())
                         .Select(g => g.Key)
                         .FirstOrDefault() ?? "";
        if (name.Length == 0) name = Path.GetFileName(collectionDir);

        var addresses = facts.GetValueOrDefault("IPAddresses", "")
            .Split([',', ' '], StringSplitOptions.RemoveEmptyEntries)
            .Where(a => IPAddress.TryParse(a, out _))
            .Select(IpHistoryRecord.Normalise)
            .ToList();
        var fullNames = events.Select(e => e.Computer).Where(c => c.Length > 0)
                              .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        return new RemoteAccessHost(Path.GetFileName(collectionDir), collectionDir, name.Split('.')[0].ToUpperInvariant(),
                                    fullNames, addresses, events, coverage,
                                    File.Exists(file) ? File.GetLastWriteTimeUtc(file) : null,
                                    built?.Status == WorkStatus.Failed ? built.Reason : null);
    }

    // --- event log --------------------------------------------------------------------------------

    public sealed class LogCoverage
    {
        public int Events { get; set; }
        public DateTime? First { get; set; }
        public DateTime? Last { get; set; }
        public List<DateTime> Cleared { get; } = [];

        internal void Saw(DateTime? time)
        {
            Events++;
            if (time is not { } t) return;
            if (First is null || t < First) First = t;
            if (Last is null || t > Last) Last = t;
        }
    }

    public sealed record EventLogRead(List<RemoteAccessEvent> Events, Dictionary<string, LogCoverage> Coverage);

    /// <summary>
    /// Reads the RDP events from EvtxECmd's CSV, by column name, and notes where each log starts
    /// and ends. Event fields come from the Payload column (the event's own XML as JSON), so a
    /// change to EvtxECmd's maps cannot move them.
    /// </summary>
    public static EventLogRead ReadEventLog(string path, CancellationToken cancellationToken = default)
    {
        var events = new List<RemoteAccessEvent>();
        var coverage = new Dictionary<string, LogCoverage>(StringComparer.Ordinal);
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return new EventLogRead(events, coverage);

        int Column(string n) => header.FindIndex(h => h.Trim().Equals(n, StringComparison.OrdinalIgnoreCase));
        var timeCol = Column("TimeCreated");
        var idCol = Column("EventId");
        var channelCol = Column("Channel");
        var computerCol = Column("Computer");
        var payloadCol = Column("Payload");
        if (timeCol < 0 || idCol < 0 || channelCol < 0 || payloadCol < 0)
            throw new InvalidDataException($"{Path.GetFileName(path)} is not EvtxECmd output: TimeCreated, EventId, Channel or Payload column missing");
        var last = new[] { timeCol, idCol, channelCol, computerCol }.Max();
        // The Payload is read only for the events below; every other row needs just its time.
        var wantPayload = payloadCol > last
            ? fields => LogName(fields[channelCol]) is { } l && WantsPayload(l, fields[idCol].Trim())
            : (Func<List<string>, bool>?)null;

        var rows = 0;
        while (reader.ReadRecord(last, wantPayload) is { } fields)
        {
            if ((++rows & 0xFFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (fields.Count <= last) continue;
            var hasPayload = fields.Count > payloadCol;

            var log = LogName(fields[channelCol]);
            if (log is null) continue;
            var time = IpHistory.ParseEventTime(fields[timeCol]);
            if (!coverage.TryGetValue(log, out var c)) coverage[log] = c = new LogCoverage();
            c.Saw(time);

            var id = fields[idCol].Trim();
            var computer = computerCol >= 0 ? fields[computerCol].Trim() : "";
            switch (log, id)
            {
                case (SecurityLog, "1102"):
                    if (time is { } cleared) c.Cleared.Add(cleared);
                    break;
                case (_, _) when !hasPayload:
                    break;
                case (SystemLog, "104"):
                    // The System log records the clearing of any log; the cleared log is named in it.
                    var data104 = Fields(fields[payloadCol]);
                    var clearedLog = LogName(data104.GetValueOrDefault("Channel", "")) ?? data104.GetValueOrDefault("Channel", "");
                    if (time is { } t104 && clearedLog.Length > 0)
                    {
                        if (!coverage.TryGetValue(clearedLog, out var target)) coverage[clearedLog] = target = new LogCoverage();
                        target.Cleared.Add(t104);
                    }
                    break;
                case (SecurityLog, "4624" or "4778" or "4779" or "4634"):
                case (RcmLog, "1149"):
                case (LsmLog, "21" or "23" or "24" or "25"):
                case (RdpCoreLog, "131"):
                case (ClientLog, "1024" or "1102"):
                    if (ToEvent(log, id, time, computer, Fields(fields[payloadCol])) is { } e) events.Add(e);
                    break;
            }
        }
        return new EventLogRead(events, coverage);
    }

    /// <summary>The events <see cref="ReadEventLog"/> reads a Payload for.</summary>
    private static bool WantsPayload(string log, string id) => (log, id) switch
    {
        (SystemLog, "104") => true,
        (SecurityLog, "4624" or "4778" or "4779" or "4634") => true,
        (RcmLog, "1149") => true,
        (LsmLog, "21" or "23" or "24" or "25") => true,
        (RdpCoreLog, "131") => true,
        (ClientLog, "1024" or "1102") => true,
        _ => false
    };

    private static string? LogName(string channel) => channel.Trim() switch
    {
        var c when c.Equals("Security", StringComparison.OrdinalIgnoreCase) => SecurityLog,
        var c when c.Equals("System", StringComparison.OrdinalIgnoreCase) => SystemLog,
        var c when c.Equals(RcmChannel, StringComparison.OrdinalIgnoreCase) => RcmLog,
        var c when c.Equals(LsmChannel, StringComparison.OrdinalIgnoreCase) => LsmLog,
        var c when c.Equals(RdpCoreChannel, StringComparison.OrdinalIgnoreCase) => RdpCoreLog,
        var c when c.Equals(ClientChannel, StringComparison.OrdinalIgnoreCase) => ClientLog,
        _ => null
    };

    private static RemoteAccessEvent? ToEvent(string log, string id, DateTime? time, string computer, Dictionary<string, string> d)
    {
        string F(string n) => d.GetValueOrDefault(n, "").Trim();
        RemoteAccessEvent In(string kind, string account, string address, string remoteName,
                             string logonId = "", string sessionId = "", string detail = "") =>
            new(time, RemoteAccessEvent.Inbound, $"{Short(log)} {id}", kind, account, CleanAddress(address),
                CleanName(remoteName), logonId, sessionId, computer, detail);

        switch (log, id)
        {
            case (SecurityLog, "4624"):
                // Type 10 is RemoteInteractive: an RDP logon. Type 7 (unlock) and 3 (network)
                // are other things, and are left for later lateral movement work.
                if (F("LogonType") != "10") return null;
                return In("Logon", Account(F("TargetDomainName"), F("TargetUserName")), F("IpAddress"), F("WorkstationName"),
                          F("TargetLogonId"), detail: "logon type 10");
            case (SecurityLog, "4634"):
                if (F("LogonType") != "10") return null;
                return In("Logoff", Account(F("TargetDomainName"), F("TargetUserName")), "", "", F("TargetLogonId"));
            case (SecurityLog, "4778" or "4779"):
                return In(id == "4778" ? "Reconnect" : "Disconnect", Account(F("AccountDomain"), F("AccountName")),
                          F("ClientAddress"), F("ClientName"), F("LogonID"), detail: F("SessionName"));
            case (RcmLog, "1149"):
                return In("Authenticated", Account(F("Param2"), F("Param1")), F("Param3"), "");
            case (LsmLog, _):
                // "LOCAL" is a console session: not remote.
                var address = F("Address");
                if (address.Equals("LOCAL", StringComparison.OrdinalIgnoreCase)) return null;
                var kind = id switch { "21" => "Logon", "23" => "Logoff", "24" => "Disconnect", _ => "Reconnect" };
                return In(kind, F("User"), address, "", sessionId: F("SessionID"));
            case (RdpCoreLog, "131"):
                return In("TcpAccepted", "", F("ClientIP"), "", detail: F("ConnType"));
            case (ClientLog, _):
                var server = F("Value");
                if (server.Length == 0) return null;
                var isAddress = IPAddress.TryParse(CleanAddress(server), out _);
                return new RemoteAccessEvent(time, RemoteAccessEvent.Outbound, $"{Short(log)} {id}", "Connect", "",
                    isAddress ? CleanAddress(server) : "", isAddress ? "" : CleanName(server), "", "", computer,
                    id == "1024" ? "connecting to a server" : "multi-transport connection to a server");
        }
        return null;
    }

    private static string Short(string log) => log switch
    {
        RcmLog => "RCM",
        LsmLog => "LSM",
        _ => log
    };

    private static string Account(string domain, string user)
    {
        if (user.Length == 0 || user == "-") return "";
        return domain.Length > 0 && domain != "-" ? domain + "\\" + user : user;
    }

    /// <summary>
    /// The address without its port or brackets: RdpCoreTS writes 10.0.0.5:51234 and
    /// [fe80::1]:51234. "-" and other non-addresses come back empty, loopback is kept.
    /// </summary>
    public static string CleanAddress(string text)
    {
        var value = text.Trim();
        if (value.Length == 0 || value == "-") return "";
        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close > 0) value = value[1..close];
        }
        else if (value.Count(ch => ch == ':') == 1)
            value = value[..value.IndexOf(':')];
        return IPAddress.TryParse(value, out _) ? IpHistoryRecord.Normalise(value) : "";
    }

    private static string CleanName(string text)
    {
        var value = text.Trim();
        return value == "-" ? "" : value;
    }

    /// <summary>
    /// Every named field in an EvtxECmd Payload: EventData's Name/#text pairs and the elements of
    /// UserData (which is where 1149 and the LocalSessionManager events keep theirs).
    /// </summary>
    public static Dictionary<string, string> Fields(string payload)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(payload)) return data;
        try
        {
            using var doc = JsonDocument.Parse(payload);
            Walk(doc.RootElement, data);
        }
        catch (JsonException) { }
        return data;
    }

    private static void Walk(JsonElement element, Dictionary<string, string> data)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray()) Walk(item, data);
                break;
            case JsonValueKind.Object:
                if (element.TryGetProperty("@Name", out var name) && name.ValueKind == JsonValueKind.String)
                {
                    data[name.GetString() ?? ""] = element.TryGetProperty("#text", out var t) ? t.ToString() : "";
                    break;
                }
                foreach (var p in element.EnumerateObject())
                {
                    if (p.Name.StartsWith('@') || p.Name.StartsWith('#')) continue;
                    if (p.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array) Walk(p.Value, data);
                    else data[p.Name] = p.Value.ToString();
                }
                break;
        }
    }

    // --- other artefacts --------------------------------------------------------------------------

    private sealed record Inputs(
        string? EventLog, List<string> Registry, List<string> Prefetch, List<string> Amcache, List<string> JumpLists)
    {
        public List<string> All => new[] { EventLog }.OfType<string>().Concat(Registry).Concat(Prefetch)
                                                     .Concat(Amcache).Concat(JumpLists).ToList();
    }

    private static Inputs FindInputs(string collectionDir)
    {
        List<string> Files(string folder, string pattern)
        {
            var dir = Path.Combine(collectionDir, folder);
            return Directory.Exists(dir)
                ? Directory.EnumerateFiles(dir, pattern, SearchOption.AllDirectories)
                           .Order(StringComparer.OrdinalIgnoreCase).ToList()
                : [];
        }

        // A module re-run writes beside the old file (EvtxECmd_EventLogs_2.csv); the newest is complete.
        var evtx = Files("EventLogs", "EvtxECmd*.csv").OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault();
        return new Inputs(
            evtx,
            Files("Registry", "*_RECmd_NTUSER.csv"),
            Files("Prefetch", "*PECmd_Output.csv"),
            Files("Amcache", "*FileEntries.csv"),
            Files("JumpLists", "*_AutomaticDestinations.csv"));
    }

    private static void AddArtefacts(List<SourceRow> sources, List<RemoteAccessEvent> events, string source,
                                     List<string> files, string collectionDir,
                                     Func<string, IEnumerable<RemoteAccessEvent>> read, string module)
    {
        if (files.Count == 0)
        {
            sources.Add(new SourceRow(source, $"not present: no {module} output", 0, null, null, [], ""));
            return;
        }
        var found = files.SelectMany(read).ToList();
        events.AddRange(found);
        var times = found.Select(e => e.TimeUtc).OfType<DateTime>().ToList();
        sources.Add(new SourceRow(source, found.Count > 0 ? "used" : "no RDP entries", found.Count,
                                  times.Count > 0 ? times.Min() : null, times.Count > 0 ? times.Max() : null, [],
                                  string.Join("; ", files.Select(f => Path.GetRelativePath(collectionDir, f)))));
    }

    /// <summary>Reads a CSV by column name, one dictionary-free row at a time.</summary>
    private static IEnumerable<Func<string, string>> Rows(string path, CancellationToken cancellationToken)
    {
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) yield break;
        var index = header.Select((n, i) => (n, i))
            .GroupBy(p => p.n.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().i, StringComparer.OrdinalIgnoreCase);
        while (reader.ReadRecord() is { } fields)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return n => index.TryGetValue(n, out var i) && i < fields.Count ? fields[i] : "";
        }
    }

    private static DateTime? Time(string text) => IpHistory.ParseEventTime(text.Trim());

    /// <summary>
    /// The Terminal Server Client keys from RECmd's NTUSER batch output: Default\MRUn values name
    /// servers this user connected to, and each Servers\&lt;name&gt; key's last write time is
    /// roughly the last connection to that server.
    /// </summary>
    private static IEnumerable<RemoteAccessEvent> ReadRegistry(string path, CancellationToken cancellationToken)
    {
        var user = UserFromFileName(path, "_RECmd_NTUSER");
        foreach (var cell in Rows(path, cancellationToken))
        {
            var key = cell("KeyPath");
            var at = key.IndexOf(@"Terminal Server Client\", StringComparison.OrdinalIgnoreCase);
            if (at < 0) continue;
            var rest = key[(at + @"Terminal Server Client\".Length)..];
            var written = Time(cell("LastWriteTimestamp"));

            if (rest.StartsWith(@"Servers\", StringComparison.OrdinalIgnoreCase))
            {
                var server = rest[@"Servers\".Length..].Split('\\')[0];
                if (server.Length == 0) continue;
                var hint = cell("ValueName").Equals("UsernameHint", StringComparison.OrdinalIgnoreCase) ? cell("ValueData") : "";
                yield return Artefact(written, "Registry MRU", "Recent", user, server,
                                      "Servers key last written" + (hint.Length > 0 ? $"; UsernameHint {hint}" : ""));
            }
            else if (rest.Equals("Default", StringComparison.OrdinalIgnoreCase)
                     && cell("ValueName").StartsWith("MRU", StringComparison.OrdinalIgnoreCase))
            {
                var server = cell("ValueData").Trim();
                if (server.Length == 0) continue;
                // Only MRU0 is the newest; the Default key's write time says nothing about the rest.
                var newest = cell("ValueName").Equals("MRU0", StringComparison.OrdinalIgnoreCase);
                yield return Artefact(newest ? written : null, "Registry MRU", "Recent", user, server,
                                      $"Default {cell("ValueName")}");
            }
        }
    }

    private static IEnumerable<RemoteAccessEvent> ReadPrefetch(string path, CancellationToken cancellationToken)
    {
        foreach (var cell in Rows(path, cancellationToken))
        {
            if (!cell("ExecutableName").Equals("MSTSC.EXE", StringComparison.OrdinalIgnoreCase)) continue;
            var runs = new[] { "LastRun" }.Concat(Enumerable.Range(0, 7).Select(i => $"PreviousRun{i}"))
                .Select(c => Time(cell(c))).OfType<DateTime>();
            foreach (var run in runs)
                yield return Artefact(run, "Prefetch", "Execution", "", "", $"mstsc.exe ran; run count {cell("RunCount")}");
        }
    }

    private static IEnumerable<RemoteAccessEvent> ReadAmcache(string path, CancellationToken cancellationToken)
    {
        foreach (var cell in Rows(path, cancellationToken))
        {
            var file = cell("FullPath");
            if (!Path.GetFileName(file.Replace('\\', '/')).Equals("mstsc.exe", StringComparison.OrdinalIgnoreCase)
                && !cell("Name").Equals("mstsc.exe", StringComparison.OrdinalIgnoreCase)) continue;
            yield return Artefact(Time(cell("FileKeyLastWriteTimestamp")), "Amcache", "Execution", "", "",
                                  "mstsc.exe in Amcache (key last written); " + file);
        }
    }

    private static IEnumerable<RemoteAccessEvent> ReadJumpList(string path, CancellationToken cancellationToken)
    {
        foreach (var cell in Rows(path, cancellationToken))
        {
            if (!cell("AppId").Equals(MstscAppId, StringComparison.OrdinalIgnoreCase)) continue;
            var arguments = cell("Arguments");
            var match = MstscTarget.Match(arguments);
            var server = match.Success ? match.Groups[1].Value : cell("Path");
            if (server.Length == 0) continue;
            var user = UserFromPath(cell("SourceFile"));
            yield return Artefact(Time(cell("LastModified")), "Jump list", "Recent", user, server,
                                  "Remote Desktop Connection jump list" + (arguments.Length > 0 ? "; " + arguments : ""));
        }
    }

    private static RemoteAccessEvent Artefact(DateTime? time, string source, string kind, string user, string server, string detail)
    {
        var address = CleanAddress(server);
        var name = address.Length > 0 ? "" : server.Trim();
        // An .rdp file or a "server:port" target: the name is the part a host would answer to.
        if (name.EndsWith(".rdp", StringComparison.OrdinalIgnoreCase)) name = Path.GetFileNameWithoutExtension(name.Replace('\\', '/'));
        if (name.Contains(':') && !name.Contains('\\')) name = name[..name.IndexOf(':')];
        return new RemoteAccessEvent(time, RemoteAccessEvent.Outbound, source, kind, user, address, name, "", "", "", detail);
    }

    private static string UserFromFileName(string path, string suffix)
    {
        var file = Path.GetFileNameWithoutExtension(path);
        var at = file.IndexOf(suffix, StringComparison.OrdinalIgnoreCase);
        return at > 0 ? file[..at] : "";
    }

    private static string UserFromPath(string path)
    {
        var parts = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        var users = Array.FindIndex(parts, p => p.Equals("Users", StringComparison.OrdinalIgnoreCase));
        return users >= 0 && users + 1 < parts.Length ? parts[users + 1] : "";
    }

    // --- sources file -----------------------------------------------------------------------------

    public sealed record SourceRow(
        string Log, string Status, int Events, DateTime? First, DateTime? Last, IReadOnlyList<DateTime> Cleared, string Input);

    private static void WriteSources(string path, IEnumerable<SourceRow> sources)
    {
        var temp = path + ".tmp";
        using (var csv = new StreamWriter(temp, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            CsvFile.WriteRow(csv, SourceColumns);
            foreach (var s in sources)
                CsvFile.WriteRow(csv, s.Log, s.Status, s.Events.ToString(CultureInfo.InvariantCulture),
                                 IpHistoryRecord.Format(s.First), IpHistoryRecord.Format(s.Last),
                                 string.Join("; ", s.Cleared.Order().Select(t => IpHistoryRecord.Format(t))), s.Input);
        }
        File.Move(temp, path, overwrite: true);
    }

    public static List<SourceRow> ReadSources(string path)
    {
        var rows = new List<SourceRow>();
        foreach (var cell in Rows(path, CancellationToken.None))
        {
            if (cell("Log").Length == 0) continue;
            rows.Add(new SourceRow(cell("Log"), cell("Status"),
                int.TryParse(cell("Events"), NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : 0,
                IpHistoryRecord.ParseTime(cell("FirstEventUtc")), IpHistoryRecord.ParseTime(cell("LastEventUtc")),
                cell("ClearedUtc").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(IpHistoryRecord.ParseTime).OfType<DateTime>().ToList(),
                cell("Input")));
        }
        return rows;
    }

    /// <summary>Both outputs exist and are newer than every input, so a rebuild would write the same.</summary>
    private static bool UpToDate(string outFile, string sourcesFile, IReadOnlyList<string> inputs)
    {
        if (!File.Exists(sourcesFile) || !File.Exists(outFile)) return false;
        var built = File.GetLastWriteTimeUtc(sourcesFile);
        if (File.GetLastWriteTimeUtc(outFile) < built) built = File.GetLastWriteTimeUtc(outFile);
        return inputs.All(i => File.GetLastWriteTimeUtc(i) <= built);
    }
}

/// <summary>One host's remote access file, loaded, with what the trace needs to know about the host.</summary>
public sealed record RemoteAccessHost(
    string Collection, string CollectionDirectory, string HostName, IReadOnlyList<string> FullNames,
    IReadOnlyList<string> Addresses, IReadOnlyList<RemoteAccessEvent> Events,
    IReadOnlyList<RemoteAccess.SourceRow> Coverage, DateTime? BuiltUtc, string? Problem)
{
    public RemoteAccess.SourceRow? Log(string name) =>
        Coverage.FirstOrDefault(c => c.Log == name && c.Status == "used");

    /// <summary>The host answers to this name: HOST01, host01.corp.example, or the collection's name.</summary>
    public bool IsNamed(string name)
    {
        var shortName = name.Trim().Split('.')[0].ToUpperInvariant();
        if (shortName.Length == 0) return false;
        return shortName == HostName
               || FullNames.Any(f => f.Split('.')[0].Equals(shortName, StringComparison.OrdinalIgnoreCase))
               || Collection.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
