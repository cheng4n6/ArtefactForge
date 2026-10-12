using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// An RDP session on one host, built by joining the events that describe it: the 4624 logon, the
/// 1149 authentication, the LocalSessionManager logon or reconnect and the RdpCoreTS connection,
/// all from one address within a couple of minutes.
/// </summary>
public sealed record RdpSession(
    string Collection, string Host, DateTime StartUtc, DateTime? EndUtc, string Kind, string Account,
    string SourceIp, string ClientName, IReadOnlyList<string> Evidence)
{
    public string EvidenceText => string.Join("; ", Evidence);
    public string Start => IpHistoryRecord.Format(StartUtc);
    public string End => IpHistoryRecord.Format(EndUtc);
}

/// <summary>How far to look. Defaults suit most cases; the analyst can widen either.</summary>
public sealed record RdpTraceOptions
{
    /// <summary>How far back from a connection to look for the session it came from.</summary>
    public TimeSpan Lookback { get; init; } = TimeSpan.FromHours(12);

    /// <summary>Two hosts' events within this of each other are one connection, whatever the clocks say.</summary>
    public TimeSpan MatchWindow { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Beyond the match window but within this, a client event is shown as a possible clock difference.</summary>
    public TimeSpan SkewLimit { get; init; } = TimeSpan.FromHours(2);
}

/// <summary>One connection in a trace: from a source address to a host in the case.</summary>
public sealed record RdpHop
{
    public required int Number { get; init; }
    public required string Result { get; init; }
    public required string ToHost { get; init; }
    public required DateTime TimeUtc { get; init; }
    public required string Account { get; init; }
    public required string SourceIp { get; init; }
    public string ClientName { get; init; } = "";
    public string FromHost { get; init; } = "";
    public string MappedBy { get; init; } = "";
    public string ReceivingEvidence { get; init; } = "";
    public string SendingEvidence { get; init; } = "";
    public string ClockOffset { get; init; } = "";
    public IReadOnlyList<string> Flags { get; init; } = [];
    public string NextStep { get; init; } = "";
}

public sealed record RdpTraceResult(
    RdpSession Start, IReadOnlyList<RdpHop> Hops, string Summary, string? EndAddress,
    IReadOnlyList<string> Accounts, IReadOnlyList<string> HostsToCollect, IReadOnlyList<string> HostsUsed);

/// <summary>A trace saved earlier, and whether what it read has changed since.</summary>
public sealed record SavedRdpTrace(string Path, DateTime TracedUtc, string StartHost, string Summary, string? Stale);

/// <summary>
/// Follows an RDP logon back host by host. From a session on a host it maps the source address to
/// a host in the case, confirms the outbound connection there, then finds the inbound session on
/// that host the connection came from, until the address is outside the case.
///
/// Each hop is one of:
///   Confirmed     the source host has a client event for this connection
///   Inferred      the address maps to the source host, but nothing there records connecting
///   Collect next  the source is an internal host that is not in the case
///   End of chain  an external or loopback address, or no source address at all
///
/// It flags rather than guesses: DHCP reuse, a client name that disagrees with the address (VPN,
/// NAT or a jump host), loopback, log gaps and clearing, clock differences, more than one
/// candidate session and a change of account. Reads only the hosts' remote access files and the
/// case IP history.
/// </summary>
public static class RdpTrace
{
    public const string Confirmed = "Confirmed";
    public const string Inferred = "Inferred";
    public const string CollectNext = "Collect next";
    public const string EndOfChain = "End of chain";

    public static readonly string[] Columns =
    [
        "Hop", "Result", "ToHost", "TimeUtc", "Account", "SourceIp", "ClientName", "FromHost", "MappedBy",
        "ReceivingEvidence", "SendingEvidence", "ClockOffset", "Flags", "NextStep"
    ];

    private const string FilePrefix = "RdpTrace_";
    private static readonly TimeSpan JoinWindow = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    // --- sessions ---------------------------------------------------------------------------------

    /// <summary>The Windows hosts in a case, each with its remote access file loaded (and built if needed).</summary>
    public static List<RemoteAccessHost> LoadHosts(string caseDirectory, CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(caseDirectory)) return [];
        return Directory.EnumerateDirectories(caseDirectory)
            .Where(d => !Path.GetFileName(d).StartsWith('_'))
            .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
            .Select(d => RemoteAccess.Load(d, cancellationToken))
            .Where(h => h.Events.Count > 0 || h.Coverage.Count > 0)
            .ToList();
    }

    /// <summary>
    /// The RDP sessions on a host (or every host, with no host given) that started between
    /// <paramref name="fromUtc"/> and <paramref name="toUtc"/>, newest first. The address and
    /// account filters match exactly, ignoring case and the account's domain.
    /// </summary>
    public static List<RdpSession> FindSessions(
        IEnumerable<RemoteAccessHost> hosts, string? host = null, DateTime? fromUtc = null, DateTime? toUtc = null,
        string? sourceIp = null, string? account = null)
    {
        var ip = string.IsNullOrWhiteSpace(sourceIp) ? null : IpHistoryRecord.Normalise(sourceIp);
        var user = string.IsNullOrWhiteSpace(account) ? null : RemoteAccessEvent.ShortUser(account);
        return hosts.Where(h => string.IsNullOrWhiteSpace(host) || h.IsNamed(host))
            .SelectMany(Sessions)
            .Where(s => (fromUtc is null || s.StartUtc >= fromUtc) && (toUtc is null || s.StartUtc <= toUtc))
            .Where(s => ip is null || s.SourceIp == ip)
            .Where(s => user is null || RemoteAccessEvent.ShortUser(s.Account) == user)
            .OrderByDescending(s => s.StartUtc)
            .ToList();
    }

    /// <summary>Every RDP session on one host.</summary>
    public static List<RdpSession> Sessions(RemoteAccessHost host)
    {
        var inbound = host.Events.Where(e => e.Direction == RemoteAccessEvent.Inbound && e.TimeUtc is not null)
                                 .OrderBy(e => e.TimeUtc).ToList();
        var anchors = inbound.Where(e => e.Kind is "Logon" or "Reconnect" or "Authenticated").ToList();
        var ends = inbound.Where(e => e.Kind is "Disconnect" or "Logoff").ToList();
        var accepts = inbound.Where(e => e.Kind == "TcpAccepted").ToList();

        var groups = new List<List<RemoteAccessEvent>>();
        foreach (var e in anchors)
        {
            var group = groups.LastOrDefault(g => e.TimeUtc - g[0].TimeUtc <= JoinWindow && SameConnection(g, e));
            if (group is null) groups.Add([e]);
            else group.Add(e);
        }

        var sessions = new List<RdpSession>();
        foreach (var g in groups)
        {
            var start = g.Min(e => e.TimeUtc)!.Value;
            var logon = g.FirstOrDefault(e => e.Source == "Security 4624")
                        ?? g.FirstOrDefault(e => e.Source == "Security 4778");
            var account = logon?.Account is { Length: > 0 } a ? a
                : g.Select(e => e.Account).FirstOrDefault(x => x.Length > 0) ?? "";
            var ip = g.Select(e => e.Address).FirstOrDefault(x => x.Length > 0) ?? "";
            var client = g.Select(e => e.RemoteName).FirstOrDefault(x => x.Length > 0) ?? "";

            var evidence = g.Select(e => e.Source).Distinct().ToList();
            var accepted = accepts.Where(e => e.Address == ip && ip.Length > 0
                                              && e.TimeUtc >= start - JoinWindow && e.TimeUtc <= start + JoinWindow).ToList();
            if (accepted.Count > 0) evidence.Add(accepted[0].Source);

            var kind = g.Any(e => e.Source == "Security 4624" || (e.Source == "LSM 21")) ? "Logon"
                     : g.Any(e => e.Kind == "Reconnect") ? "Reconnect"
                     : "Authenticated only";

            var user = RemoteAccessEvent.ShortUser(account);
            var logonIds = g.Select(e => e.LogonId).Where(x => x.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var sessionIds = g.Select(e => e.SessionId).Where(x => x.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var end = ends.FirstOrDefault(e => e.TimeUtc > start
                                               && (logonIds.Contains(e.LogonId) || sessionIds.Contains(e.SessionId)
                                                   || (e.LogonId.Length == 0 && e.SessionId.Length == 0 && e.User == user)))
                          ?.TimeUtc;

            sessions.Add(new RdpSession(host.Collection, host.HostName, start, end, kind, account, ip, client, evidence));
        }
        return sessions;
    }

    private static bool SameConnection(List<RemoteAccessEvent> group, RemoteAccessEvent e)
    {
        var ip = group.Select(g => g.Address).FirstOrDefault(a => a.Length > 0);
        if (ip is not null && e.Address.Length > 0) return ip == e.Address;
        var user = group.Select(g => g.User).FirstOrDefault(u => u.Length > 0);
        return user is not null && e.User.Length > 0 && user == e.User;
    }

    // --- trace ------------------------------------------------------------------------------------

    /// <summary>Traces a session back from the case on disk.</summary>
    public static RdpTraceResult Trace(string caseDirectory, RdpSession start, RdpTraceOptions? options = null,
                                       CancellationToken cancellationToken = default) =>
        Trace(LoadHosts(caseDirectory, cancellationToken), LoadIpHistory(caseDirectory), start, options);

    public static List<IpHistoryRecord> LoadIpHistory(string caseDirectory)
    {
        var path = Path.Combine(caseDirectory, IpHistory.FileName);
        return File.Exists(path) ? IpHistoryRecord.Read(path) : [];
    }

    public static RdpTraceResult Trace(IReadOnlyList<RemoteAccessHost> hosts, IReadOnlyList<IpHistoryRecord> ipHistory,
                                       RdpSession start, RdpTraceOptions? options = null)
    {
        options ??= new RdpTraceOptions();
        var hops = new List<RdpHop>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var toCollect = new List<string>();
        string? endAddress = null;
        var ending = "";

        var session = start;
        string? previousAccount = null, previousHost = null;
        while (true)
        {
            var receiving = hosts.First(h => h.Collection.Equals(session.Collection, StringComparison.OrdinalIgnoreCase));
            visited.Add(receiving.Collection);
            used.Add(receiving.Collection);

            var flags = new List<string>();
            if (previousAccount is not null && !SameUser(previousAccount, session.Account))
                flags.Add($"account changes: {Show(session.Account)} logs on to {receiving.HostName}, {previousAccount} to {previousHost}");
            previousAccount = session.Account;
            previousHost = receiving.HostName;

            var hop = new RdpHop
            {
                Number = hops.Count + 1, Result = "", ToHost = receiving.HostName, TimeUtc = session.StartUtc,
                Account = session.Account, SourceIp = session.SourceIp, ClientName = session.ClientName,
                ReceivingEvidence = session.EvidenceText
            };

            // The end of the chain is decided by the address before any mapping.
            if (session.SourceIp.Length == 0)
            {
                ending = session.ClientName.Length > 0
                    ? $"no source address recorded (client name {session.ClientName})"
                    : "no source address recorded";
                var byName = session.ClientName.Length > 0 ? hosts.FirstOrDefault(h => h.IsNamed(session.ClientName)) : null;
                if (byName is null)
                {
                    hops.Add(hop with { Result = EndOfChain, Flags = flags, NextStep = "No address in the logon events: check the client name against the network's DHCP and DNS records" });
                    break;
                }
            }

            if (IPAddress.TryParse(session.SourceIp, out var address))
            {
                if (IPAddress.IsLoopback(address) || (address.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(address.MapToIPv4())))
                {
                    flags.Add("loopback source address: usually tunnelled RDP (an SSH or other port forward on this host)");
                    hops.Add(hop with { Result = EndOfChain, Flags = flags,
                        NextStep = $"Look on {receiving.HostName} for tunnelling tools and port forwards (plink, ssh, chisel, ngrok, netsh portproxy) around this time" });
                    ending = $"loopback on {receiving.HostName} (tunnelled RDP)";
                    endAddress = session.SourceIp;
                    break;
                }
                if (!IsInternal(address))
                {
                    flags.Add("external address");
                    hops.Add(hop with { Result = EndOfChain, Flags = flags,
                        NextStep = "External address: add it to the IOC list and check firewall, VPN and proxy logs for it" });
                    ending = $"external IP {session.SourceIp}";
                    endAddress = session.SourceIp;
                    break;
                }
                if (IsCarrierNat(address))
                    flags.Add("carrier-grade NAT range (100.64.0.0/10): often a VPN or overlay network, so the address may be a gateway");
            }

            // Which host had the address. Each source is a candidate; disagreements are flags.
            var candidates = MapAddress(hosts, ipHistory, session, flags);
            var inCase = candidates.Where(c => c.Host is not null).ToList();

            (Candidate Candidate, Connection? Connection)? chosen = null;
            foreach (var c in inCase)
            {
                var connection = FindConnection(c.Host!, receiving, session, options);
                if (connection is { Confirmed: true }) { chosen = (c, connection); break; }
                chosen ??= (c, connection);
            }

            if (chosen is null)
            {
                var name = candidates.Select(c => c.Name).FirstOrDefault(n => n.Length > 0);
                hops.Add(hop with
                {
                    Result = CollectNext, Flags = flags,
                    FromHost = name ?? "",
                    MappedBy = string.Join("; ", candidates.Select(c => c.By)),
                    NextStep = name is null
                        ? $"Find which machine had {session.SourceIp} at {IpHistoryRecord.Format(session.StartUtc)} UTC (DHCP, firewall or VPN logs) and collect it"
                        : $"Collect {name} and add it to the case, then run the trace again"
                });
                if (name is not null) toCollect.Add(name);
                ending = name is null ? $"{session.SourceIp}, an internal address not mapped to a host" : $"{name}, not in the case";
                endAddress = session.SourceIp;
                break;
            }

            var (candidate, found) = chosen.Value;
            var sender = candidate.Host!;
            used.Add(sender.Collection);
            AddLogFlags(sender, session.StartUtc, options, flags);

            if (found?.ClockOffset is { } offset && offset.Duration() > options.MatchWindow)
                flags.Add($"possible clock difference: the nearest client event on {sender.HostName} is {RemoteAccessEvent.FormatOffset(offset)} from this logon");
            else if (found?.ClockOffset is { } small && small.Duration() > TimeSpan.FromMinutes(1))
                flags.Add($"clocks differ by about {RemoteAccessEvent.FormatOffset(small)} ({receiving.HostName} minus {sender.HostName})");

            if (visited.Contains(sender.Collection))
            {
                flags.Add($"loop: {sender.HostName} is already in this trace");
                hops.Add(hop with
                {
                    Result = found is { Confirmed: true } ? Confirmed : Inferred, Flags = flags, FromHost = sender.HostName,
                    MappedBy = candidate.By, SendingEvidence = found?.Evidence ?? "",
                    ClockOffset = found?.ClockOffset is { } o ? RemoteAccessEvent.FormatOffset(o) : "",
                    NextStep = "The chain loops back on itself: check the times and addresses by hand"
                });
                ending = $"a loop back to {sender.HostName}";
                break;
            }

            // The session on the sender that this connection came from.
            var earlier = Sessions(sender)
                .Where(s => s.StartUtc <= session.StartUtc + options.MatchWindow
                            && s.StartUtc >= session.StartUtc - options.Lookback
                            && (s.EndUtc is null || s.EndUtc >= session.StartUtc - options.MatchWindow))
                .OrderByDescending(s => s.StartUtc)
                .ToList();
            var others = earlier.Skip(1).Where(s => s.SourceIp != earlier[0].SourceIp || !SameUser(s.Account, earlier[0].Account)).ToList();
            if (others.Count > 0)
                flags.Add($"{others.Count} other session(s) on {sender.HostName} in the window (branch): "
                          + string.Join(", ", others.Take(5).Select(s => $"{s.Account} from {Show(s.SourceIp)} at {s.Start}")));

            string nextStep;
            if (earlier.Count == 0)
            {
                var security = sender.Log(RemoteAccess.SecurityLog);
                var gap = security?.First is not { } first || first > session.StartUtc - options.Lookback;
                nextStep = gap
                    ? $"No inbound RDP to {sender.HostName} found, but its logs do not cover the {options.Lookback.TotalHours:N0} h before: look for other access to it, or a longer log"
                    : $"No inbound RDP to {sender.HostName} in the {options.Lookback.TotalHours:N0} h before: the session started there (local logon, other remote access such as SMB, WinRM or a remote tool)";
                ending = $"{sender.HostName} (no earlier inbound RDP found)";
            }
            else nextStep = "";

            hops.Add(hop with
            {
                Result = found is { Confirmed: true } ? Confirmed : Inferred, Flags = flags, FromHost = sender.HostName,
                MappedBy = candidate.By, SendingEvidence = found?.Evidence ?? "",
                ClockOffset = found?.ClockOffset is { } c2 ? RemoteAccessEvent.FormatOffset(c2) : "",
                NextStep = nextStep
            });
            if (earlier.Count == 0) break;
            session = earlier[0];
        }

        var accounts = hops.Select(h => h.Account).Where(a => a.Length > 0)
                           .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var summary = $"{hops.Count} hop{(hops.Count == 1 ? "" : "s")}, ends at {ending}"
                      + (toCollect.Count > 0 ? $", {toCollect.Count} host{(toCollect.Count == 1 ? "" : "s")} to collect" : "")
                      + (hops.Any(h => h.Flags.Count > 0) ? $", {hops.Sum(h => h.Flags.Count)} flag(s) to check" : "")
                      + ".";
        return new RdpTraceResult(start, hops, summary, endAddress, accounts, toCollect, used.Order(StringComparer.OrdinalIgnoreCase).ToList());
    }

    private sealed record Candidate(string Name, RemoteAccessHost? Host, string By);

    private static List<Candidate> MapAddress(IReadOnlyList<RemoteAccessHost> hosts, IReadOnlyList<IpHistoryRecord> ipHistory,
                                              RdpSession session, List<string> flags)
    {
        var candidates = new List<Candidate>();
        void Add(string name, string by)
        {
            var shortName = name.Split('.')[0].ToUpperInvariant();
            if (shortName.Length == 0) return;
            var existing = candidates.FindIndex(c => c.Name == shortName);
            if (existing >= 0)
            {
                candidates[existing] = candidates[existing] with { By = candidates[existing].By + "; " + by };
                return;
            }
            candidates.Add(new Candidate(shortName, hosts.FirstOrDefault(h => h.IsNamed(shortName)), by));
        }

        if (session.SourceIp.Length > 0)
        {
            var lookup = IpHistoryLookup.Find(ipHistory.Where(r => r.Source != "SystemInfo"), session.SourceIp, session.StartUtc);
            if (lookup.Best is { HostName.Length: > 0 } best)
            {
                Add(best.HostName, $"IP history: {best.Source} {IpHistoryRecord.Format(best.FirstSeenUtc)} to {IpHistoryRecord.Format(best.LastSeenUtc)}");
                if (best.FirstSeenUtc > session.StartUtc || best.LastSeenUtc < session.StartUtc)
                    flags.Add($"the IP history does not cover this time for {session.SourceIp}: nearest record names {best.ShortHostName}");
                foreach (var conflict in lookup.Conflicts)
                    flags.Add($"DHCP reuse: {session.SourceIp} also belonged to {conflict.ShortHostName} ({conflict.Source}) at this time");
            }
            foreach (var host in hosts.Where(h => h.Addresses.Contains(session.SourceIp)))
                Add(host.HostName, "SystemInfo address (at collection time)");
        }
        if (session.ClientName.Length > 0) Add(session.ClientName, "client name in the logon events");

        if (candidates.Count > 1)
            flags.Add("the address and client name point to different machines (" + string.Join(", ", candidates.Select(c => c.Name))
                      + "): a VPN gateway, NAT or jump host may sit between them");
        return candidates;
    }

    private sealed record Connection(bool Confirmed, string Evidence, TimeSpan? ClockOffset);

    /// <summary>What the sending host records about connecting to the receiving host around this time.</summary>
    private static Connection? FindConnection(RemoteAccessHost sender, RemoteAccessHost receiving, RdpSession session,
                                              RdpTraceOptions options)
    {
        bool Targets(RemoteAccessEvent e) =>
            (e.RemoteName.Length > 0 && receiving.IsNamed(e.RemoteName))
            || (e.Address.Length > 0 && receiving.Addresses.Contains(e.Address));

        var outbound = sender.Events.Where(e => e.Direction == RemoteAccessEvent.Outbound).ToList();
        var evidence = new List<string>();

        var client = outbound.Where(e => e.Source.StartsWith(RemoteAccess.ClientLog, StringComparison.Ordinal)
                                         && e.TimeUtc is not null && Targets(e))
                             .Select(e => (Event: e, Offset: session.StartUtc - e.TimeUtc!.Value))
                             .Where(x => x.Offset.Duration() <= options.SkewLimit)
                             .OrderBy(x => x.Offset.Duration())
                             .FirstOrDefault();
        var confirmed = client.Event is not null && client.Offset.Duration() <= options.MatchWindow;
        if (client.Event is not null)
            evidence.Add($"{client.Event.Source} to {Show(client.Event.RemoteName.Length > 0 ? client.Event.RemoteName : client.Event.Address)} at {IpHistoryRecord.Format(client.Event.TimeUtc)}");

        foreach (var recent in outbound.Where(e => e.Kind == "Recent" && Targets(e))
                                       .GroupBy(e => (e.Source, e.Account)).Select(g => g.First()))
            evidence.Add($"{recent.Source} ({(recent.Account.Length > 0 ? recent.Account : "user unknown")}) names {Show(recent.RemoteName.Length > 0 ? recent.RemoteName : recent.Address)}"
                         + (recent.TimeUtc is { } t ? $", last written {IpHistoryRecord.Format(t)}" : ""));

        var runs = outbound.Where(e => e.Kind == "Execution" && e.TimeUtc is not null
                                       && (session.StartUtc - e.TimeUtc!.Value).Duration() <= options.SkewLimit)
                           .GroupBy(e => e.Source).Select(g => g.OrderBy(e => (session.StartUtc - e.TimeUtc!.Value).Duration()).First());
        foreach (var run in runs) evidence.Add($"mstsc.exe ({run.Source}) at {IpHistoryRecord.Format(run.TimeUtc)}");

        if (evidence.Count == 0) return null;
        return new Connection(confirmed, string.Join("; ", evidence), client.Event is null ? null : client.Offset);
    }

    private static void AddLogFlags(RemoteAccessHost host, DateTime at, RdpTraceOptions options, List<string> flags)
    {
        if (host.Problem is { } problem) flags.Add($"{host.HostName}: {problem}");
        if (host.Coverage.Any(c => c.Log == "Event logs"))
        {
            flags.Add($"{host.HostName} has no EvtxECmd output, so neither its client events nor its inbound logons can be read");
            return;
        }
        var client = host.Log(RemoteAccess.ClientLog);
        if (client is null) flags.Add($"{host.HostName}: no RDPClient log events, so the outbound connection cannot be confirmed from the event log");
        else if (client.First > at) flags.Add($"{host.HostName}: RDPClient log starts at {IpHistoryRecord.Format(client.First)}, after this connection");

        var security = host.Log(RemoteAccess.SecurityLog);
        if (security is null) flags.Add($"{host.HostName}: no Security log events");
        else if (security.First > at - options.Lookback)
            flags.Add($"{host.HostName}: Security log starts at {IpHistoryRecord.Format(security.First)}, so logons before that are not visible");

        foreach (var c in host.Coverage.Where(c => c.Cleared.Count > 0))
            flags.Add($"{host.HostName}: {c.Log} log cleared at {string.Join(", ", c.Cleared.Select(t => IpHistoryRecord.Format(t)))}");
    }

    /// <summary>Private, link-local and CGNAT ranges: an address a host in the case might hold.</summary>
    public static bool IsInternal(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] == 10
                   || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                   || (b[0] == 192 && b[1] == 168)
                   || (b[0] == 169 && b[1] == 254)
                   || IsCarrierNat(address);
        }
        return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal;
    }

    private static bool IsCarrierNat(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = address.GetAddressBytes();
        return b[0] == 100 && b[1] >= 64 && b[1] <= 127;
    }

    private static bool SameUser(string a, string b) => RemoteAccessEvent.ShortUser(a) == RemoteAccessEvent.ShortUser(b);

    private static string Show(string value) => value.Length > 0 ? value : "-";

    // --- saved traces -----------------------------------------------------------------------------

    private sealed record TraceInputs(
        DateTime TracedUtc, string StartHost, string StartTimeUtc, string Account, string SourceIp, string Summary,
        Dictionary<string, DateTime?> Hosts, List<string> CaseHosts);

    /// <summary>
    /// Saves the trace as RdpTrace_&lt;host&gt;_&lt;time&gt;.csv in the case folder, with a .json
    /// beside it recording what it read. Never overwrites: a second trace of the same session is
    /// saved alongside as _2, _3.
    /// </summary>
    public static string Save(string caseDirectory, RdpTraceResult trace, IReadOnlyList<RemoteAccessHost> hosts)
    {
        Directory.CreateDirectory(caseDirectory);
        var stem = $"{FilePrefix}{SafeName(trace.Start.Host)}_{trace.Start.StartUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}";
        var path = Path.Combine(caseDirectory, stem + ".csv");
        for (var n = 2; File.Exists(path) || File.Exists(Path.ChangeExtension(path, ".json")); n++)
            path = Path.Combine(caseDirectory, $"{stem}_{n}.csv");

        using (var csv = new StreamWriter(path, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            CsvFile.WriteRow(csv, Columns);
            foreach (var h in trace.Hops)
                CsvFile.WriteRow(csv, h.Number.ToString(CultureInfo.InvariantCulture), h.Result, h.ToHost,
                                 IpHistoryRecord.Format(h.TimeUtc), h.Account, h.SourceIp, h.ClientName, h.FromHost,
                                 h.MappedBy, h.ReceivingEvidence, h.SendingEvidence, h.ClockOffset,
                                 string.Join("; ", h.Flags), h.NextStep);
        }

        var inputs = new TraceInputs(
            DateTime.UtcNow, trace.Start.Host, trace.Start.Start, trace.Start.Account, trace.Start.SourceIp, trace.Summary,
            trace.HostsUsed.ToDictionary(c => c, c => hosts.FirstOrDefault(h => h.Collection == c)?.BuiltUtc),
            hosts.Select(h => h.Collection).ToList());
        File.WriteAllText(Path.ChangeExtension(path, ".json"), JsonSerializer.Serialize(inputs, Json));
        return path;
    }

    /// <summary>
    /// The case's saved traces, newest first, each marked when a host it read has been
    /// reprocessed since, or a host has been added to the case, so it can be run again.
    /// </summary>
    public static List<SavedRdpTrace> Saved(string caseDirectory)
    {
        var saved = new List<SavedRdpTrace>();
        if (!Directory.Exists(caseDirectory)) return saved;
        var current = Directory.EnumerateDirectories(caseDirectory)
            .Where(d => !Path.GetFileName(d).StartsWith('_'))
            .Where(d => File.Exists(Path.Combine(d, RemoteAccess.Folder, RemoteAccess.FileName)))
            .ToDictionary(d => Path.GetFileName(d)!, d => File.GetLastWriteTimeUtc(Path.Combine(d, RemoteAccess.Folder, RemoteAccess.FileName)),
                          StringComparer.OrdinalIgnoreCase);

        foreach (var json in Directory.EnumerateFiles(caseDirectory, FilePrefix + "*.json"))
        {
            var csv = Path.ChangeExtension(json, ".csv");
            if (!File.Exists(csv)) continue;
            TraceInputs? inputs;
            try { inputs = JsonSerializer.Deserialize<TraceInputs>(File.ReadAllText(json)); }
            catch (Exception ex) when (ex is IOException or JsonException) { inputs = null; }
            if (inputs is null) continue;

            var changed = inputs.Hosts.Where(h => !current.TryGetValue(h.Key, out var built) || built > h.Value)
                                      .Select(h => h.Key).ToList();
            var added = current.Keys.Except(inputs.CaseHosts, StringComparer.OrdinalIgnoreCase).ToList();
            string? stale = null;
            if (changed.Count > 0) stale = "reprocessed since: " + string.Join(", ", changed);
            if (added.Count > 0) stale = (stale is null ? "" : stale + "; ") + "added since: " + string.Join(", ", added);
            saved.Add(new SavedRdpTrace(csv, inputs.TracedUtc, inputs.StartHost, inputs.Summary, stale));
        }
        return saved.OrderByDescending(s => s.TracedUtc).ToList();
    }

    private static string SafeName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var safe = new string(name.Select(c => invalid.Contains(c) || c == '\\' || c == '/' ? '_' : c).ToArray());
        return safe.Length > 0 ? safe : "host";
    }
}
