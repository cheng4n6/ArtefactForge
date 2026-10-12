using System.Globalization;
using System.Text;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// One row of a host's RemoteAccess\RemoteAccess.csv: an event or artefact that says this host
/// received, or made, a Remote Desktop connection. Times are UTC.
///
///   TimeUtc     when it happened, yyyy-MM-dd HH:mm:ss; empty for a registry value with no time
///   Direction   Inbound (to this host) or Outbound (from this host)
///   Source      where it came from: "Security 4624", "RCM 1149", "LSM 21", "RdpCoreTS 131",
///               "RDPClient 1024", "Registry MRU", "Prefetch", "Amcache", "Jump list"
///   Kind        Logon, Reconnect, Disconnect, Logoff, Authenticated, TcpAccepted, Connect,
///               Recent (an MRU or jump list entry) or Execution (mstsc.exe ran)
///   Account     DOMAIN\user as the event gives it, or the profile the artefact came from
///   Address     the other end's IP address, as recorded
///   RemoteName  the other end's name: client name on inbound, server name on outbound
///   LogonId     Security log logon ID, to tie a logon to its disconnects
///   SessionId   Terminal Services session ID
///   Computer    the Computer field of the event (this host's name as it wrote the event)
///   Detail      anything else worth reading, such as the logon type
/// </summary>
public sealed record RemoteAccessEvent(
    DateTime? TimeUtc, string Direction, string Source, string Kind, string Account, string Address,
    string RemoteName, string LogonId, string SessionId, string Computer, string Detail)
{
    public const string Inbound = "Inbound";
    public const string Outbound = "Outbound";

    public static readonly string[] Columns =
    [
        "TimeUtc", "Direction", "Source", "Kind", "Account", "Address", "RemoteName", "LogonId",
        "SessionId", "Computer", "Detail"
    ];

    public string[] ToCells() =>
    [
        IpHistoryRecord.Format(TimeUtc), Direction, Source, Kind, Account, Address, RemoteName,
        LogonId, SessionId, Computer, Detail
    ];

    /// <summary>The user name without domain or realm, upper case, for comparing accounts.</summary>
    public string User => ShortUser(Account);

    public static string ShortUser(string account)
    {
        var text = account.Trim();
        var slash = text.LastIndexOf('\\');
        if (slash >= 0) text = text[(slash + 1)..];
        var at = text.IndexOf('@');
        if (at >= 0) text = text[..at];
        return text.ToUpperInvariant();
    }

    public static List<RemoteAccessEvent> Read(string path)
    {
        var rows = new List<RemoteAccessEvent>();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return rows;
        var index = header.Select((name, i) => (name, i))
            .ToDictionary(p => p.name.Trim(), p => p.i, StringComparer.OrdinalIgnoreCase);

        while (reader.ReadRecord() is { } fields)
        {
            string Cell(string name) => index.TryGetValue(name, out var i) && i < fields.Count ? fields[i] : "";
            if (Cell("Direction").Length == 0) continue;
            rows.Add(new RemoteAccessEvent(
                IpHistoryRecord.ParseTime(Cell("TimeUtc")), Cell("Direction"), Cell("Source"), Cell("Kind"),
                Cell("Account"), Cell("Address"), Cell("RemoteName"), Cell("LogonId"), Cell("SessionId"),
                Cell("Computer"), Cell("Detail")));
        }
        return rows;
    }

    /// <summary>Writes the rows in time order, those with no time last.</summary>
    public static void Write(string path, IEnumerable<RemoteAccessEvent> rows)
    {
        var temp = path + ".tmp";
        using (var csv = new StreamWriter(temp, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            CsvFile.WriteRow(csv, Columns);
            foreach (var row in rows.Distinct()
                                    .OrderBy(r => r.TimeUtc ?? DateTime.MaxValue)
                                    .ThenBy(r => r.Source, StringComparer.Ordinal))
                CsvFile.WriteRow(csv, row.ToCells());
        }
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>+01:02:03 or -00:00:40; hours run past 24 rather than wrapping.</summary>
    internal static string FormatOffset(TimeSpan offset)
    {
        var d = offset.Duration();
        return (offset < TimeSpan.Zero ? "-" : "+")
               + string.Create(CultureInfo.InvariantCulture, $"{(int)d.TotalHours:00}:{d.Minutes:00}:{d.Seconds:00}");
    }
}
