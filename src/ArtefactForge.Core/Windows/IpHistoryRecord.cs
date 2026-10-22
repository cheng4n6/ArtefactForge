using System.Buffers;
using System.Globalization;
using System.Net;
using System.Text;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// One row of IpHistory.csv: an address seen with a host or account over a period, from one
/// source. The per-collection file and the case roll-up share these columns, and other features
/// (the RDP trace among them) read them by name, so the column list is a format promise: add new
/// columns at the end, never rename or reorder.
///
///   IpAddress     the address, IPv4 or IPv6, as .NET writes it (no ::ffff: prefix)
///   HostName      the machine, when the source names one: HOST01 from a HOST01$ computer
///                 account, or the name a DHCP lease or DNS record gave
///   Account       the Kerberos account name, without the realm (HOST01$, alice)
///   MacAddress    from DHCP only, as 00-50-56-9A-1B-2C
///   FirstSeenUtc  earliest event, yyyy-MM-dd HH:mm:ss UTC; empty when the source has no time
///   LastSeenUtc   latest event, same form
///   Source        Kerberos, DHCP, DHCPv6, DNS audit or SystemInfo
///   EventCount    events behind the row; empty for SystemInfo, which is a snapshot
///   Collection    the collection(s) the row came from, '; '-separated in the roll-up
/// </summary>
public sealed record IpHistoryRecord(
    string IpAddress, string HostName, string Account, string MacAddress,
    DateTime? FirstSeenUtc, DateTime? LastSeenUtc, string Source, int? EventCount, string Collection)
{
    public static readonly string[] Columns =
    [
        "IpAddress", "HostName", "Account", "MacAddress", "FirstSeenUtc", "LastSeenUtc", "Source",
        "EventCount", "Collection"
    ];

    public const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

    public string[] ToCells() =>
    [
        IpAddress, HostName, Account, MacAddress, Format(FirstSeenUtc), Format(LastSeenUtc), Source,
        EventCount?.ToString(CultureInfo.InvariantCulture) ?? "", Collection
    ];

    /// <summary>The machine name without its domain, for comparing HOST01 with host01.corp.example.</summary>
    public string ShortHostName => HostName.Split('.')[0].ToUpperInvariant();

    public static string Format(DateTime? time) =>
        time?.ToString(TimeFormat, CultureInfo.InvariantCulture) ?? "";

    public static DateTime? ParseTime(string text) =>
        DateTime.TryParseExact(text.Trim(), TimeFormat, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;

    /// <summary>Reads an IpHistory.csv written by <see cref="Write"/> (or by hand, as long as the header is there).</summary>
    public static List<IpHistoryRecord> Read(string path)
    {
        var rows = new List<IpHistoryRecord>();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return rows;
        var index = header.Select((name, i) => (name, i))
            .ToDictionary(p => p.name.Trim(), p => p.i, StringComparer.OrdinalIgnoreCase);

        while (reader.ReadRecord() is { } fields)
        {
            string Cell(string name) => index.TryGetValue(name, out var i) && i < fields.Count ? fields[i] : "";
            if (Cell("IpAddress").Length == 0) continue;
            rows.Add(new IpHistoryRecord(
                Cell("IpAddress"), Cell("HostName"), Cell("Account"), Cell("MacAddress"),
                ParseTime(Cell("FirstSeenUtc")), ParseTime(Cell("LastSeenUtc")), Cell("Source"),
                int.TryParse(Cell("EventCount"), NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : null,
                Cell("Collection")));
        }
        return rows;
    }

    /// <summary>Writes the rows in address order, then by first sighting.</summary>
    public static void Write(string path, IEnumerable<IpHistoryRecord> rows)
    {
        var temp = path + ".tmp";
        using (var csv = new StreamWriter(temp, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            CsvFile.WriteRow(csv, Columns);
            foreach (var row in Sort(rows)) CsvFile.WriteRow(csv, row.ToCells());
        }
        // Written beside and swapped in, so a reader never sees half a file and a failed write
        // leaves the previous one in place.
        File.Move(temp, path, overwrite: true);
    }

    public static IEnumerable<IpHistoryRecord> Sort(IEnumerable<IpHistoryRecord> rows) =>
        rows.OrderBy(r => AddressKey(r.IpAddress), StringComparer.Ordinal)
            .ThenBy(r => r.FirstSeenUtc ?? DateTime.MaxValue)
            .ThenBy(r => r.Source, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.HostName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Account, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The address as it should be compared: ::ffff:10.0.0.5 and 10.0.0.5 are one address, and an
    /// unparseable value is returned trimmed so it still groups with itself.
    /// </summary>
    public static string Normalise(string address)
    {
        var text = address.Trim();
        if (!IPAddress.TryParse(text, out var ip)) return text;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) ip.ScopeId = 0;
        return ip.ToString();
    }

    /// <summary>Sorts IPv4 before IPv6 and each numerically, so 10.0.0.9 comes before 10.0.0.10.</summary>
    private static string AddressKey(string address) =>
        IPAddress.TryParse(address, out var ip)
            ? (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "4" : "6")
              + Convert.ToHexString(ip.GetAddressBytes())
            : "9" + address;
}

/// <summary>Who had an address at a moment: the best match, and anything that disagrees with it.</summary>
public sealed record IpLookupResult(IpHistoryRecord? Best, IReadOnlyList<IpHistoryRecord> Conflicts);

/// <summary>"Who had this IP at this time", over the rows of an IpHistory.csv.</summary>
public static class IpHistoryLookup
{
    /// <summary>
    /// The best row for <paramref name="address"/> at <paramref name="whenUtc"/> (or, with no
    /// time, the most recent), plus the rows covering that moment that name a different host.
    ///
    /// A row whose first-to-last span covers the time beats one that does not; then the closer
    /// span; then the source: a DHCP lease names the machine the address was given to, a Kerberos
    /// computer account the machine that authenticated from it, a DNS record only what the zone
    /// said, and SystemInfo is a snapshot with no time at all. Rows that name only a user account
    /// are used when nothing names a host. A conflict usually means DHCP gave the address to two
    /// machines inside the span, so the analyst should narrow the time and look again.
    /// </summary>
    public static IpLookupResult Find(IEnumerable<IpHistoryRecord> rows, string address, DateTime? whenUtc)
    {
        var wanted = IpHistoryRecord.Normalise(address);
        var candidates = rows.Where(r => IpHistoryRecord.Normalise(r.IpAddress) == wanted
                                         && (r.HostName.Length > 0 || r.Account.Length > 0))
                             .ToList();
        if (candidates.Count == 0) return new IpLookupResult(null, []);

        var best = candidates
            .OrderBy(r => r.HostName.Length > 0 ? 0 : 1)
            .ThenBy(r => Distance(r, whenUtc))
            .ThenBy(r => SourceRank(r.Source))
            .ThenByDescending(r => r.LastSeenUtc ?? DateTime.MinValue)
            .ThenByDescending(r => r.EventCount ?? 0)
            .First();

        var conflicts = best.HostName.Length == 0
            ? []
            : candidates.Where(r => r.HostName.Length > 0
                                    && r.ShortHostName != best.ShortHostName
                                    && (whenUtc is null || Distance(r, whenUtc) == TimeSpan.Zero))
                        .ToList();
        return new IpLookupResult(best, conflicts);
    }

    private static TimeSpan Distance(IpHistoryRecord row, DateTime? when)
    {
        if (row.FirstSeenUtc is not { } first || row.LastSeenUtc is not { } last) return TimeSpan.MaxValue;
        if (when is not { } t) return TimeSpan.Zero;
        if (t < first) return first - t;
        if (t > last) return t - last;
        return TimeSpan.Zero;
    }

    private static int SourceRank(string source) => source switch
    {
        "DHCP" or "DHCPv6" => 0,
        "Kerberos" => 1,
        "DNS audit" => 2,
        _ => 3
    };
}

/// <summary>
/// Streams RFC 4180 records, including quoted cells that run over several lines. EvtxECmd output
/// runs to gigabytes, so nothing is read whole: text is scanned a buffer at a time, a run of
/// ordinary characters copied in one go, and a caller can skip the rest of a record it does not want.
/// </summary>
public sealed class CsvRecordReader : IDisposable
{
    private static readonly SearchValues<char> Unquoted = SearchValues.Create(",\"\r\n");

    private readonly StreamReader _reader;
    private readonly StringBuilder _cell = new();
    private readonly char[] _buffer = new char[1 << 16];
    private int _pos;
    private int _len;

    public CsvRecordReader(string path)
    {
        // Shared, so a file another program has open (Timeline Explorer, say) can still be read.
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                                    1 << 16, FileOptions.SequentialScan);
        _reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, 1 << 16);
    }

    /// <summary>The next record, or null at the end of the file.</summary>
    public List<string>? ReadRecord() => ReadRecord(int.MaxValue, null);

    /// <summary>
    /// The next record, or null at the end of the file. Once cells 0 to <paramref name="decideAfter"/>
    /// are read, <paramref name="wantRest"/> sees them; when it says no, the rest of the record is
    /// passed over without being copied and only those cells come back. EvtxECmd's Payload, the
    /// last and much the largest cell, is wanted for a few event IDs out of every log.
    /// </summary>
    public List<string>? ReadRecord(int decideAfter, Func<List<string>, bool>? wantRest)
    {
        if (!Fill()) return null;

        var fields = new List<string>();
        var quoted = false;
        _cell.Clear();
        while (Fill())
        {
            var span = _buffer.AsSpan(_pos, _len - _pos);
            if (quoted)
            {
                var at = span.IndexOf('"');
                if (at < 0) { _cell.Append(span); _pos = _len; continue; }
                _cell.Append(span[..at]);
                _pos += at + 1;
                if (Peek() == '"') { _cell.Append('"'); _pos++; }
                else quoted = false;
                continue;
            }

            var stop = span.IndexOfAny(Unquoted);
            if (stop < 0) { _cell.Append(span); _pos = _len; continue; }
            _cell.Append(span[..stop]);
            var ch = span[stop];
            _pos += stop + 1;
            if (ch == '"') quoted = true;
            else if (ch == '\n') break;
            else if (ch == ',')
            {
                fields.Add(_cell.ToString());
                _cell.Clear();
                if (fields.Count == decideAfter + 1 && wantRest is not null && !wantRest(fields))
                {
                    SkipRecord();
                    return fields;
                }
            }
            // '\r' outside quotes is dropped, as a line ending.
        }
        fields.Add(_cell.ToString());
        return fields;
    }

    /// <summary>Passes over the rest of a record, quoted line breaks included.</summary>
    private void SkipRecord()
    {
        var quoted = false;
        while (Fill())
        {
            var span = _buffer.AsSpan(_pos, _len - _pos);
            var at = quoted ? span.IndexOf('"') : span.IndexOfAny('"', '\n');
            if (at < 0) { _pos = _len; continue; }
            _pos += at + 1;
            if (span[at] == '\n') return;
            // An escaped quote is two in a row: leaving the cell and coming straight back in.
            quoted = !quoted;
        }
    }

    /// <summary>True when there is a character to read, refilling the buffer as needed.</summary>
    private bool Fill()
    {
        if (_pos < _len) return true;
        _len = _reader.Read(_buffer, 0, _buffer.Length);
        _pos = 0;
        return _len > 0;
    }

    private int Peek() => Fill() ? _buffer[_pos] : -1;

    public void Dispose() => _reader.Dispose();
}
