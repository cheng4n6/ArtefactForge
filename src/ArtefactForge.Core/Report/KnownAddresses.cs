using System.Net;
using System.Net.Sockets;
using System.Text;
using ArtefactForge.Core.Ioc;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Core.Report;

/// <summary>What an address is: a short label shown beside it, a note and where the label came from.</summary>
public sealed record AddressLabel(string Label, string Note, string From);

/// <summary>
/// Labels for addresses the analyst already knows: the domain controllers, the VPN pool, the
/// proxy. They come from two places, so an address in the case report reads "10.0.0.10 DC"
/// rather than a bare number to look up:
///
///   KnownAddresses.csv at the case root, the analyst's own (Address, Label, Note). An address is
///   one IP or a CIDR range (10.8.0.0/16). Lines starting with # are notes.
///   The case's system summaries: each domain controller's addresses, and the DNS servers and
///   gateways the hosts were set to use.
///
/// The most specific match wins, so 10.0.0.10 "DC" shows inside a 10.0.0.0/8 "Office LAN"; at the
/// same length the analyst's label wins. A row that cannot be read is reported, not dropped.
/// </summary>
public sealed class KnownAddresses
{
    public const string FileName = "KnownAddresses.csv";
    public static readonly string[] Columns = ["Address", "Label", "Note"];

    /// <summary>Where labels found in the data come from, for its column in the report.</summary>
    public const string FromData = "system summary";

    private readonly List<(IPNetwork Range, string Text, AddressLabel Label, int Rank)> _entries = [];
    private readonly List<string> _problems = [];

    /// <summary>Every label, the analyst's first, then by address.</summary>
    public IReadOnlyList<(string Address, AddressLabel Label)> Entries =>
        _entries.OrderBy(e => e.Rank).ThenBy(e => Key(e.Range), StringComparer.Ordinal)
                .Select(e => (e.Text, e.Label)).ToList();

    /// <summary>Rows of KnownAddresses.csv that could not be read, each saying which and why.</summary>
    public IReadOnlyList<string> Problems => _problems;

    /// <summary>True when the case has its own KnownAddresses.csv.</summary>
    public bool HasFile { get; private set; }

    public static string PathFor(string caseDirectory) => Path.Combine(caseDirectory, FileName);

    public static KnownAddresses Load(string caseDirectory, IEnumerable<ReportHost> hosts)
    {
        var known = new KnownAddresses();
        known.ReadFile(PathFor(caseDirectory));
        known.FromSummaries(hosts);
        return known;
    }

    /// <summary>The label for an address, or null when it has none or is not an address.</summary>
    public AddressLabel? For(string address)
    {
        if (_entries.Count == 0 || !IPAddress.TryParse(IpHistoryRecord.Normalise(address), out var ip)) return null;
        AddressLabel? best = null;
        int bestLength = -1, bestRank = int.MaxValue;
        foreach (var (range, _, label, rank) in _entries)
        {
            if (range.BaseAddress.AddressFamily != ip.AddressFamily || !range.Contains(ip)) continue;
            if (range.PrefixLength > bestLength || (range.PrefixLength == bestLength && rank < bestRank))
            {
                best = label;
                bestLength = range.PrefixLength;
                bestRank = rank;
            }
        }
        return best;
    }

    /// <summary>
    /// Creates KnownAddresses.csv with its header and an example line, if the case has none, and
    /// returns its path. An existing file is left exactly as it is.
    /// </summary>
    public static string EnsureFile(string caseDirectory)
    {
        var path = PathFor(caseDirectory);
        if (File.Exists(path)) return path;
        var text = new StringBuilder()
            .AppendLine(string.Join(",", Columns))
            .AppendLine("# One IP or a CIDR range per line, with a short label for the case report. Lines starting with # are left out.")
            .AppendLine("# 10.8.0.0/16,VPN,Remote access pool");
        AtomicFile.WriteAllText(path, text.ToString());
        return path;
    }

    private void ReadFile(string path)
    {
        if (!File.Exists(path)) return;
        HasFile = true;
        try
        {
            using var reader = CsvText.OpenRead(path);
            int address = -1, label = -1, note = -1;
            foreach (var record in CsvText.Records(reader))
            {
                var fields = CsvText.Split(record.Text).Select(f => f.Trim()).ToArray();
                if (fields.All(f => f.Length == 0) || fields[0].StartsWith('#')) continue;
                if (address < 0)
                {
                    address = Array.FindIndex(fields, f => f.Equals("Address", StringComparison.OrdinalIgnoreCase));
                    label = Array.FindIndex(fields, f => f.Equals("Label", StringComparison.OrdinalIgnoreCase));
                    note = Array.FindIndex(fields, f => f.Equals("Note", StringComparison.OrdinalIgnoreCase));
                    if (address < 0 || label < 0)
                    {
                        _problems.Add($"{FileName} has no Address and Label header, so none of it was read");
                        return;
                    }
                    continue;
                }

                string Cell(int i) => i >= 0 && i < fields.Length ? fields[i] : "";
                var text = Cell(address);
                if (Cell(label).Length == 0)
                    _problems.Add($"line {record.LineNumber}: {text} has no label");
                else if (!TryRange(text, out var range))
                    _problems.Add($"line {record.LineNumber}: {text} is not an IP address or a CIDR range such as 10.8.0.0/16");
                else
                    _entries.Add((range, text, new AddressLabel(Cell(label), Cell(note), FileName), 0));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _problems.Add($"{FileName} could not be read: {ex.Message}");
        }
    }

    private void FromSummaries(IEnumerable<ReportHost> hosts)
    {
        foreach (var host in hosts)
        {
            if (host.Role.Equals("Domain controller", StringComparison.OrdinalIgnoreCase))
                foreach (var a in Split(host.Addresses))
                    AddFound(a, "DC", $"Domain controller {host.Name}", 1);
            foreach (var a in Split(host.Fact("DnsServers")))
                AddFound(a, "DNS", $"DNS server set on {host.Name}", 2);
            foreach (var a in Split(host.Fact("Gateways")))
                AddFound(a, "Gateway", $"Default gateway of {host.Name}", 3);
        }
    }

    /// <summary>
    /// A label found in the data, once per address: the first host to give it names it, and a
    /// stronger label (a DC over a DNS server) replaces a weaker one.
    /// </summary>
    private void AddFound(string text, string label, string note, int rank)
    {
        if (!IPAddress.TryParse(IpHistoryRecord.Normalise(text), out var ip)) return;
        var range = new IPNetwork(ip, ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
        var at = _entries.FindIndex(e => e.Rank > 0 && e.Range.Equals(range));
        if (at >= 0)
        {
            if (_entries[at].Rank <= rank) return;
            _entries.RemoveAt(at);
        }
        _entries.Add((range, ip.ToString(), new AddressLabel(label, note, FromData), rank));
    }

    private static IEnumerable<string> Split(string addresses) =>
        addresses.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static bool TryRange(string text, out IPNetwork range)
    {
        range = default;
        if (text.Contains('/'))
        {
            if (!IPNetwork.TryParse(text, out var parsed)) return false;
            range = parsed;
            return true;
        }
        if (!IPAddress.TryParse(IpHistoryRecord.Normalise(text), out var ip)) return false;
        range = new IPNetwork(ip, ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
        return true;
    }

    private static string Key(IPNetwork range) =>
        (range.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? "4" : "6")
        + Convert.ToHexString(range.BaseAddress.GetAddressBytes()) + range.PrefixLength.ToString("D3");
}
