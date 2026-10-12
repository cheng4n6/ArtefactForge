using System.Globalization;
using System.Net;
using System.Text;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// The WindowsDhcpServerLog module: the Windows DHCP server's audit logs,
/// Windows\System32\dhcp\DhcpSrvLog-Mon.log ... DhcpSrvLog-Sun.log and the DhcpV6SrvLog-*.log
/// pair, one file per weekday, so about a week of leases.
///
///   DhcpServerLog.csv  one row per lease event: when, the address, the host name, the MAC
///
/// The logs are written in the server's local time with a two-digit year (MM/dd/yy). Local times
/// are converted to UTC with the time zone named in the collection's SYSTEM hive, and the local
/// time is kept beside it. When the zone cannot be read, TimeUtc is left empty and that is
/// reported, rather than passing local time off as UTC.
///
/// Only events that bind an address to a client are kept: 10 new lease, 11 renew, 12 release and
/// 20 BOOTP for IPv4, and every IPv6 row with an address. The rest (the log's own start and stop,
/// DNS update results, scope full) say nothing about who had which address.
/// </summary>
public static class DhcpServerLogExport
{
    public const string OutputFile = "DhcpServerLog.csv";

    public static readonly string[] Columns =
    [
        "TimeUtc", "LocalTime", "Protocol", "EventId", "Description", "IpAddress", "HostName",
        "MacAddress", "Duid", "SourceFile"
    ];

    private static readonly HashSet<int> LeaseEvents = [10, 11, 12, 20];

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors,
                          CancellationToken cancellationToken)
    {
        var directory = Path.Combine(root, "Windows", "System32", "dhcp");
        var files = Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, "Dhcp*SrvLog-*.log")
                .OrderBy(f => Path.GetFileName(f), StringComparer.OrdinalIgnoreCase)
                .ToList()
            : [];
        if (files.Count == 0)
        {
            log.WriteLine($"No DHCP server audit logs in {Path.Combine("Windows", "System32", "dhcp")} under {root}");
            return 0;
        }

        var zone = TimeZoneFromRoot(root, out var zoneProblem);
        if (zone is null)
            errors.WriteLine($"{zoneProblem} - DHCP log times are local; TimeUtc is left empty.");
        else
            log.WriteLine($"DHCP log times converted to UTC from {zone.Id}");

        Directory.CreateDirectory(outputDirectory);
        using var csv = new CsvFile(Path.Combine(outputDirectory, OutputFile), Columns);

        foreach (var path in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = Path.GetRelativePath(root, path).Replace('\\', '/');
            string[] lines;
            try
            {
                // The service holds today's file open, so share it.
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                                                  FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream, Encoding.Latin1);
                lines = reader.ReadToEnd().Split('\n');
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.WriteLine($"{source}: could not read: {ex.Message}");
                continue;
            }

            var parsed = Parse(lines, zone, out var unreadable);
            foreach (var row in parsed)
                csv.Write(row.TimeUtc is { } t ? t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "",
                          row.LocalTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                          row.Protocol, row.EventId.ToString(CultureInfo.InvariantCulture), row.Description,
                          row.IpAddress, row.HostName, row.MacAddress, row.Duid, source);

            log.WriteLine($"{source}: {parsed.Count} lease events");
            if (unreadable > 0)
                errors.WriteLine($"{source}: {unreadable} event line(s) could not be read (date, time or ID) and were left out.");
        }

        log.WriteLine($"{csv.Rows} lease events written to {OutputFile}");
        return 0;
    }

    /// <summary>One lease event from a DHCP server audit log.</summary>
    public sealed record LeaseEvent(
        DateTime? TimeUtc, DateTime LocalTime, string Protocol, int EventId, string Description,
        string IpAddress, string HostName, string MacAddress, string Duid);

    /// <summary>
    /// Reads one log's lines. The column header ("ID,Date,Time,...") follows a block of free text
    /// explaining the event codes; columns are found by name from it, because the IPv4 log gained
    /// columns over Windows versions and the IPv6 log has its own set.
    /// </summary>
    public static List<LeaseEvent> Parse(IEnumerable<string> lines, TimeZoneInfo? zone, out int unreadable)
    {
        unreadable = 0;
        var events = new List<LeaseEvent>();
        Dictionary<string, int>? columns = null;
        var isV6 = false;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');
            if (columns is null)
            {
                if (!line.StartsWith("ID,Date,Time", StringComparison.OrdinalIgnoreCase)) continue;
                var names = line.Split(',');
                columns = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i < names.Length; i++)
                    columns.TryAdd(names[i].Trim().TrimEnd('.'), i);
                isV6 = columns.ContainsKey("IPV6 Address");
                continue;
            }

            if (line.Length == 0 || !char.IsAsciiDigit(line[0])) continue;
            var fields = line.Split(',');
            if (!int.TryParse(Field(fields, 0), NumberStyles.None, CultureInfo.InvariantCulture, out var id)
                || !TryLocalTime(Field(fields, 1), Field(fields, 2), out var local))
            {
                unreadable++;
                continue;
            }

            var address = Field(fields, Index(columns, isV6 ? "IPV6 Address" : "IP Address")).Trim();
            if (!IPAddress.TryParse(address, out _)) continue;
            if (!isV6 && !LeaseEvents.Contains(id)) continue;

            events.Add(new LeaseEvent(
                ToUtc(local, zone), local, isV6 ? "DHCPv6" : "DHCP", id,
                Field(fields, 3).Trim(), address,
                Field(fields, Index(columns, "Host Name")).Trim(),
                isV6 ? "" : FormatMac(Field(fields, Index(columns, "MAC Address")).Trim()),
                isV6 ? Field(fields, Index(columns, "Duid Bytes(Hex)")).Trim() : ""));
        }

        return events;
    }

    /// <summary>
    /// The zone the server kept its clock in, from TimeZoneKeyName in the control set it booted
    /// with. Null, with the reason, when the hive or the value is missing or names a zone this
    /// machine does not know.
    /// </summary>
    public static TimeZoneInfo? TimeZoneFromRoot(string root, out string problem)
    {
        problem = "";
        var hivePath = Path.Combine(root, "Windows", "System32", "config", "SYSTEM");
        if (!File.Exists(hivePath))
        {
            problem = "no SYSTEM hive to read the time zone from";
            return null;
        }

        string? name;
        try
        {
            using var hive = RegistryHive.Open(hivePath);
            var current = hive.ReadDword("Select", "Current") ?? 1;
            name = hive.ReadString($@"ControlSet{current:D3}\Control\TimeZoneInformation", "TimeZoneKeyName");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            problem = "could not read the time zone from the SYSTEM hive: " + ex.Message;
            return null;
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            problem = "the SYSTEM hive names no time zone (TimeZoneKeyName)";
            return null;
        }

        try { return TimeZoneInfo.FindSystemTimeZoneById(name.Trim()); }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            problem = $"time zone '{name}' from the SYSTEM hive is not known on this machine";
            return null;
        }
    }

    private static DateTime? ToUtc(DateTime local, TimeZoneInfo? zone)
    {
        if (zone is null) return null;
        // The hour skipped when clocks go forward cannot occur in a log; if it does, the clock was
        // being changed, and the standard offset is the better guess than throwing the row away.
        if (zone.IsInvalidTime(local)) local = local.AddHours(1);
        return TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), zone);
    }

    private static bool TryLocalTime(string date, string time, out DateTime local) =>
        DateTime.TryParseExact(date.Trim() + " " + time.Trim(),
            ["MM/dd/yy HH:mm:ss", "M/d/yy H:mm:ss", "MM/dd/yyyy HH:mm:ss", "M/d/yyyy H:mm:ss"],
            CultureInfo.InvariantCulture, DateTimeStyles.None, out local);

    /// <summary>"0050569A1B2C" as 00-50-56-9A-1B-2C, the form ipconfig and the DHCP console show.</summary>
    private static string FormatMac(string mac)
    {
        if (mac.Length != 12 || !mac.All(char.IsAsciiHexDigit)) return mac;
        return string.Join("-", Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2).ToUpperInvariant()));
    }

    private static int Index(Dictionary<string, int> columns, string name) =>
        columns.TryGetValue(name, out var i) ? i : -1;

    private static string Field(string[] fields, int index) =>
        index >= 0 && index < fields.Length ? fields[index] : "";
}
