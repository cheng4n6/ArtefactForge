using System.Globalization;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxSyslog module: the general system logs, with their rotations.
///
///   LinuxSyslog_Events.csv           every line of syslog, messages, kern.log, daemon.log,
///                                    user.log and cloud-init.log
///   LinuxSyslog_KeyEvents.csv        the lines worth starting from: cron jobs run, USB devices,
///                                    unsigned or out-of-tree kernel modules, crashes, OOM kills,
///                                    interfaces set promiscuous
///   LinuxSyslog_CloudInitOutput.csv  cloud-init-output.log, the output of the instance's first-boot
///                                    scripts, line by line
///
/// auth.log and secure belong to LinuxAuth and are not read again here.
///
/// TIMESTAMPS follow LinuxAuth: classic lines ('Oct 29 10:23:45') carry no year, so it is taken
/// from the file's last-write time and rolled back a year for an entry that would otherwise fall
/// after the file was written (allowing two days for the gap between the host's clock and this
/// machine's). RawTime keeps what the line said and YearInferred says when the year was guessed.
/// RFC 3339 lines carry their year and offset, so TimestampUtc is filled for them.
///
/// A line in no recognised format (a wrapped kernel message, say) is kept with only its text, so
/// nothing in the log is dropped.
/// </summary>
public static partial class SyslogExport
{
    private static readonly string[] Header =
        ["Timestamp", "TimestampUtc", "YearInferred", "RawTime", "Host", "Process", "PID", "Message", "Log", "SourceFile"];

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var dir = new DirectoryInfo(Path.Combine(root, "var", "log"));
        if (!dir.Exists)
        {
            log.WriteLine($"No var/log under {root}");
            return 0;
        }

        var files = RotatedLogs.Order(dir.EnumerateFiles().Where(f => LogName().IsMatch(f.Name))).ToList();
        var cloudOutput = RotatedLogs.Order(dir.EnumerateFiles().Where(f => CloudOutputName().IsMatch(f.Name))).ToList();
        if (files.Count == 0 && cloudOutput.Count == 0)
        {
            log.WriteLine($"No syslog, messages, kern.log or cloud-init logs in {dir.FullName}");
            return 0;
        }

        Directory.CreateDirectory(outputDirectory);
        using var events = new CsvFile(Path.Combine(outputDirectory, "LinuxSyslog_Events.csv"), Header);
        using var keys = new CsvFile(Path.Combine(outputDirectory, "LinuxSyslog_KeyEvents.csv"), ["Event", "Detail", .. Header]);
        using var cloud = new CsvFile(Path.Combine(outputDirectory, "LinuxSyslog_CloudInitOutput.csv"), "Line", "Text", "SourceFile");

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
            var logName = LogName().Match(file.Name).Groups[1].Value;
            try
            {
                foreach (var line in RotatedLogs.ReadLines(file))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var row = Parse(line, file.LastWriteTime, logName, source);
                    events.Write(row);
                    if (KeyEvent(row[5], row[7]) is { } key) keys.Write([key.Event, key.Detail, .. row]);
                }
            }
            catch (InvalidDataException ex)
            {
                errors.WriteLine($"{source}: {ex.Message}");
            }
        }

        foreach (var file in cloudOutput)
        {
            var source = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
            var n = 0;
            try
            {
                foreach (var line in RotatedLogs.ReadLines(file))
                    cloud.Write((++n).ToString(CultureInfo.InvariantCulture), line, source);
            }
            catch (InvalidDataException ex)
            {
                errors.WriteLine($"{source}: {ex.Message}");
            }
        }

        foreach (var csv in new[] { events, keys, cloud })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-34} {csv.Rows} row(s)");
        return 0;
    }

    [GeneratedRegex(@"^(syslog|messages|kern\.log|daemon\.log|user\.log|cloud-init\.log)(\.\d+|-\d{8})?(\.gz)?$")]
    private static partial Regex LogName();

    [GeneratedRegex(@"^cloud-init-output\.log(\.\d+|-\d{8})?(\.gz)?$")]
    private static partial Regex CloudOutputName();

    /// <summary>One line as a row in <see cref="Header"/> order.</summary>
    internal static string[] Parse(string line, DateTime reference, string logName, string source)
    {
        var rfc = Rfc3339().Match(line);
        if (rfc.Success && DateTimeOffset.TryParse(rfc.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var at))
        {
            var format = rfc.Groups[2].Success ? "yyyy-MM-dd HH:mm:ss.ffffff" : "yyyy-MM-dd HH:mm:ss";
            return
            [
                at.DateTime.ToString(format, CultureInfo.InvariantCulture),
                at.UtcDateTime.ToString(format, CultureInfo.InvariantCulture),
                "no", rfc.Groups[1].Value, rfc.Groups[3].Value, rfc.Groups[4].Value.Trim(), rfc.Groups[5].Value,
                rfc.Groups[6].Value, logName, source
            ];
        }

        var classic = Classic().Match(line);
        if (classic.Success)
        {
            var raw = classic.Groups[1].Value;
            var timestamp = "";
            if (DateTime.TryParseExact(Regex.Replace(raw, @"\s+", " ") + " " + reference.Year, "MMM d HH:mm:ss yyyy",
                                       CultureInfo.InvariantCulture, DateTimeStyles.None, out var t))
            {
                if (t > reference.AddDays(2)) t = t.AddYears(-1);
                timestamp = t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            }
            return
            [
                timestamp, "", "yes", raw, classic.Groups[2].Value, classic.Groups[3].Value.Trim(),
                classic.Groups[4].Value, classic.Groups[5].Value, logName, source
            ];
        }

        // cloud-init.log: 2025-10-11 10:00:00,123 - util.py[DEBUG]: message
        var cloud = CloudInit().Match(line);
        if (cloud.Success)
            return
            [
                cloud.Groups[1].Value + "." + cloud.Groups[2].Value, "", "no", cloud.Groups[1].Value + "," + cloud.Groups[2].Value,
                "", cloud.Groups[3].Value.Trim(), "", $"[{cloud.Groups[4].Value}] {cloud.Groups[5].Value}", logName, source
            ];

        return ["", "", "", "", "", "", "", line, logName, source];
    }

    // Groups: 1 time, 2 fraction, 3 host, 4 process, 5 pid, 6 message.
    [GeneratedRegex(@"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(\S+)\s+([^:\[]+?)(?:\[(\d+)\])?:\s*(.*)$")]
    private static partial Regex Rfc3339();

    [GeneratedRegex(@"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+?)(?:\[(\d+)\])?:\s*(.*)$")]
    private static partial Regex Classic();

    [GeneratedRegex(@"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3}) - ([^\[]+)\[(\w+)\]: ?(.*)$")]
    private static partial Regex CloudInit();

    /// <summary>What a line is, when it is one an investigation starts from; null for the rest.</summary>
    internal static (string Event, string Detail)? KeyEvent(string process, string message)
    {
        if (process is "CRON" or "cron" or "crond")
        {
            var cron = CronCommand().Match(message);
            if (cron.Success) return ("Cron job run", $"{cron.Groups[1].Value}: {cron.Groups[2].Value.Trim()}");
        }
        if (process == "kernel")
        {
            if (message.Contains("module verification failed", StringComparison.Ordinal))
                return ("Unsigned kernel module loaded", message);
            if (message.Contains("loading out-of-tree module taints kernel", StringComparison.Ordinal))
                return ("Out-of-tree kernel module loaded", message);
            var usb = UsbProduct().Match(message);
            if (usb.Success) return ("USB device connected", message);
            if (message.Contains("New USB device found", StringComparison.Ordinal)) return ("USB device connected", message);
            if (message.Contains(" segfault at ", StringComparison.Ordinal)) return ("Process crashed (segfault)", message);
            if (message.Contains("Out of memory: Killed process", StringComparison.Ordinal)) return ("Process killed (out of memory)", message);
            if (message.Contains("entered promiscuous mode", StringComparison.Ordinal)) return ("Interface set promiscuous", message);
        }
        return null;
    }

    // (alice) CMD (/usr/local/bin/backup.sh)
    [GeneratedRegex(@"^\((\S+)\) CMD \((.*)\)\s*$")]
    private static partial Regex CronCommand();

    [GeneratedRegex(@"usb \S+: (Product|Manufacturer|SerialNumber): ")]
    private static partial Regex UsbProduct();
}
