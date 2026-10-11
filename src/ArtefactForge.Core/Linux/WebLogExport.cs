using System.Globalization;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxWebLogs module: Apache and nginx access and error logs, with rotated and gzipped history.
///
///   LinuxWebLogs_Access.csv    one row per request, UTC
///   LinuxWebLogs_Flagged.csv   requests matching a known-bad pattern, with the reason
///   LinuxWebLogs_Errors.csv    error log lines, host local time
///
/// Access logs are parsed as Common or Combined Log Format, optionally with the vhost:port prefix
/// Debian writes to other_vhosts_access.log - between them the defaults for both servers. A custom
/// LogFormat that matches neither is counted and reported rather than half-parsed.
///
/// The flags are a triage aid, not detection: they point at the requests worth reading first.
/// </summary>
public static class WebLogExport
{
    private static readonly string[] LogDirectories = ["var/log/apache2", "var/log/httpd", "var/log/nginx"];

    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    private static readonly Regex AccessName = new(@"access", Options | RegexOptions.IgnoreCase);
    private static readonly Regex ErrorName = new(@"error", Options | RegexOptions.IgnoreCase);

    // [vhost:port ]host ident user [time] "request" status bytes[ "referer" "user-agent"]
    private static readonly Regex AccessLine = new(
        @"^(?:(?<vhost>\S+?):(?<port>\d+)\s+)?(?<host>\S+) (?<ident>\S+) (?<user>\S+) \[(?<time>[^\]]+)\] ""(?<request>(?:[^""\\]|\\.)*)"" (?<status>\d{3}|-) (?<bytes>\d+|-)(?: ""(?<referer>(?:[^""\\]|\\.)*)"" ""(?<agent>(?:[^""\\]|\\.)*)"")?",
        Options);

    // [Wed Oct 11 14:32:52.123456 2023] [core:error] [pid 1234:tid 5678] [client 192.0.2.1:5678] message
    private static readonly Regex ApacheError = new(
        @"^\[(?<time>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(?:(?<module>[^:\]]*):)?(?<level>[^\]]+)\](?: \[pid (?<pid>\d+)[^\]]*\])?(?: \[client (?<client>[^\]]+)\])?\s*(?<message>.*)$",
        Options);

    // 2023/10/11 14:32:52 [error] 1234#1234: *5 message, client: 192.0.2.1, server: ...
    private static readonly Regex NginxError = new(
        @"^(?<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?<level>\w+)\] (?<pid>\d+)#\d+: (?:\*\d+ )?(?<message>.*?)(?:, client: (?<client>[^,]+)(?:, .*)?)?$",
        Options);

    private static readonly (string Flag, Regex Pattern)[] RequestFlags =
    [
        ("PathTraversal", new(@"\.\./|\.\.\\", Options)),
        ("SensitiveFile", new(@"/etc/(?:passwd|shadow|hosts)|/proc/self|/\.env\b|/\.git/|wp-config\.php|id_rsa|\.aws/credentials", Options | RegexOptions.IgnoreCase)),
        ("Log4Shell", new(@"\$\{(?:jndi|\$\{|lower:|upper:|env:)", Options | RegexOptions.IgnoreCase)),
        ("SqlInjection", new(@"union\s+(?:all\s+)?select|information_schema|sleep\(\s*\d|benchmark\(|'\s*or\s*'?1'?\s*=\s*'?1", Options | RegexOptions.IgnoreCase)),
        ("CommandInjection", new(@"(?:[;|`]|\$\()\s*(?:wget|curl|bash|sh|nc|ncat|python\d?|perl|chmod|id|whoami|uname)\b|/bin/(?:ba)?sh\b|powershell", Options | RegexOptions.IgnoreCase)),
        ("WebShell", new(@"[?&](?:cmd|exec|command|execute)=|/(?:c99|r57|b374k|wso|webshell|shell|cmd)\.(?:php\d?|jsp|aspx?)\b|base64_decode|eval\(|assert\(", Options | RegexOptions.IgnoreCase))
    ];

    private static readonly Regex ScannerAgent = new(
        @"sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wfuzz|ffuf|feroxbuster|acunetix|nessus|openvas|wpscan|hydra|metasploit",
        Options | RegexOptions.IgnoreCase);

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var sources = new List<(string Server, FileInfo File)>();
        foreach (var relative in LogDirectories)
        {
            var dir = new DirectoryInfo(Path.Combine(root, relative));
            if (!dir.Exists) continue;
            var server = relative.EndsWith("nginx") ? "nginx" : "apache";
            try
            {
                sources.AddRange(RotatedLogs.Order(dir.EnumerateFiles("*", SearchOption.AllDirectories))
                    .Where(f => AccessName.IsMatch(f.Name) || ErrorName.IsMatch(f.Name))
                    .Select(f => (server, f)));
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                errors.WriteLine($"{relative}: could not list - {ex.Message}");
            }
        }

        if (sources.Count == 0)
        {
            log.WriteLine($"No access or error logs under {string.Join(", ", LogDirectories)}");
            return 0;
        }

        Directory.CreateDirectory(outputDirectory);
        using var access = new CsvFile(Path.Combine(outputDirectory, "LinuxWebLogs_Access.csv"),
            "TimestampUtc", "RawTime", "Server", "VHost", "ClientIP", "User", "Method", "Url", "Protocol",
            "Status", "Bytes", "Referer", "UserAgent", "Flags", "SourceFile", "Line");
        using var flagged = new CsvFile(Path.Combine(outputDirectory, "LinuxWebLogs_Flagged.csv"),
            "TimestampUtc", "RawTime", "Server", "VHost", "ClientIP", "User", "Method", "Url", "Protocol",
            "Status", "Bytes", "Referer", "UserAgent", "Flags", "SourceFile", "Line");
        using var errorLog = new CsvFile(Path.Combine(outputDirectory, "LinuxWebLogs_Errors.csv"),
            "Timestamp", "Server", "Level", "Module", "PID", "Client", "Message", "SourceFile", "Line");

        foreach (var (server, file) in sources)
        {
            var relativeName = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
            var isAccess = AccessName.IsMatch(file.Name);
            var unparsed = 0;
            var lineNumber = 0;

            try
            {
                foreach (var line in RotatedLogs.ReadLines(file))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    lineNumber++;
                    if (line.Length == 0) continue;

                    if (isAccess)
                    {
                        var row = ParseAccess(line, server, relativeName, lineNumber);
                        if (row is null) { unparsed++; continue; }
                        access.Write(row);
                        if (row[13].Length > 0) flagged.Write(row);
                    }
                    else
                    {
                        errorLog.Write(ParseError(line, server, relativeName, lineNumber));
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                errors.WriteLine($"{relativeName}: incomplete, read to line {lineNumber} - {ex.Message}");
            }

            if (unparsed > 0)
                errors.WriteLine($"{relativeName}: {unparsed} of {lineNumber} line(s) not in Common or Combined format - custom LogFormat? Not parsed.");
        }

        log.WriteLine($"  {sources.Count} log file(s) read");
        foreach (var csv in new[] { access, flagged, errorLog })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-28} {csv.Rows} row(s)");
        return 0;
    }

    public static string[]? ParseAccess(string line, string server, string source, int lineNumber)
    {
        var m = AccessLine.Match(line);
        if (!m.Success) return null;

        var raw = m.Groups["time"].Value;
        var utc = DateTimeOffset.TryParseExact(raw, "dd/MMM/yyyy:HH:mm:ss zzz", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var parsed)
            ? parsed.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss")
            : "";

        // "GET /path HTTP/1.1" - but a scanner's garbage request line is kept whole in Url.
        var request = Unescape(m.Groups["request"].Value);
        string method = "", url = request, protocol = "";
        var parts = request.Split(' ');
        if (parts.Length >= 3 && parts[^1].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            method = parts[0];
            protocol = parts[^1];
            url = string.Join(' ', parts[1..^1]);
        }

        var agent = Unescape(m.Groups["agent"].Value);
        var vhost = m.Groups["vhost"].Success ? m.Groups["vhost"].Value + ":" + m.Groups["port"].Value : "";
        var user = m.Groups["user"].Value == "-" ? "" : m.Groups["user"].Value;

        return
        [
            utc, raw, server, vhost, m.Groups["host"].Value, user, method, url, protocol,
            m.Groups["status"].Value, m.Groups["bytes"].Value == "-" ? "0" : m.Groups["bytes"].Value,
            Unescape(m.Groups["referer"].Value), agent, Flags(url, agent), source, lineNumber.ToString()
        ];
    }

    public static string[] ParseError(string line, string server, string source, int lineNumber)
    {
        var a = ApacheError.Match(line);
        if (a.Success)
        {
            var time = DateTime.TryParseExact(Regex.Replace(a.Groups["time"].Value, " +", " "),
                ["ddd MMM d HH:mm:ss.ffffff yyyy", "ddd MMM d HH:mm:ss yyyy"],
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)
                ? t.ToString("yyyy-MM-dd HH:mm:ss.ffffff") : a.Groups["time"].Value;
            return [time, server, a.Groups["level"].Value, a.Groups["module"].Value, a.Groups["pid"].Value,
                    a.Groups["client"].Value, a.Groups["message"].Value, source, lineNumber.ToString()];
        }

        var n = NginxError.Match(line);
        if (n.Success)
        {
            var time = DateTime.TryParseExact(n.Groups["time"].Value, "yyyy/MM/dd HH:mm:ss",
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)
                ? t.ToString("yyyy-MM-dd HH:mm:ss") : n.Groups["time"].Value;
            return [time, server, n.Groups["level"].Value, "", n.Groups["pid"].Value,
                    n.Groups["client"].Value.Trim(), n.Groups["message"].Value, source, lineNumber.ToString()];
        }

        // A continuation - PHP stack traces, multi-line messages. Kept, so nothing is lost.
        return ["", server, "", "", "", "", line, source, lineNumber.ToString()];
    }

    /// <summary>Apache escapes quotes and control bytes in the request and agent as \" and \xhh.</summary>
    private static string Unescape(string value) =>
        value.Contains('\\') ? value.Replace("\\\"", "\"").Replace("\\\\", "\\") : value;

    public static string Flags(string url, string agent)
    {
        // Match against the decoded URL as well as the raw one: %2e%2e%2f is ../ to the server.
        var decoded = url;
        for (var i = 0; i < 2; i++)
        {
            try { decoded = Uri.UnescapeDataString(decoded.Replace('+', ' ')); }
            catch (UriFormatException) { break; }
        }

        var flags = new List<string>();
        foreach (var (flag, pattern) in RequestFlags)
            if (pattern.IsMatch(url) || pattern.IsMatch(decoded)) flags.Add(flag);
        if (ScannerAgent.IsMatch(agent)) flags.Add("ScannerAgent");
        return string.Join(";", flags);
    }
}
