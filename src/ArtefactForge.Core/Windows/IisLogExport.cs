using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// The WindowsIisLogs module: IIS web server logs in W3C extended format, HTTP.sys error logs and
/// the site list.
///
///   IisLogs_Requests.csv   one row per request (web and FTP sites), UTC
///   IisLogs_Flagged.csv    the requests matching a known-bad pattern, same columns
///   IisLogs_HttpErr.csv    requests HTTP.sys rejected before IIS saw them, UTC
///   IisLogs_Sites.csv      each site's applications and virtual directories, from applicationHost.config
///
/// Logs are looked for in inetpub\logs\LogFiles, Windows\System32\LogFiles (servers upgraded from
/// IIS 6) and every log folder applicationHost.config names, one subfolder per site (W3SVC1,
/// FTPSVC2). A W3C log is blocks of # directives and space-separated values; each #Fields line
/// sets the columns for the lines after it, because IIS starts a new block, in the same file,
/// when the service restarts or the logged fields change. W3C times are UTC whatever the "local
/// time rollover" setting, which changes only the file names. NCSA and IIS native format logs,
/// zipped archives and lines that do not fit their #Fields line are reported, not half-parsed.
///
/// The flags are a triage aid, not detection: they point at the requests worth reading first.
/// </summary>
public static class IisLogExport
{
    public const string RequestsFile = "IisLogs_Requests.csv";
    public const string FlaggedFile = "IisLogs_Flagged.csv";
    public const string HttpErrFile = "IisLogs_HttpErr.csv";
    public const string SitesFile = "IisLogs_Sites.csv";

    public static readonly string[] RequestColumns =
    [
        "TimestampUtc", "RawTime", "Service", "SiteId", "SiteName", "ServerName", "ServerIP", "ServerPort", "Method",
        "UriStem", "UriQuery", "Url", "Host", "Protocol", "Status", "SubStatus", "Win32Status", "BytesSent",
        "BytesReceived", "TimeTakenMs", "ClientIP", "ForwardedFor", "User", "UserAgent", "Referer", "Flags", "Extra",
        "SourceFile", "Line"
    ];

    public static readonly string[] HttpErrColumns =
    [
        "TimestampUtc", "RawTime", "ClientIP", "ClientPort", "ServerIP", "ServerPort", "Protocol", "Method", "Url",
        "Status", "SiteId", "Reason", "Queue", "SourceFile", "Line"
    ];

    public static readonly string[] SiteColumns =
    [
        "SiteId", "SiteName", "Bindings", "Application", "VirtualPath", "PhysicalPath", "CollectionPath",
        "LogDirectory", "LogFormat", "LogFields", "LocalTimeRollover"
    ];

    private const string DefaultLogDirectory = @"%SystemDrive%\inetpub\logs\LogFiles";
    private static readonly string ConfigPath = Path.Combine("Windows", "System32", "inetsrv", "config", "applicationHost.config");

    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

    // W3SVC1, FTPSVC2, and W3SVC alone for central (server-wide) logging.
    private static readonly Regex SiteFolder = new(@"^(?<service>W3SVC|FTPSVC)(?<id>\d*)$", Options);

    // ASP.NET shells: scripts under aspnet_client (it holds only static files), and the usual names.
    private static readonly Regex AspNetShell = new(
        @"/aspnet_client/(?:[^/?]+/)*[^/?]+\.(?:aspx|ashx|asmx|asp)\b|/(?:cmd|shell|webshell|aspxspy|spy)\.(?:ashx|asmx)\b", Options);

    // ProxyLogon and ProxyShell request shapes on Exchange.
    private static readonly Regex ExchangeExploit = new(
        @"/autodiscover/autodiscover\.json\?@|/ecp/[a-z]\.js(?:$|\?)|/owa/auth/[a-z]\.js(?:$|\?)|/ecp/DDI/DDIService\.svc/SetObject", Options);

    private static readonly Regex ExchangeCookie = new(@"X-(?:BE|Anon)Resource[^;]*~", Options);

    // A script answering a POST from a folder that normally holds static files.
    private static readonly Regex StaticFolderScript = new(
        @"/(?:aspnet_client|images?|img|uploads?|css|js|fonts|static|content|media)/(?:[^/?]+/)*[^/?]+\.(?:aspx|ashx|asmx|asp|php|jsp)$", Options);

    /// <summary>A site from applicationHost.config, for its name and log settings.</summary>
    public sealed record Site(string Id, string Name, string LogDirectory, string LogFormat);

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var sites = ReadConfig(root, log, errors, out var siteRows, out var configDirectories);

        var logDirectories = new List<string>
        {
            Path.Combine(root, "inetpub", "logs", "LogFiles"),
            Path.Combine(root, "Windows", "System32", "LogFiles")
        };
        foreach (var configured in configDirectories)
        {
            var mapped = MapToRoot(root, configured, out var problem);
            if (mapped is null) errors.WriteLine($"applicationHost.config logs to {configured}: {problem}; not read.");
            else if (!Directory.Exists(mapped)) errors.WriteLine($"applicationHost.config logs to {configured}, which is not in the collection.");
            else logDirectories.Add(mapped);
        }

        var siteFolders = logDirectories
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateDirectories(d))
            .Where(d => SiteFolder.IsMatch(Path.GetFileName(d)))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var httpErr = Path.Combine(root, "Windows", "System32", "LogFiles", "HTTPERR");

        Directory.CreateDirectory(outputDirectory);
        if (siteRows.Count > 0)
        {
            using var sitesCsv = new CsvFile(Path.Combine(outputDirectory, SitesFile), SiteColumns);
            foreach (var row in siteRows) sitesCsv.Write(row);
            log.WriteLine($"  {SitesFile,-24} {sitesCsv.Rows} row(s)");
        }

        if (siteFolders.Count == 0 && !Directory.Exists(httpErr))
        {
            log.WriteLine("No IIS log folders (W3SVC<n>, FTPSVC<n>) or HTTPERR logs found");
            return 0;
        }

        using var requests = new CsvFile(Path.Combine(outputDirectory, RequestsFile), RequestColumns);
        using var flagged = new CsvFile(Path.Combine(outputDirectory, FlaggedFile), RequestColumns);
        using var errorsCsv = new CsvFile(Path.Combine(outputDirectory, HttpErrFile), HttpErrColumns);
        var files = 0;

        foreach (var folder in siteFolders)
        {
            var m = SiteFolder.Match(Path.GetFileName(folder));
            var service = m.Groups["service"].Value.ToUpperInvariant() == "FTPSVC" ? "FTP" : "W3SVC";
            var folderId = m.Groups["id"].Value;
            var before = requests.Rows;
            foreach (var file in LogFiles(folder, errors, root))
            {
                cancellationToken.ThrowIfCancellationRequested();
                files++;
                var source = Relative(root, file.FullName);
                ReadFile(file, source, errors, cancellationToken, (line, fields) =>
                {
                    var row = RequestRow(fields, service, folderId, sites, source, line);
                    requests.Write(row);
                    if (row[25].Length > 0) flagged.Write(row);
                    return row[0].Length > 0;
                });
            }
            log.WriteLine($"  {Relative(root, folder)}: {requests.Rows - before} request(s)");
        }

        if (Directory.Exists(httpErr))
        {
            foreach (var file in LogFiles(httpErr, errors, root))
            {
                cancellationToken.ThrowIfCancellationRequested();
                files++;
                var source = Relative(root, file.FullName);
                ReadFile(file, source, errors, cancellationToken, (line, fields) =>
                {
                    var row = HttpErrRow(fields, source, line);
                    errorsCsv.Write(row);
                    return row[0].Length > 0;
                });
            }
        }

        log.WriteLine($"  {files} log file(s) read");
        foreach (var csv in new[] { requests, flagged, errorsCsv })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-24} {csv.Rows} row(s)");
        return 0;
    }

    /// <summary>The .log files of a folder, oldest name first; a zipped archive beside them is named, not read.</summary>
    private static IEnumerable<FileInfo> LogFiles(string folder, TextWriter errors, string root)
    {
        List<FileInfo> files;
        try
        {
            files = new DirectoryInfo(folder).EnumerateFiles().OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            errors.WriteLine($"{Relative(root, folder)}: could not list - {ex.Message}");
            yield break;
        }
        foreach (var file in files)
        {
            if (file.Extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) || file.Extension.Equals(".7z", StringComparison.OrdinalIgnoreCase))
                errors.WriteLine($"{Relative(root, file.FullName)}: archived logs, not read - unpack them into the folder to include them.");
            else if (file.Extension.Equals(".log", StringComparison.OrdinalIgnoreCase))
                yield return file;
        }
    }

    // --- W3C reading --------------------------------------------------------------------------------

    /// <summary>The field names of one #Fields line (lower case) and where each is; a name logged twice keeps the first.</summary>
    public sealed class W3cLayout
    {
        public IReadOnlyList<string> Names { get; }
        public IReadOnlyDictionary<string, int> Index { get; }

        public W3cLayout(string fields)
        {
            Names = fields.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(Normalise).ToList();
            var index = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < Names.Count; i++) index.TryAdd(Names[i], i);
            Index = index;
        }
    }

    /// <summary>The values of one W3C line, looked up by field name (lower case).</summary>
    public sealed class W3cFields(W3cLayout layout, string[] values)
    {
        /// <summary>The value logged for <paramref name="field"/>; empty when it was not logged or is "-".</summary>
        public string this[string field] =>
            layout.Index.TryGetValue(field, out var i) && values[i] != "-" ? values[i] : "";

        /// <summary>Every value in order; First is false for a name already logged earlier on the line.</summary>
        public IEnumerable<(string Field, string Value, bool First)> All =>
            layout.Names.Select((n, i) => (n, values[i], layout.Index[n] == i));
    }

    /// <summary>
    /// Reads one W3C log, handing each data line to <paramref name="row"/>, which says whether the
    /// row had a time. What could not be read is reported once per file.
    /// </summary>
    private static void ReadFile(FileInfo file, string source, TextWriter errors, CancellationToken cancellationToken,
        Func<int, W3cFields, bool> row)
    {
        var stats = new W3cStats();
        try
        {
            using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, EncodingFor(file.Name), detectEncodingFromByteOrderMarks: true);
            Read(reader, cancellationToken, row, stats);
            Report(stats, file.Name, source, errors);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            errors.WriteLine($"{source}: incomplete, read to line {stats.Lines} - {ex.Message}");
        }
    }

    /// <summary>What reading one log found that was not a row.</summary>
    public sealed record W3cStats
    {
        public int Lines { get; set; }
        public int Rows { get; set; }
        public int BeforeFields { get; set; }
        public int Mismatched { get; set; }
        public bool LastLineMismatched { get; set; }
        public int WithoutTime { get; set; }
        public bool HadFields { get; set; }
    }

    /// <summary>
    /// The W3C reader: directives start with '#', and each #Fields line replaces the field map for
    /// the lines that follow. A data line before any #Fields, or with a different number of values
    /// than its #Fields line, is counted and skipped.
    /// </summary>
    public static W3cStats Read(TextReader reader, CancellationToken cancellationToken, Func<int, W3cFields, bool> row,
        W3cStats? stats = null)
    {
        stats ??= new W3cStats();
        W3cLayout? layout = null;
        string? line;
        var lastWasMismatch = false;
        while ((line = reader.ReadLine()) is not null)
        {
            if ((++stats.Lines & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (line.Length == 0) continue;
            if (line[0] == '#')
            {
                if (line.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
                {
                    layout = new W3cLayout(line["#Fields:".Length..]);
                    stats.HadFields = true;
                }
                lastWasMismatch = false;
                continue;
            }
            if (layout is null)
            {
                stats.BeforeFields++;
                continue;
            }
            var values = line.TrimEnd().Split(' ');
            if (values.Length != layout.Names.Count)
            {
                stats.Mismatched++;
                lastWasMismatch = true;
                continue;
            }
            lastWasMismatch = false;
            stats.Rows++;
            if (!row(stats.Lines, new W3cFields(layout, values))) stats.WithoutTime++;
        }
        stats.LastLineMismatched = lastWasMismatch;
        return stats;
    }

    /// <summary>A field name as its key: lower case, and cs(X-Forwarded-For) the same as X-Forwarded-For.</summary>
    private static string Normalise(string name)
    {
        var lower = name.Trim().ToLowerInvariant();
        return lower is "cs(x-forwarded-for)" or "x-forwarded-for" or "x_forwarded_for" or "xff" ? "x-forwarded-for" : lower;
    }

    private static void Report(W3cStats stats, string fileName, string source, TextWriter errors)
    {
        if (!stats.HadFields)
        {
            if (stats.BeforeFields == 0) return;   // an empty log
            var format = Regex.IsMatch(fileName, @"^(?:u_)?nc", RegexOptions.IgnoreCase) ? "NCSA format"
                : Regex.IsMatch(fileName, @"^(?:u_)?in", RegexOptions.IgnoreCase) ? "IIS native format"
                : "not W3C (no #Fields line)";
            errors.WriteLine($"{source}: IIS log in {format}, not parsed ({stats.BeforeFields} line(s)).");
            return;
        }
        if (stats.BeforeFields > 0)
            errors.WriteLine($"{source}: {stats.BeforeFields} line(s) before the first #Fields line - start of the file missing? Not parsed.");
        if (stats.Mismatched > 0)
            errors.WriteLine($"{source}: {stats.Mismatched} line(s) did not match their #Fields line and were left out" +
                             (stats.LastLineMismatched ? "; the last line is one of them - file truncated?" : "."));
        if (stats.WithoutTime > 0)
            errors.WriteLine($"{source}: {stats.WithoutTime} row(s) without a readable date and time; TimestampUtc is empty.");
    }

    /// <summary>u_ex files are UTF-8; others are ANSI (read as Latin-1) unless they start with a byte order mark.</summary>
    private static Encoding EncodingFor(string fileName) =>
        fileName.StartsWith("u_", StringComparison.OrdinalIgnoreCase) ? new UTF8Encoding(false) : Encoding.Latin1;

    // --- rows ---------------------------------------------------------------------------------------

    private static readonly HashSet<string> RequestFields = new(StringComparer.Ordinal)
    {
        "date", "time", "s-sitename", "s-computername", "s-ip", "s-port", "cs-method", "cs-uri-stem", "cs-uri-query",
        "cs-host", "cs-version", "sc-status", "sc-substatus", "sc-win32-status", "sc-bytes", "cs-bytes", "time-taken",
        "c-ip", "x-forwarded-for", "cs-username", "cs(user-agent)", "cs(referer)"
    };

    public static string[] RequestRow(W3cFields f, string service, string folderId,
        IReadOnlyDictionary<string, Site> sites, string source, int line)
    {
        var (utc, raw) = Time(f);
        // s-sitename is the service and ID (W3SVC1), not the site's friendly name.
        var siteId = folderId.Length > 0 ? folderId : Regex.Match(f["s-sitename"], @"\d+$").Value;
        var siteName = sites.TryGetValue(siteId, out var site) ? site.Name : "";
        var stem = f["cs-uri-stem"];
        var query = f["cs-uri-query"];
        var url = query.Length > 0 ? stem + "?" + query : stem;
        var agent = Plus(f["cs(user-agent)"]);
        var extra = string.Join("; ", f.All.Where(p => (!RequestFields.Contains(p.Field) || !p.First) && p.Value is not ("-" or ""))
                                           .Select(p => p.Field + "=" + p.Value));
        var flags = Flags(f["cs-method"], url, stem, f["sc-status"], agent, f["cs(cookie)"]);
        return
        [
            utc, raw, service, siteId, siteName, f["s-computername"], f["s-ip"], f["s-port"], f["cs-method"],
            stem, query, url, f["cs-host"], f["cs-version"], f["sc-status"], f["sc-substatus"], f["sc-win32-status"],
            f["sc-bytes"], f["cs-bytes"], f["time-taken"], f["c-ip"], f["x-forwarded-for"], f["cs-username"], agent,
            Plus(f["cs(referer)"]), flags, extra, source, line.ToString(CultureInfo.InvariantCulture)
        ];
    }

    public static string[] HttpErrRow(W3cFields f, string source, int line)
    {
        var (utc, raw) = Time(f);
        return
        [
            utc, raw, f["c-ip"], f["c-port"], f["s-ip"], f["s-port"], f["cs-version"], f["cs-method"], f["cs-uri"],
            f["sc-status"], f["s-siteid"], f["s-reason"], f["s-queuename"], source, line.ToString(CultureInfo.InvariantCulture)
        ];
    }

    /// <summary>W3C date and time are UTC. Fractions, which some custom loggers add, are dropped.</summary>
    private static (string Utc, string Raw) Time(W3cFields f)
    {
        var raw = (f["date"] + " " + f["time"]).Trim();
        var utc = DateTime.TryParseExact(raw, ["yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ss.FFFFFFF"], CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t)
            ? t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
            : "";
        return (utc, raw);
    }

    /// <summary>IIS writes a space in the user agent, referer and cookie as '+'.</summary>
    private static string Plus(string value) => value.Replace('+', ' ');

    /// <summary>The Linux web log flags, and the IIS and Exchange ones.</summary>
    public static string Flags(string method, string url, string stem, string status, string agent, string cookie = "")
    {
        var flags = WebLogExport.Flags(url, agent).Split(';', StringSplitOptions.RemoveEmptyEntries).ToList();
        // Exchange ActiveSync names its command Cmd= on every request (?Cmd=Sync&User=...), which the
        // shared web shell pattern would flag on every phone that syncs mail.
        if (stem.StartsWith("/Microsoft-Server-ActiveSync", StringComparison.OrdinalIgnoreCase)) flags.Remove("WebShell");
        if (AspNetShell.IsMatch(stem) && !flags.Contains("WebShell")) flags.Add("WebShell");
        if (ExchangeExploit.IsMatch(url) || ExchangeCookie.IsMatch(cookie)) flags.Add("ExchangeExploit");
        if (method.Equals("POST", StringComparison.OrdinalIgnoreCase) && status == "200" && StaticFolderScript.IsMatch(stem))
            flags.Add("ScriptPost");
        return string.Join(";", flags);
    }

    // --- applicationHost.config ---------------------------------------------------------------------

    /// <summary>
    /// The sites, by ID, and one Sites.csv row per application and virtual directory; every log
    /// folder the configuration names is added to <paramref name="logDirectories"/>. Without the
    /// file, none of these: site names and physical paths are left blank.
    /// </summary>
    public static Dictionary<string, Site> ReadConfig(string root, TextWriter log, TextWriter errors,
        out List<string[]> rows, out List<string> logDirectories)
    {
        var sites = new Dictionary<string, Site>(StringComparer.Ordinal);
        rows = [];
        logDirectories = [];
        var path = Path.Combine(root, ConfigPath);
        if (!File.Exists(path))
        {
            log.WriteLine("No applicationHost.config in the collection: site names and physical paths are left blank");
            return sites;
        }

        XDocument document;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null });
            document = XDocument.Load(reader);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or XmlException)
        {
            errors.WriteLine($"{ConfigPath.Replace('\\', '/')}: could not be read ({ex.Message}); site names and physical paths are left blank.");
            return sites;
        }

        var sitesElement = document.Root?.Element("system.applicationHost")?.Element("sites");
        if (sitesElement is null) return sites;

        var defaults = sitesElement.Element("siteDefaults")?.Element("logFile");
        var defaultDirectory = Attr(defaults, "directory", DefaultLogDirectory);
        var defaultFormat = Attr(defaults, "logFormat", "W3C");
        var defaultFields = Attr(defaults, "logExtFileFlags", "");
        var defaultRollover = Attr(defaults, "localTimeRollover", "false");

        foreach (var directory in sitesElement.Descendants("logFile").Select(e => (string?)e.Attribute("directory")))
            if (!string.IsNullOrWhiteSpace(directory)) logDirectories.Add(directory);
        if (document.Root?.Element("system.applicationHost")?.Element("log")?.Element("centralW3CLogFile") is { } central
            && (string?)central.Attribute("directory") is { Length: > 0 } centralDirectory)
            logDirectories.Add(centralDirectory);
        logDirectories = logDirectories.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        foreach (var site in sitesElement.Elements("site"))
        {
            var id = Attr(site, "id", "");
            var name = Attr(site, "name", "");
            var logFile = site.Element("logFile");
            var directory = Attr(logFile, "directory", defaultDirectory);
            var format = Attr(logFile, "logFormat", defaultFormat);
            if (id.Length > 0) sites.TryAdd(id, new Site(id, name, directory, format));
            if (!format.Equals("W3C", StringComparison.OrdinalIgnoreCase))
                errors.WriteLine($"Site {name} ({id}) logs in {format} format, which is not parsed.");

            var bindings = string.Join("; ", site.Element("bindings")?.Elements("binding")
                .Select(b => Attr(b, "protocol", "") + " " + Attr(b, "bindingInformation", "")) ?? []);
            foreach (var application in site.Elements("application"))
            {
                var appPath = Attr(application, "path", "/");
                foreach (var directoryElement in application.Elements("virtualDirectory"))
                {
                    var physical = Attr(directoryElement, "physicalPath", "");
                    var expanded = Expand(physical);
                    var collection = physical.Length > 0 ? MapToRoot(root, physical, out _) ?? "" : "";
                    rows.Add(
                    [
                        id, name, bindings, appPath, VirtualPath(appPath, Attr(directoryElement, "path", "/")), expanded ?? physical,
                        collection.Length > 0 ? Relative(root, collection) : "", directory, format,
                        Attr(logFile, "logExtFileFlags", defaultFields), Attr(logFile, "localTimeRollover", defaultRollover)
                    ]);
                }
            }
        }
        log.WriteLine($"applicationHost.config: {sites.Count} site(s)");
        return sites;
    }

    private static string Attr(XElement? element, string name, string fallback) =>
        (string?)element?.Attribute(name) is { } value ? value : fallback;

    /// <summary>"/" and "/images" is /images; "/owa" and "/" is /owa.</summary>
    private static string VirtualPath(string application, string directory)
    {
        var app = application.TrimEnd('/');
        var dir = directory.Trim('/');
        return dir.Length == 0 ? (app.Length == 0 ? "/" : app) : app + "/" + dir;
    }

    /// <summary>%SystemDrive% as C:, %SystemRoot% and %windir% as C:\Windows; null for any other variable.</summary>
    public static string? Expand(string path)
    {
        var expanded = Regex.Replace(path, "%SystemDrive%", "C:", RegexOptions.IgnoreCase);
        expanded = Regex.Replace(expanded, "%(?:SystemRoot|windir)%", @"C:\Windows", RegexOptions.IgnoreCase);
        return expanded.Contains('%') ? null : expanded;
    }

    /// <summary>
    /// A path on the server as a path in the collection: the system drive is the root. A path on
    /// another drive, or with a variable the module cannot know, is null, with why.
    /// </summary>
    public static string? MapToRoot(string root, string serverPath, out string problem)
    {
        problem = "";
        if (Expand(serverPath) is not { } expanded)
        {
            problem = "it names an environment variable the collection cannot tell";
            return null;
        }
        if (!expanded.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase))
        {
            problem = expanded.Length >= 2 && expanded[1] == ':'
                ? $"it is on another volume ({expanded[..2]}), not this collection's root"
                : "it is not a local path";
            return null;
        }
        return Path.Combine([root, .. expanded[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries)]);
    }

    private static string Relative(string root, string path) => Path.GetRelativePath(root, path).Replace('\\', '/');
}
