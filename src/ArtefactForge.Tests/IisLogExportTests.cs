using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Tests;

/// <summary>
/// The WindowsIisLogs module, against synthetic logs only: no IIS evidence was available when it
/// was written. The fixture under Fixtures\iis\collection is built by Build-IisFixtures.ps1 beside
/// it; the format follows Microsoft's W3C extended log documentation and IIS 10's defaults. Treat
/// the module as unverified against a real server until one has been collected and run.
/// </summary>
public class IisLogExportTests
{
    private const string Header = "#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n#Date: 2026-03-16 00:00:00\r\n";
    private const string DefaultFields =
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\r\n";

    private static string Fixture => Path.Combine(AppContext.BaseDirectory, "Fixtures", "iis", "collection");

    // Output goes to a folder of its own, never into the fixture.
    private static (string Log, string Errors, string Out) Run(string root)
    {
        var output = Path.Combine(Path.GetTempPath(), "af-iis-" + Guid.NewGuid().ToString("N")[..8]);
        var log = new StringWriter();
        var errors = new StringWriter();
        Assert.Equal(0, IisLogExport.Run(root, output, log, errors, default));
        return (log.ToString(), errors.ToString(), output);
    }

    /// <summary>A written CSV's rows by column name; none when the file was not written.</summary>
    private static List<Dictionary<string, string>> Rows(string output, string file)
    {
        var path = Path.Combine(output, file);
        if (!File.Exists(path)) return [];
        var lines = File.ReadAllLines(path, Encoding.UTF8);
        var header = Core.Ioc.CsvText.Split(lines[0].TrimStart('\uFEFF'));
        return lines.Skip(1).Select(l => Core.Ioc.CsvText.Split(l))
                    .Select(f => header.Select((h, i) => (h, v: f[i])).ToDictionary(p => p.h, p => p.v))
                    .ToList();
    }

    private static void Write(string root, string relative, string text, Encoding? encoding = null)
    {
        var path = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text, encoding ?? new UTF8Encoding(false));
    }

    private static string Line(string time, string stem, string query = "-", string client = "198.51.100.10", string status = "200",
                               string method = "GET", string agent = "Mozilla/5.0+(Windows+NT+10.0)") =>
        $"2026-03-16 {time} 192.0.2.10 {method} {stem} {query} 443 - {client} {agent} - {status} 0 0 15\r\n";

    [Fact]
    public void The_synthetic_collection_gives_every_request_site_and_rejected_request()
    {
        var (log, errors, output) = Run(Fixture);

        // A good run says nothing on stderr, so it is not marked for review.
        Assert.Equal("", errors);
        var requests = Rows(output, IisLogExport.RequestsFile);
        Assert.Equal(129, requests.Count(r => r["SiteId"] == "1"));
        Assert.Equal(31, requests.Count(r => r["SiteId"] == "2"));
        Assert.Equal(3, requests.Count(r => r["Service"] == "FTP"));
        Assert.Equal(2, Rows(output, IisLogExport.HttpErrFile).Count);
        Assert.Equal(5, Rows(output, IisLogExport.SitesFile).Count);
        Assert.Contains("applicationHost.config: 3 site(s)", log);

        Assert.All(requests, r => Assert.Matches(@"^2026-03-16 \d\d:\d\d:\d\d$", r["TimestampUtc"]));
        Assert.All(requests.Where(r => r["SiteId"] == "1"), r => Assert.Equal("Default Web Site", r["SiteName"]));

        // The second #Fields block in the same file added the host, bytes and X-Forwarded-For.
        var wide = requests.Where(r => r["SiteId"] == "1" && r["Host"].Length > 0).ToList();
        Assert.Equal(60, wide.Count);
        Assert.All(wide, r =>
        {
            Assert.Equal("www.example.test", r["Host"]);
            Assert.Equal("192.0.2.250", r["ClientIP"]);
            Assert.NotEqual("", r["ForwardedFor"]);
            Assert.NotEqual("", r["BytesSent"]);
            Assert.Equal("WEB01", r["ServerName"]);
        });
        Assert.All(requests.Where(r => r["SiteId"] == "1" && r["Host"].Length == 0), r => Assert.Equal("", r["ForwardedFor"]));
        Assert.Contains(requests, r => r["ClientIP"] == "2001:db8::25");
        Assert.Contains(requests, r => r["UserAgent"].StartsWith("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", StringComparison.Ordinal));
        Assert.Contains(requests, r => r["User"] == @"CORP\alice");

        var ftp = requests.Single(r => r["Method"] == "RETR");
        Assert.Equal(("Files", "finance.xlsx", "226"), (ftp["SiteName"], ftp["UriStem"], ftp["Status"]));
        Assert.Contains("x-session=6a1b2c3d", ftp["Extra"]);
    }

    [Fact]
    public void The_synthetic_collection_flags_the_scanner_the_dropped_script_and_the_exchange_exploit_but_not_ActiveSync()
    {
        var (_, _, output) = Run(Fixture);
        var flagged = Rows(output, IisLogExport.FlaggedFile);

        Assert.Equal(5, flagged.Count(r => r["Flags"].Contains("ScannerAgent")));
        Assert.Contains(flagged, r => r["UriStem"] == "/../../windows/win.ini" && r["Flags"].Contains("PathTraversal"));
        Assert.Contains(flagged, r => r["UriStem"] == "/search.aspx" && r["Flags"].Contains("SqlInjection"));
        var shell = flagged.Where(r => r["UriStem"] == "/aspnet_client/system_web/errorpage.aspx").ToList();
        Assert.Equal(3, shell.Count);
        Assert.All(shell, r => Assert.Equal("WebShell;ScriptPost", r["Flags"]));
        Assert.Equal("/autodiscover/autodiscover.json?@evil.example/powershell/?X-Rps-CAT=VgEAVAdXaW5kb3dz",
                     flagged.Single(r => r["Flags"].Contains("ExchangeExploit"))["Url"]);
        Assert.DoesNotContain(flagged, r => r["UriStem"].StartsWith("/Microsoft-Server-ActiveSync", StringComparison.Ordinal));
        Assert.Equal(flagged.Count, Rows(output, IisLogExport.RequestsFile).Count(r => r["Flags"].Length > 0));
    }

    [Fact]
    public void The_sites_file_gives_each_virtual_directory_its_server_and_collection_path()
    {
        var (_, _, output) = Run(Fixture);
        var sites = Rows(output, IisLogExport.SitesFile);

        var root = sites.Single(s => s["SiteId"] == "1" && s["VirtualPath"] == "/");
        Assert.Equal((@"C:\inetpub\wwwroot", "inetpub/wwwroot", "https *:443:"), (root["PhysicalPath"], root["CollectionPath"], root["Bindings"]));
        // On another volume: kept, with no path in the collection.
        var downloads = sites.Single(s => s["VirtualPath"] == "/downloads");
        Assert.Equal((@"D:\Downloads", ""), (downloads["PhysicalPath"], downloads["CollectionPath"]));
        Assert.Equal("/owa", sites.Single(s => s["Application"] == "/owa")["VirtualPath"]);
        Assert.All(sites, s => Assert.Equal("W3C", s["LogFormat"]));
    }

    [Fact]
    public void The_fixture_builder_still_makes_the_checked_in_fixture()
    {
        var builder = Path.Combine(AppContext.BaseDirectory, "Fixtures", "iis", "Build-IisFixtures.ps1");
        var source = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Fixtures", "iis", "Build-IisFixtures.ps1"));
        if (File.Exists(source)) builder = source;
        Assert.True(File.Exists(builder), "Build-IisFixtures.ps1 is missing");
        using var dir = new TempDirectory();
        var built = Path.Combine(dir.Path, "collection");

        using var process = Process.Start(new ProcessStartInfo("powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{builder}\" -Out \"{built}\"")
            { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false })!;
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, stderr);

        var expected = Directory.EnumerateFiles(Fixture, "*", SearchOption.AllDirectories)
                                .Select(f => Path.GetRelativePath(Fixture, f)).Order().ToList();
        Assert.Equal(expected, Directory.EnumerateFiles(built, "*", SearchOption.AllDirectories)
                                        .Select(f => Path.GetRelativePath(built, f)).Order());
        // Text compared without regard to line ends: git may store the fixture with LF and check it out with CRLF.
        static string Text(string path) => File.ReadAllText(path).Replace("\r\n", "\n");
        foreach (var file in expected)
            Assert.True(Text(Path.Combine(Fixture, file)) == Text(Path.Combine(built, file)), file);
    }

    [Fact]
    public void Each_Fields_line_sets_the_columns_for_the_lines_after_it_even_reordered()
    {
        using var dir = new TempDirectory();
        Write(dir.Path, @"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log",
            Header + DefaultFields + Line("10:00:00", "/a.aspx")
            + Header + "#Fields: time date c-ip cs-uri-stem sc-status cs-method\r\n"
            + "10:05:00 2026-03-16 198.51.100.20 /b.aspx 500 POST\r\n");

        var (_, errors, output) = Run(dir.Path);

        Assert.Equal("", errors);
        var rows = Rows(output, IisLogExport.RequestsFile);
        Assert.Equal(("2026-03-16 10:00:00", "/a.aspx", "GET", "200"), (rows[0]["TimestampUtc"], rows[0]["Url"], rows[0]["Method"], rows[0]["Status"]));
        Assert.Equal(("2026-03-16 10:05:00", "/b.aspx", "POST", "500", "198.51.100.20"),
                     (rows[1]["TimestampUtc"], rows[1]["Url"], rows[1]["Method"], rows[1]["Status"], rows[1]["ClientIP"]));
        Assert.Equal(("", "", "1"), (rows[1]["UserAgent"], rows[1]["ServerIP"], rows[1]["SiteId"]));
    }

    [Fact]
    public void Lines_before_any_Fields_line_or_that_do_not_fit_it_are_reported_not_half_parsed()
    {
        using var dir = new TempDirectory();
        Write(dir.Path, @"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log",
            Line("09:59:00", "/early.aspx") + Header + DefaultFields + Line("10:00:00", "/a.aspx")
            + "2026-03-16 10:00:01 192.0.2.10 GET /short\r\n" + Line("10:00:02", "/b.aspx")
            + "2026-03-16 10:00:03 192.0.2.10 GET /cut-off - 443");

        var (_, errors, output) = Run(dir.Path);

        Assert.Equal(["/a.aspx", "/b.aspx"], Rows(output, IisLogExport.RequestsFile).Select(r => r["Url"]));
        Assert.Contains("1 line(s) before the first #Fields line", errors);
        Assert.Contains("2 line(s) did not match their #Fields line and were left out; the last line is one of them - file truncated?", errors);
    }

    [Fact]
    public void Other_formats_and_zipped_archives_are_named_not_read()
    {
        using var dir = new TempDirectory();
        var folder = Path.Combine(dir.Path, @"inetpub\logs\LogFiles\W3SVC1");
        Write(folder, "u_nc260316.log", "198.51.100.10 - - [16/Mar/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 512\r\n");
        Write(folder, "u_in260316.log", "198.51.100.10, -, 3/16/2026, 10:00:00, W3SVC1, WEB01, 192.0.2.10, 15, 300, 512, 200, 0, GET, /, -,\r\n");
        Write(folder, "u_ex260316.log", Header + DefaultFields + Line("10:00:00", "/"));
        using (var zip = ZipFile.Open(Path.Combine(folder, "old-logs.zip"), ZipArchiveMode.Create))
            zip.CreateEntry("u_ex260101.log");

        var (_, errors, output) = Run(dir.Path);

        Assert.Single(Rows(output, IisLogExport.RequestsFile));
        Assert.Contains("u_nc260316.log: IIS log in NCSA format, not parsed (1 line(s))", errors);
        Assert.Contains("u_in260316.log: IIS log in IIS native format, not parsed", errors);
        Assert.Contains("old-logs.zip: archived logs, not read", errors);
    }

    [Fact]
    public void ANSI_logs_are_read_as_Latin1_and_UTF8_logs_with_or_without_a_byte_order_mark()
    {
        using var dir = new TempDirectory();
        var folder = Path.Combine(dir.Path, @"inetpub\logs\LogFiles\W3SVC1");
        Write(folder, "ex260315.log", Header + DefaultFields + Line("10:00:00", "/caf\u00e9.aspx"), Encoding.Latin1);
        Write(folder, "u_ex260316.log", Header + DefaultFields + Line("10:00:00", "/na\u00efve.aspx"), new UTF8Encoding(true));
        Write(folder, "u_ex260317.log", Header + DefaultFields + Line("10:00:00", "/\u00fcber.aspx"));

        var (_, errors, output) = Run(dir.Path);

        Assert.Equal("", errors);
        Assert.Equal(["/caf\u00e9.aspx", "/na\u00efve.aspx", "/\u00fcber.aspx"], Rows(output, IisLogExport.RequestsFile).Select(r => r["UriStem"]));
    }

    [Fact]
    public void A_field_logged_twice_keeps_the_first_and_custom_fields_go_to_Extra()
    {
        using var dir = new TempDirectory();
        Write(dir.Path, @"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log",
            Header + "#Fields: date time c-ip cs-uri-stem sc-status c-ip cs(X-Forwarded-For) x-original-host cs(Cookie)\r\n"
            + "2026-03-16 10:00:00 192.0.2.250 /a.aspx 200 192.0.2.251 203.0.113.9,192.0.2.250 portal.example.test ASP.NET_SessionId=abc\r\n");

        var (_, errors, output) = Run(dir.Path);

        Assert.Equal("", errors);
        var row = Rows(output, IisLogExport.RequestsFile).Single();
        Assert.Equal(("192.0.2.250", "203.0.113.9,192.0.2.250"), (row["ClientIP"], row["ForwardedFor"]));
        Assert.Equal("c-ip=192.0.2.251; x-original-host=portal.example.test; cs(cookie)=ASP.NET_SessionId=abc", row["Extra"]);
    }

    [Fact]
    public void A_log_without_date_and_time_keeps_its_rows_with_no_UTC_time_and_says_so()
    {
        using var dir = new TempDirectory();
        Write(dir.Path, @"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log", Header + "#Fields: c-ip cs-uri-stem sc-status\r\n198.51.100.10 /a 200\r\n");

        var (_, errors, output) = Run(dir.Path);

        Assert.Equal("", Rows(output, IisLogExport.RequestsFile).Single()["TimestampUtc"]);
        Assert.Contains("1 row(s) without a readable date and time", errors);
    }

    [Fact]
    public void Without_applicationHost_config_site_names_are_blank_and_nothing_is_reported()
    {
        using var dir = new TempDirectory();
        Write(dir.Path, @"inetpub\logs\LogFiles\W3SVC7\u_ex260316.log", Header + DefaultFields + Line("10:00:00", "/"));

        var (log, errors, output) = Run(dir.Path);

        Assert.Equal("", errors);
        Assert.Contains("site names and physical paths are left blank", log);
        Assert.Equal(("7", ""), (Rows(output, IisLogExport.RequestsFile).Single()["SiteId"], Rows(output, IisLogExport.RequestsFile).Single()["SiteName"]));
        Assert.False(File.Exists(Path.Combine(output, IisLogExport.SitesFile)));
    }

    [Fact]
    public void Log_folders_the_configuration_names_are_read_on_the_system_drive_and_reported_elsewhere()
    {
        using var dir = new TempDirectory();
        Write(dir.Path, @"Windows\System32\inetsrv\config\applicationHost.config",
            "<configuration><system.applicationHost><sites>"
            + "<site name=\"Intranet\" id=\"4\"><application path=\"/\"><virtualDirectory path=\"/\" physicalPath=\"C:\\Sites\\Intranet\" /></application>"
            + "<logFile directory=\"C:\\WebLogs\" /></site>"
            + "<site name=\"Archive\" id=\"5\"><logFile directory=\"E:\\IISLogs\" /></site>"
            + "<site name=\"Old\" id=\"6\"><logFile directory=\"%SystemDrive%\\OldLogs\" logFormat=\"NCSA\" /></site>"
            + "</sites></system.applicationHost></configuration>");
        Write(dir.Path, @"WebLogs\W3SVC4\u_ex260316.log", Header + DefaultFields + Line("10:00:00", "/intranet.aspx"));
        Write(dir.Path, @"Windows\System32\LogFiles\W3SVC1\ex260316.log", Header + DefaultFields + Line("11:00:00", "/iis6.asp"));

        var (_, errors, output) = Run(dir.Path);

        var rows = Rows(output, IisLogExport.RequestsFile);
        Assert.Equal(["/iis6.asp", "/intranet.aspx"], rows.Select(r => r["Url"]).Order(StringComparer.Ordinal));
        Assert.Equal("Intranet", rows.Single(r => r["SiteId"] == "4")["SiteName"]);
        Assert.Contains(@"applicationHost.config logs to E:\IISLogs: it is on another volume (E:), not this collection's root; not read.", errors);
        Assert.Contains(@"applicationHost.config logs to %SystemDrive%\OldLogs, which is not in the collection.", errors);
        Assert.Contains("Site Old (6) logs in NCSA format, which is not parsed.", errors);
    }

    [Fact]
    public void A_collection_with_only_the_configuration_gives_the_site_list_and_reports_nothing()
    {
        using var dir = new TempDirectory();
        Write(dir.Path, @"Windows\System32\inetsrv\config\applicationHost.config",
            "<configuration><system.applicationHost><sites><site name=\"Default Web Site\" id=\"1\"><application path=\"/\">"
            + "<virtualDirectory path=\"/\" physicalPath=\"%SystemDrive%\\inetpub\\wwwroot\" /></application></site>"
            + "</sites></system.applicationHost></configuration>");

        var (log, errors, output) = Run(dir.Path);

        Assert.Equal("", errors);
        Assert.Contains("No IIS log folders", log);
        Assert.Equal("Default Web Site", Rows(output, IisLogExport.SitesFile).Single()["SiteName"]);
        Assert.False(File.Exists(Path.Combine(output, IisLogExport.RequestsFile)));
    }

    [Fact]
    public void A_log_the_server_still_has_open_is_read()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, @"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log");
        Write(dir.Path, @"inetpub\logs\LogFiles\W3SVC1\u_ex260316.log", Header + DefaultFields + Line("10:00:00", "/"));

        using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            var (_, errors, output) = Run(dir.Path);
            Assert.Equal("", errors);
            Assert.Single(Rows(output, IisLogExport.RequestsFile));
        }
    }

    [Theory]
    [InlineData("POST", "/aspnet_client/system_web/x.aspx", "c=d2hvYW1p", "200", "WebShell;ScriptPost")]
    [InlineData("GET", "/aspnet_client/system_web/4_0_30319/WebUIValidation.js", "", "200", "")]
    [InlineData("POST", "/images/upload.ashx", "", "200", "ScriptPost")]
    [InlineData("POST", "/images/upload.ashx", "", "404", "")]
    [InlineData("GET", "/images/upload.ashx", "", "200", "")]
    [InlineData("POST", "/Microsoft-Server-ActiveSync/Proxy/default.eas", "Cmd=Sync&User=CORP%5Calice", "200", "")]
    [InlineData("GET", "/owa/auth/x.js", "", "200", "ExchangeExploit")]
    [InlineData("GET", "/owa/auth/logon.aspx", "url=https%3a%2f%2fmail", "200", "")]
    [InlineData("POST", "/ecp/DDI/DDIService.svc/SetObject", "schema=ResetOABVirtualDirectory", "200", "ExchangeExploit")]
    [InlineData("POST", "/ecp/DDI/DDIService.svc/GetList", "schema=x", "200", "")]
    [InlineData("GET", "/cmd.aspx", "cmd=whoami", "200", "WebShell")]
    public void IIS_flags_name_the_reason_and_leave_the_near_misses(string method, string stem, string query, string status, string expected)
    {
        var url = query.Length > 0 ? stem + "?" + query : stem;
        Assert.Equal(expected, IisLogExport.Flags(method, url, stem, status, "Mozilla/5.0"));
    }

    [Fact]
    public void An_Exchange_backend_cookie_is_flagged()
    {
        Assert.Equal("ExchangeExploit", IisLogExport.Flags("POST", "/ecp/y.ecp", "/ecp/y.ecp", "200", "Mozilla/5.0",
            "X-BEResource=localhost/EWS/Exchange.asmx?a=~1942062522"));
        Assert.Equal("", IisLogExport.Flags("POST", "/ecp/y.ecp", "/ecp/y.ecp", "200", "Mozilla/5.0", "X-BackEndCookie=abc"));
    }
}
