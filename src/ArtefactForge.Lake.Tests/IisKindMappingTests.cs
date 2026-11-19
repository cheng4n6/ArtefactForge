using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

/// <summary>
/// The windows.iis kind: ArtefactForge's IisLogs_Requests.csv (the WindowsIisLogs module) into the
/// timeline's web columns. Made-up rows with the module's own header.
/// </summary>
public class IisKindMappingTests
{
    private static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    // IisLogExport.RequestColumns, as the module writes them.
    private static readonly string[] Header =
    [
        "TimestampUtc", "RawTime", "Service", "SiteId", "SiteName", "ServerName", "ServerIP", "ServerPort", "Method",
        "UriStem", "UriQuery", "Url", "Host", "Protocol", "Status", "SubStatus", "Win32Status", "BytesSent",
        "BytesReceived", "TimeTakenMs", "ClientIP", "ForwardedFor", "User", "UserAgent", "Referer", "Flags", "Extra",
        "SourceFile", "Line"
    ];

    [Fact]
    public void Requests_map_to_the_web_columns_with_the_forwarded_client_and_the_host_header()
    {
        using var temp = new TempDirectory();
        temp.Write(@"WEB01\WebLogs\IisLogs_Requests.csv", Csv(Header,
            new()
            {
                ["TimestampUtc"] = "2026-03-16 08:11:10", ["RawTime"] = "2026-03-16 08:11:10", ["Service"] = "W3SVC",
                ["SiteId"] = "1", ["SiteName"] = "Default Web Site", ["ServerIP"] = "192.0.2.10", ["ServerPort"] = "443",
                ["Method"] = "POST", ["UriStem"] = "/aspnet_client/system_web/errorpage.aspx", ["UriQuery"] = "c=d2hvYW1p",
                ["Url"] = "/aspnet_client/system_web/errorpage.aspx?c=d2hvYW1p", ["Host"] = "www.example.test",
                ["Status"] = "200", ["BytesSent"] = "512", ["BytesReceived"] = "2048", ["ClientIP"] = "192.0.2.250",
                ["ForwardedFor"] = "203.0.113.66, 192.0.2.250", ["User"] = @"CORP\alice", ["UserAgent"] = "Mozilla/5.0 (compatible)",
                ["Flags"] = "WebShell;ScriptPost"
            },
            new()
            {
                ["TimestampUtc"] = "2026-03-16 09:00:00", ["Service"] = "W3SVC", ["SiteId"] = "2", ["SiteName"] = "Exchange Back End",
                ["Method"] = "GET", ["UriStem"] = "/owa/", ["Url"] = "/owa/", ["Status"] = "302", ["ClientIP"] = "198.51.100.10"
            },
            // No time (a custom log without date and time): kept raw, not in the timeline.
            new() { ["Service"] = "W3SVC", ["SiteId"] = "3", ["Method"] = "GET", ["Url"] = "/", ["Status"] = "200" }));

        var result = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false });
        using var lake = OpenLake(result.DatabasePath!);
        var rows = Rows(lake, "SELECT * FROM timeline WHERE kind = 'windows.iis' ORDER BY ts");

        Assert.Equal(2, rows.Count);
        var shell = rows[0];
        Assert.Equal(("web", "request", "windows"), ((string)shell["category"]!, (string)shell["action"]!, (string)shell["platform"]!));
        Assert.Equal("203.0.113.66", shell["src_ip"]);
        Assert.Equal(("192.0.2.10", 443), ((string)shell["dst_ip"]!, (int)shell["dst_port"]!));
        Assert.Equal("www.example.test", shell["domain"]);
        Assert.Equal(("CORP", "alice"), ((string)shell["user_domain"]!, (string)shell["user_name"]!));
        Assert.Equal(("POST", 200), ((string)shell["http_method"]!, (int)shell["http_status"]!));
        Assert.Equal("/aspnet_client/system_web/errorpage.aspx?c=d2hvYW1p", shell["url"]);
        Assert.Equal(("/aspnet_client/system_web/errorpage.aspx", "errorpage.aspx", ".aspx"),
                     ((string)shell["path"]!, (string)shell["file_name"]!, (string)shell["extension"]!));
        Assert.Equal((2048L, 512L), ((long)shell["bytes_in"]!, (long)shell["bytes_out"]!));
        Assert.Contains("[WebShell;ScriptPost]", (string)shell["summary"]!);

        // No forwarded address or Host header: the client and the site's name.
        Assert.Equal(("198.51.100.10", "Exchange Back End"), ((string)rows[1]["src_ip"]!, (string)rows[1]["domain"]!));
        Assert.Null(rows[1]["user_name"]);

        Assert.Equal(1L, Scalar(lake, "SELECT time_unread FROM sources WHERE kind = 'windows.iis'") is long n ? n : -1L);
        Assert.Equal(3L, Scalar(lake, "SELECT count(*) FROM raw_windows_iis"));
    }
}
