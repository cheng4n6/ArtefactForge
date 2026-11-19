using ArtefactForge.Lake.Queries;
using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

/// <summary>
/// The webshell_requests saved query on a made-up IIS server: a script dropped under aspnet_client,
/// POSTed to, with w3wp.exe starting cmd.exe right after; the site's own page, which must not be
/// listed; a script in a static folder nobody requested; and a flagged POST to a script that is no
/// longer on disk. Made-up host, addresses and files.
/// </summary>
public class WebshellQueryTests
{
    private static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    private static readonly string[] RequestHeader =
    [
        "TimestampUtc", "RawTime", "Service", "SiteId", "SiteName", "ServerName", "ServerIP", "ServerPort", "Method",
        "UriStem", "UriQuery", "Url", "Host", "Protocol", "Status", "SubStatus", "Win32Status", "BytesSent",
        "BytesReceived", "TimeTakenMs", "ClientIP", "ForwardedFor", "User", "UserAgent", "Referer", "Flags", "Extra",
        "SourceFile", "Line"
    ];

    private static readonly string[] SiteHeader =
    [
        "SiteId", "SiteName", "Bindings", "Application", "VirtualPath", "PhysicalPath", "CollectionPath",
        "LogDirectory", "LogFormat", "LogFields", "LocalTimeRollover"
    ];

    private static Dictionary<string, string> Request(string time, string method, string stem, string status, string client,
                                                      string flags = "", string bytesIn = "300") => new()
    {
        ["TimestampUtc"] = time, ["RawTime"] = time, ["Service"] = "W3SVC", ["SiteId"] = "1", ["SiteName"] = "Default Web Site",
        ["ServerIP"] = "192.0.2.10", ["ServerPort"] = "443", ["Method"] = method, ["UriStem"] = stem, ["Url"] = stem,
        ["Status"] = status, ["BytesReceived"] = bytesIn, ["ClientIP"] = client, ["Flags"] = flags
    };

    private static Dictionary<string, string> File(int entry, string parent, string name, string created) => new()
    {
        ["EntryNumber"] = entry.ToString(), ["SequenceNumber"] = "1", ["InUse"] = "True", ["ParentEntryNumber"] = "5",
        ["ParentSequenceNumber"] = "5", ["ParentPath"] = parent, ["FileName"] = name, ["Extension"] = Path.GetExtension(name),
        ["FileSize"] = "2048", ["IsDirectory"] = "False", ["NameType"] = "Windows", ["Created0x10"] = created + ".0000000",
        ["LastModified0x10"] = created + ".0000000", ["SourceFile"] = @"C:\evidence\C\$MFT"
    };

    private static Dictionary<string, string> ProcessStart(string time, string image, string parent) => new()
    {
        ["RecordNumber"] = "1", ["EventRecordId"] = "1", ["TimeCreated"] = time + ".0000000", ["EventId"] = "4688",
        ["Channel"] = "Security", ["Provider"] = "Microsoft-Windows-Security-Auditing", ["Computer"] = "WEB01",
        ["ExecutableInfo"] = image, ["SourceFile"] = "Security.evtx",
        ["Payload"] = "{\"EventData\":{\"Data\":[{\"@Name\":\"NewProcessName\",\"#text\":\"" + image.Replace("\\", "\\\\")
                      + "\"},{\"@Name\":\"ParentProcessName\",\"#text\":\"" + parent.Replace("\\", "\\\\") + "\"}]}}"
    };

    private const string W3wp = @"C:\Windows\System32\inetsrv\w3wp.exe";

    private static string Case(TempDirectory temp, bool siteList = true)
    {
        if (siteList)
            temp.Write(@"WEB01\WebLogs\IisLogs_Sites.csv", Csv(SiteHeader, new Dictionary<string, string>
            {
                ["SiteId"] = "1", ["SiteName"] = "Default Web Site", ["Application"] = "/", ["VirtualPath"] = "/",
                ["PhysicalPath"] = @"C:\inetpub\wwwroot", ["CollectionPath"] = "inetpub/wwwroot", ["LogFormat"] = "W3C"
            }));
        temp.Write(@"WEB01\WebLogs\IisLogs_Requests.csv", Csv(RequestHeader,
            Request("2026-03-16 08:00:00", "GET", "/about.aspx", "200", "198.51.100.10"),
            Request("2026-03-16 08:05:00", "POST", "/about.aspx", "200", "198.51.100.11"),
            Request("2026-03-16 08:11:10", "POST", "/aspnet_client/system_web/errorpage.aspx", "200", "203.0.113.66", "WebShell;ScriptPost", "512"),
            Request("2026-03-16 08:11:40", "POST", "/aspnet_client/system_web/errorpage.aspx", "200", "203.0.113.66", "WebShell;ScriptPost", "640"),
            Request("2026-03-16 09:00:00", "POST", "/uploads/gone.ashx", "200", "203.0.113.67", "ScriptPost")));
        temp.Write(@"WEB01\FileSystem\MFTECmd_MFT.csv", Csv(MftHeader,
            File(100, @".\inetpub\wwwroot", "about.aspx", "2025-01-10 12:00:00"),
            File(101, @".\inetpub\wwwroot\aspnet_client\system_web", "errorpage.aspx", "2026-03-16 08:10:40"),
            File(102, @".\inetpub\wwwroot\images", "thumb.aspx", "2026-03-15 22:00:00"),
            File(103, @".\inetpub\wwwroot\images", "logo.png", "2025-01-10 12:00:00"),
            File(104, @".\Users\alice\Documents", "notes.aspx", "2026-03-16 08:00:00")));
        temp.Write(@"WEB01\EventLogs\EvtxECmd_EventLogs.csv", Csv(EvtxHeader,
            ProcessStart("2026-03-16 08:11:12", @"C:\Windows\System32\cmd.exe", W3wp),
            ProcessStart("2026-03-16 08:11:42", @"C:\Windows\System32\cmd.exe", W3wp),
            ProcessStart("2026-03-16 08:11:43", @"C:\Windows\System32\whoami.exe", @"C:\Windows\System32\cmd.exe"),
            // Not w3wp's, and outside the window: neither counts.
            ProcessStart("2026-03-16 08:11:15", @"C:\Windows\System32\notepad.exe", @"C:\Windows\explorer.exe"),
            ProcessStart("2026-03-16 08:30:00", @"C:\Windows\System32\net.exe", W3wp)));
        return LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false }).DatabasePath!;
    }

    private static List<Dictionary<string, string>> Run(string database, string caseDir, Dictionary<string, string>? parameters = null)
    {
        using var session = new LakeQuerySession(database, caseDir, parameters);
        return session.RunToRows(LakeQueryCatalogue.Find("webshell_requests")!);
    }

    [Fact]
    public void The_dropped_script_its_requests_and_what_w3wp_started_are_listed_and_the_sites_own_page_is_not()
    {
        using var temp = new TempDirectory();
        var rows = Run(Case(temp), temp.Path);

        Assert.Equal(["/aspnet_client/system_web/errorpage.aspx", "/uploads/gone.ashx", "/images/thumb.aspx"], rows.Select(r => r["Url"]));

        var shell = rows[0];
        Assert.Equal(("WEB01", "Default Web Site", @"\inetpub\wwwroot\aspnet_client\system_web\errorpage.aspx"),
                     (shell["Host"], shell["Site"], shell["ScriptPath"]));
        Assert.Equal(("2026-03-16 08:10:40", "MFT"), (shell["FileCreatedUtc"], shell["FileSource"]));
        Assert.Equal(("2026-03-16 08:11:10", "2026-03-16 08:11:40", "2", "2"),
                     (shell["FirstRequestUtc"], shell["LastRequestUtc"], shell["Requests"], shell["Posts200"]));
        Assert.Equal(("203.0.113.66", "1152"), (shell["ClientIPs"], shell["BytesReceived"]));
        Assert.Equal(("cmd.exe (2)", "2026-03-16 08:11:12"), (shell["ChildProcesses"], shell["FirstChildUtc"]));
        Assert.Contains("w3wp.exe started 2 process(es) within 120 s", shell["Detail"]);
        Assert.Contains("requests flagged WebShell;ScriptPost", shell["Detail"]);
        Assert.Contains("static files", shell["Detail"]);

        var gone = rows[1];
        Assert.Equal(("", "1", "203.0.113.67"), (gone["ScriptPath"], gone["Posts200"], gone["ClientIPs"]));
        Assert.Contains("no file for this URL", gone["Detail"]);

        var untouched = rows[2];
        Assert.Equal(("0", ""), (untouched["Requests"], untouched["FirstRequestUtc"]));
        Assert.Equal("in a folder that normally holds only static files", untouched["Detail"]);

        // The site's own page (requested, even POSTed to, nothing flagged) and a script outside every web root.
        Assert.DoesNotContain(rows, r => r["Url"] == "/about.aspx" || r["ScriptPath"].Contains("notes.aspx"));
    }

    [Fact]
    public void Without_a_site_list_inetpub_wwwroot_is_the_web_root()
    {
        using var temp = new TempDirectory();
        var rows = Run(Case(temp, siteList: false), temp.Path);

        var shell = rows.Single(r => r["Url"] == "/aspnet_client/system_web/errorpage.aspx");
        Assert.Equal(("", "cmd.exe (2)"), (shell["Site"], shell["ChildProcesses"]));
    }

    [Fact]
    public void A_shorter_window_counts_only_what_started_within_it()
    {
        using var temp = new TempDirectory();
        var database = Case(temp);

        var tight = Run(database, temp.Path, new Dictionary<string, string> { ["window_seconds"] = "1" });
        Assert.Equal("", tight.Single(r => r["Url"] == "/aspnet_client/system_web/errorpage.aspx")["ChildProcesses"]);

        var wide = Run(database, temp.Path, new Dictionary<string, string> { ["window_seconds"] = "3600" });
        Assert.Equal("cmd.exe (2), net.exe (1)", wide.Single(r => r["Url"] == "/aspnet_client/system_web/errorpage.aspx")["ChildProcesses"]);
    }

    [Fact]
    public void A_lake_with_no_IIS_output_runs_the_query_and_lists_nothing()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Prefetch\PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        var database = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false }).DatabasePath!;

        Assert.Empty(Run(database, temp.Path));
    }
}
