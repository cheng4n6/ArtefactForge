using ArtefactForge.Lake.Cli;
using ArtefactForge.Lake.Queries;
using static ArtefactForge.Lake.Tests.Fixtures;

namespace ArtefactForge.Lake.Tests;

/// <summary>
/// The IOC sweep queries' pieces: the allrows view, the type labels, which columns hold hashes and
/// times, and the af-lake ioc command. Parity with the C# sweep, hit for hit, is checked in
/// ArtefactForge.Tests (IocLakeParityTests). Made-up hosts and values.
/// </summary>
public class IocQueryTests
{
    private static readonly LakeOptions Small = new() { MemoryLimitBytes = 512L * 1024 * 1024, Threads = 2 };

    private static (TempDirectory Temp, LakeQuerySession Session) Prepared(string list = "Type,Value\r\nIP,10.0.0.1\r\n")
    {
        var temp = new TempDirectory();
        temp.Write(@"HOST01\EventLogs\EvtxECmd_EventLogs.csv", EvtxCsv());
        temp.Write(@"HOST01\Tools\Tool.csv", "Text,When\r\nconnect 10.0.0.1,2026-11-01 10:00:00\r\n");
        temp.Write("IocHits.csv", "IocType,Ioc,Host,Module,Time,OutputFile,LineNumber,MatchingLine\r\nIP,10.0.0.1,HOST01,x,,f,2,10.0.0.1\r\n");
        temp.Write("IOCs.csv", list);
        var result = LakeBuilder.Build(temp.Path, Small with { RunAnalyses = false });
        var session = new LakeQuerySession(result.DatabasePath!, temp.Path);
        session.RunToRows(LakeQueryCatalogue.Find("ioc_list")!);
        return (temp, session);
    }

    private static object? Eval(LakeQuerySession session, string expression)
    {
        using var command = session.CreateCommand();
        command.CommandText = "SELECT " + expression;
        return command.ExecuteScalar();
    }

    [Fact]
    public void The_allrows_view_holds_every_hosts_rows_with_their_column_names_and_none_of_the_cases_own()
    {
        var (temp, session) = Prepared();
        using (temp) using (session)
        {
            Assert.Equal(3L, Eval(session, "count(*) FROM ioc_lake_rows"));
            Assert.Equal(0L, Eval(session, "count(*) FROM ioc_lake_rows WHERE host = '(case)'"));
            Assert.Equal("Text,When", Eval(session, "array_to_string(names, ',') FROM ioc_lake_rows WHERE raw_table LIKE '%tool%'"));
            Assert.Equal("connect 10.0.0.1|2026-11-01 10:00:00",
                         Eval(session, "array_to_string(cells, '|') FROM ioc_lake_rows WHERE raw_table LIKE '%tool%'"));
        }
    }

    [Theory]
    [InlineData("File name", "FileName")]
    [InlineData("file-path", "Path")]
    [InlineData("SHA-256", "Hash")]
    [InlineData("IP address", "IP")]
    [InlineData("FQDN", "Domain")]
    [InlineData("E-mail", "Account")]
    [InlineData("Registry key", null)]
    public void Type_labels_are_read_the_way_the_IOC_list_reads_them(string label, string? type)
    {
        var (temp, session) = Prepared();
        using (temp) using (session)
            Assert.Equal(type, Eval(session, $"ioc_type('{label}')") as string);
    }

    [Theory]
    [InlineData("SHA1", true)]
    [InlineData("SHA-256", true)]
    [InlineData("Hashes", true)]
    [InlineData("md5sum", true)]
    [InlineData("sha", true)]
    [InlineData("Shadow", false)]
    [InlineData("SharedPath", false)]
    public void Hash_columns_are_named_as_the_sweep_names_them(string name, bool hash)
    {
        var (temp, session) = Prepared();
        using (temp) using (session)
            Assert.Equal(hash, Eval(session, $"ioc_hash_column('{name}')"));
    }

    [Theory]
    [InlineData("TimeCreated", true)]
    [InlineData("LastWriteTime", true)]
    [InlineData("CreationDate", true)]
    [InlineData("TimeZone", false)]
    [InlineData("LastWritten", false)]
    public void Time_columns_are_named_as_the_sweep_names_them(string name, bool time)
    {
        var (temp, session) = Prepared();
        using (temp) using (session)
            Assert.Equal(time, Eval(session, $"ioc_time_column('{name}')"));
    }

    [Fact]
    public void A_path_is_looked_for_with_either_separator_doubled_backslashes_and_without_its_drive()
    {
        var (temp, session) = Prepared("Type,Value\r\nPath,C:\\Temp\\evil.exe\r\nAccount,CORP\\bob\r\nIP,10.0.0.1\r\nRegistry,HKLM\\x\r\n");
        using (temp) using (session)
        {
            var forms = session.RunToRows(LakeQueryCatalogue.Find("ioc_list")!);
            Assert.Equal(3, forms.Count);   // the unknown type is listed but not looked for
            Assert.Equal(@"/Temp/evil.exe | C:/Temp/evil.exe | C:\Temp\evil.exe | C:\\Temp\\evil.exe | \Temp\evil.exe | \\Temp\\evil.exe",
                         forms[0]["Forms"]);
            Assert.Equal(@"CORP\\bob | CORP\bob", forms[1]["Forms"]);
        }
    }

    [Fact]
    public void The_command_writes_IocHits_and_says_when_the_case_has_no_list()
    {
        using var temp = new TempDirectory();
        temp.Write(@"HOST01\Tools\Tool.csv", "Text,EventTime\r\nconnect 10.0.0.1,2026-11-01 10:00:00\r\n");
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["build", temp.Path, "--memory-gb", "0.5", "--threads", "2"], new StringWriter(), new StringWriter()));

        var output = new StringWriter();
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["ioc", temp.Path], output, new StringWriter()));
        Assert.Contains("no IOCs.csv in the case", output.ToString());

        temp.Write("IOCs.csv", "Type,Value\r\nIP,10.0.0.1\r\n");
        Assert.Equal(LakeCli.ExitBuilt, LakeCli.Run(["ioc", temp.Path], new StringWriter(), new StringWriter()));
        var path = Path.Combine(temp.Path, "_Lake", "results", "IOC", "IocHits.csv");
        Assert.Equal([0xEF, 0xBB, 0xBF], File.ReadAllBytes(path)[..3]);
        var lines = File.ReadAllLines(path);
        Assert.Equal("IocType,Ioc,Host,Module,Time,OutputFile,LineNumber,MatchingLine", lines[0]);
        Assert.Equal(@"IP,10.0.0.1,HOST01,Tools,2026-11-01 10:00:00,HOST01\Tools\Tool.csv,2,""connect 10.0.0.1,2026-11-01 10:00:00""", lines[1]);
    }
}
