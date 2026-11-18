using System.Text;
using ArtefactForge.Lake.Contract;
using DuckDB.NET.Data;

namespace ArtefactForge.Lake.Tests;

/// <summary>A throwaway directory tree for tests that need real files on disk.</summary>
public sealed class TempDirectory : IDisposable
{
    public string Path { get; } =
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "af-lake-test-" + Guid.NewGuid().ToString("N")[..8]);

    public TempDirectory() => Directory.CreateDirectory(Path);

    /// <summary>Writes a file, creating the folders above it. Returns the full path.</summary>
    public string Write(string relativePath, string content, bool byteOrderMark = false)
    {
        var full = System.IO.Path.Combine(Path, relativePath);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content, new UTF8Encoding(byteOrderMark));
        return full;
    }

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); }
        catch { /* a leaked temp folder is not worth failing a test over */ }
    }
}

/// <summary>
/// Small made-up parser output with the real tools' headers (EvtxECmd, PECmd, MFTECmd as of
/// 2026), for host HOST01 and user alice. No evidence.
/// </summary>
public static class Fixtures
{
    public static readonly string[] EvtxHeader =
    [
        "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "ProcessId",
        "ThreadId", "Computer", "ChunkNumber", "UserId", "MapDescription", "UserName", "RemoteHost",
        "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6",
        "ExecutableInfo", "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload"
    ];

    public static readonly string[] MftHeader =
    [
        "EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber", "ParentSequenceNumber", "ParentPath",
        "FileName", "Extension", "FileSize", "ReferenceCount", "ReparseTarget", "IsDirectory", "HasAds", "IsAds",
        "SI<FN", "uSecZeros", "Copied", "SiFlags", "NameType", "Created0x10", "Created0x30", "LastModified0x10",
        "LastModified0x30", "LastRecordChange0x10", "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30",
        "UpdateSequenceNumber", "LogfileSequenceNumber", "SecurityId", "ObjectIdFileDroid", "LoggedUtilStream",
        "ZoneIdContents", "SourceFile"
    ];

    public static readonly string[] UsnHeader =
    [
        "Name", "Extension", "EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber",
        "ParentPath", "UpdateSequenceNumber", "UpdateTimestamp", "UpdateReasons", "FileAttributes", "OffsetToData",
        "SourceFile"
    ];

    public static readonly string[] PecmdOutputHeader =
    [
        "Note", "SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed", "ExecutableName", "Hash",
        "Size", "Version", "RunCount", "LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3",
        "PreviousRun4", "PreviousRun5", "PreviousRun6", "Volume0Name", "Volume0Serial", "Volume0Created",
        "Volume1Name", "Volume1Serial", "Volume1Created", "Directories", "FilesLoaded", "ParsingError"
    ];

    /// <summary>A CSV with <paramref name="header"/> and one line per row; missing fields are empty.</summary>
    public static string Csv(string[] header, params Dictionary<string, string>[] rows)
    {
        var text = new StringBuilder();
        text.Append(string.Join(',', header)).Append("\r\n");
        foreach (var row in rows)
            text.Append(string.Join(',', header.Select(h => Quote(row.GetValueOrDefault(h, ""))))).Append("\r\n");
        return text.ToString();
    }

    private static string Quote(string value) =>
        value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;

    /// <summary>A network logon of alice from 10.0.0.5, and a service install, as EvtxECmd writes them.</summary>
    public static string EvtxCsv() => Csv(EvtxHeader,
        new()
        {
            ["RecordNumber"] = "1", ["EventRecordId"] = "101", ["TimeCreated"] = "2026-11-01 09:15:30.1234567",
            ["EventId"] = "4624", ["Level"] = "LogAlways", ["Provider"] = "Microsoft-Windows-Security-Auditing",
            ["Channel"] = "Security", ["ProcessId"] = "640", ["Computer"] = "HOST01",
            ["MapDescription"] = "Successful logon", ["UserName"] = "-\\-", ["RemoteHost"] = "WKS02 (10.0.0.5)",
            ["PayloadData1"] = "Target: CORP\\alice", ["PayloadData2"] = "LogonType 3",
            ["ExecutableInfo"] = "", ["SourceFile"] = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            ["Payload"] = "{\"EventData\":{}}"
        },
        new()
        {
            ["RecordNumber"] = "2", ["EventRecordId"] = "55", ["TimeCreated"] = "2026-11-01 09:20:00.0000000",
            ["EventId"] = "7045", ["Level"] = "Info", ["Provider"] = "Service Control Manager", ["Channel"] = "System",
            ["ProcessId"] = "700", ["Computer"] = "HOST01", ["UserId"] = "S-1-5-21-1000-1000-1000-1001",
            ["MapDescription"] = "A new service was installed in the system", ["PayloadData1"] = "Name: updater",
            ["ExecutableInfo"] = "\"C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe\" -svc",
            ["SourceFile"] = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx"
        });

    public static string PecmdTimelineCsv() =>
        "RunTime,ExecutableName\r\n" +
        "2026-11-01 09:21:00,\\VOLUME{01d7ebc2658a22b2-7465b7bc}\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\UPDATER.EXE\r\n" +
        "2026-11-01 08:00:00,\\VOLUME{01d7ebc2658a22b2-7465b7bc}\\WINDOWS\\SYSTEM32\\CMD.EXE\r\n";

    public static string PecmdOutputCsv() => Csv(PecmdOutputHeader, new Dictionary<string, string>
    {
        ["SourceFilename"] = "C:\\Windows\\Prefetch\\UPDATER.EXE-1A2B3C4D.pf", ["SourceCreated"] = "2026-11-01 09:21:05",
        ["ExecutableName"] = "UPDATER.EXE", ["Hash"] = "1A2B3C4D", ["RunCount"] = "2",
        ["LastRun"] = "2026-11-01 09:21:00", ["PreviousRun0"] = "2026-11-01 09:20:10",
        ["FilesLoaded"] = "\\VOLUME{01d7ebc2658a22b2-7465b7bc}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, " +
                          "\\VOLUME{01d7ebc2658a22b2-7465b7bc}\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\UPDATER.EXE"
    });

    /// <summary>updater.exe created then modified, and a folder whose two times are the same.</summary>
    public static string MftCsv() => Csv(MftHeader,
        new()
        {
            ["EntryNumber"] = "5001", ["SequenceNumber"] = "3", ["InUse"] = "True",
            ["ParentPath"] = ".\\Users\\alice\\AppData\\Local\\Temp", ["FileName"] = "updater.exe",
            ["Extension"] = ".exe", ["FileSize"] = "73728", ["IsDirectory"] = "False",
            ["Created0x10"] = "2026-11-01 09:19:58.1000000", ["LastModified0x10"] = "2026-11-01 09:19:59.2000000",
            ["LastRecordChange0x10"] = "2026-11-01 09:19:59.2000000", ["LastAccess0x10"] = "2026-11-01 09:19:59.2000000",
            ["SourceFile"] = "C:\\$MFT"
        },
        new()
        {
            ["EntryNumber"] = "5000", ["SequenceNumber"] = "1", ["InUse"] = "True",
            ["ParentPath"] = ".\\Users\\alice\\AppData\\Local", ["FileName"] = "Temp", ["FileSize"] = "0",
            ["IsDirectory"] = "True", ["Created0x10"] = "2025-01-01 00:00:00.0000000",
            ["LastModified0x10"] = "2025-01-01 00:00:00.0000000",
            ["LastRecordChange0x10"] = "2025-01-01 00:00:00.0000000", ["LastAccess0x10"] = "2025-01-01 00:00:00.0000000",
            ["SourceFile"] = "C:\\$MFT"
        });

    public static string UsnCsv() => Csv(UsnHeader, new Dictionary<string, string>
    {
        ["Name"] = "report.docx.lockbit", ["Extension"] = ".lockbit", ["EntryNumber"] = "6000", ["SequenceNumber"] = "2",
        ["ParentPath"] = ".\\Users\\alice\\Documents", ["UpdateSequenceNumber"] = "4096",
        ["UpdateTimestamp"] = "2026-11-01 09:30:00.5000000", ["UpdateReasons"] = "RenameNewName",
        ["FileAttributes"] = "Archive", ["SourceFile"] = "C:\\$Extend\\$J"
    });

    /// <summary>
    /// A host folder as ArtefactForge writes it: the parser CSVs and an outputs.json listing them,
    /// plus one entry whose module failed.
    /// </summary>
    public static void WriteArtefactForgeHost(TempDirectory temp, string host)
    {
        temp.Write($@"{host}\EventLogs\EvtxECmd_EventLogs.csv", EvtxCsv(), byteOrderMark: true);
        temp.Write($@"{host}\Prefetch\PECmd_Output_Timeline.csv", PecmdTimelineCsv());
        temp.Write($@"{host}\Prefetch\PECmd_Output.csv", PecmdOutputCsv());
        temp.Write($@"{host}\FileSystem\MFTECmd_MFT.csv", MftCsv(), byteOrderMark: true);
        temp.Write($@"{host}\FileSystem\MFTECmd_USNJournal.csv", UsnCsv(), byteOrderMark: true);
        temp.Write($@"{host}\LNKFiles\alice\alice_LECmd_Recent.csv",
            "SourceFile,SourceCreated,TargetCreated,LocalPath\r\nC:\\Users\\alice\\Recent\\a.lnk,2026-11-01 09:00:00,2026-10-01 10:00:00,C:\\Users\\alice\\Documents\\a.docx\r\n");

        OutputEntry Entry(string path, string parser, string toolFileName, string status = OutputStatus.Completed,
            string? user = null) => new()
            {
                Path = path, Format = Path.GetExtension(path).TrimStart('.'), Parser = parser, ParserVersion = "1.0.0.0",
                ToolFileName = toolFileName, Status = status, User = user
            };

        var manifest = new OutputsManifest
        {
            Producer = new OutputsProducer { Name = "ArtefactForge", Version = "0.6.0", Build = "0.6.0+abc1234" },
            UpdatedUtc = new DateTime(2026, 11, 2, 0, 0, 0, DateTimeKind.Utc),
            Host = new OutputsHost { Name = host, Hostname = host + ".corp.example", Platform = Platforms.Windows },
            Outputs =
            [
                Entry("EventLogs/EvtxECmd_EventLogs.csv", "EvtxECmd", "EvtxECmd_EventLogs.csv"),
                Entry("Prefetch/PECmd_Output_Timeline.csv", "PECmd", "20261101100301_PECmd_Output_Timeline.csv"),
                Entry("Prefetch/PECmd_Output.csv", "PECmd", "20261101100301_PECmd_Output.csv"),
                Entry("FileSystem/MFTECmd_MFT.csv", "MFTECmd", "MFTECmd_MFT.csv"),
                Entry("FileSystem/MFTECmd_USNJournal.csv", "MFTECmd", "MFTECmd_USNJournal.csv"),
                Entry("LNKFiles/alice/alice_LECmd_Recent.csv", "LECmd", "20261101100301_LECmd_Recent.csv", user: "alice"),
                Entry("Amcache/AmcacheParser_Output.csv", "AmcacheParser", "Amcache_Output.csv", OutputStatus.Failed)
            ]
        };
        OutputsManifestFile.Write(OutputsManifestFile.PathIn(Path.Combine(temp.Path, host)), manifest);
    }

    /// <summary>Opens a built lake read-only.</summary>
    public static DuckDBConnection OpenLake(string path)
    {
        var connection = new DuckDBConnection($"Data Source={path};ACCESS_MODE=READ_ONLY");
        connection.Open();
        return connection;
    }

    public static object? Scalar(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        var value = command.ExecuteScalar();
        return value is DBNull ? null : value;
    }

    /// <summary>The rows of a query, each as column name to value.</summary>
    public static List<Dictionary<string, object?>> Rows(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        var rows = new List<Dictionary<string, object?>>();
        while (reader.Read())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }
}
