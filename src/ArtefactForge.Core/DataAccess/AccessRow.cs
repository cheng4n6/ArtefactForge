using System.Globalization;
using ArtefactForge.Core.Ioc;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Core.DataAccess;

/// <summary>
/// One time a user opened, browsed or reached a file or folder. The host file keeps the SID and
/// the artefact it came from; the case's DataAccess.csv has only the five columns the client gets.
/// </summary>
public sealed record AccessRow(DateTime TimeUtc, string System, string User, string Sid, string Path,
                               string Activity, string Source)
{
    public const string Opened = "Opened";
    public const string FolderBrowsed = "Folder browsed";
    public const string OpenedOrSaved = "Opened or saved via dialog";
    public const string ShareAccessed = "Share accessed";
    public const string AccessedOverShare = "Accessed over share";

    public static readonly string[] HostColumns = ["TimeUtc", "System", "User", "SID", "Path", "Activity", "Source"];
    public static readonly string[] CaseColumns = ["Date/Time (UTC)", "System", "User", "Path", "Activity"];

    /// <summary>Two rows saying the same thing, from two artefacts, are one row in the report.</summary>
    public (DateTime, string, string, string, string) Key =>
        (TimeUtc, System.ToUpperInvariant(), User.ToUpperInvariant(), Path.ToUpperInvariant(), Activity);

    public static void WriteHost(string path, IEnumerable<AccessRow> rows) =>
        AtomicFile.Write(path, writer =>
        {
            Linux.CsvFile.WriteRow(writer, HostColumns);
            foreach (var r in rows)
                Linux.CsvFile.WriteRow(writer, IpHistoryRecord.Format(r.TimeUtc), r.System, r.User, r.Sid, r.Path, r.Activity, r.Source);
        });

    public static IEnumerable<AccessRow> ReadHost(string path, CancellationToken cancellationToken = default)
    {
        foreach (var cell in CaseUsers.Rows(path, cancellationToken))
        {
            if (IpHistoryRecord.ParseTime(cell("TimeUtc")) is not { } time) continue;
            yield return new AccessRow(time, cell("System"), cell("User"), cell("SID"), cell("Path"), cell("Activity"), cell("Source"));
        }
    }

    public static void WriteCase(string path, IEnumerable<AccessRow> rows) =>
        AtomicFile.Write(path, writer =>
        {
            Linux.CsvFile.WriteRow(writer, CaseColumns);
            foreach (var r in rows)
                Linux.CsvFile.WriteRow(writer, IpHistoryRecord.Format(r.TimeUtc), r.System, r.User, r.Path, r.Activity);
        });

    /// <summary>The number of rows in a written file, without keeping them.</summary>
    public static int Count(string path)
    {
        if (!File.Exists(path)) return 0;
        using var reader = new CsvRecordReader(path);
        var rows = -1;   // the header
        while (reader.ReadRecord() is not null) rows++;
        return Math.Max(rows, 0);
    }

    public override string ToString() =>
        string.Join(" ", TimeUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), System, User, Path, Activity);
}
