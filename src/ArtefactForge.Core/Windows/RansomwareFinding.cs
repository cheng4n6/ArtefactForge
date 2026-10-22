using System.Globalization;
using System.Text;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// One host's ransomware result: a row of the case's Ransomware.csv, and the one row of the
/// host's own Ransomware\RansomwareSummary.csv. Times are UTC.
///
///   Collection          the host's folder in the case
///   Host                the machine's own name where its system summary has it
///   Status              Found, None found, Not checked or Failed
///   Extension           what was added to encrypted files (.lockbit), empty for none
///   ExtensionBasis      Detected, Confirmed (by the analyst, as detected), Override (the
///                       analyst's value) or Swept (confirmed on another host and found here)
///   NoteName            the ransom note's file name
///   NoteBasis           as ExtensionBasis, for the note
///   NoteSize            the size most copies of the note have, in bytes
///   NoteSha256          of the copy saved in the case, when one could be saved
///   NoteCopy            that copy, relative to the case folder
///   NoteFolders         how many folders hold a copy of the note
///   StartUtc            the first file renamed to the extension
///   StartIsEarliestSeen True when the USN journal does not reach back to the start (it had
///                       wrapped, or only the MFT was there), so the start is only the earliest
///                       time found and encryption may have begun before it
///   FinishUtc           the last file renamed to the extension
///   FilesAffected       files with the extension
///   RatePerMinute       files per minute from start to finish
///   PeakPerMinute       the most files in any one minute
///   Source              USN, MFT or "USN and MFT": where the times and counts came from
///   Differences         case level only: where this host differs from the rest of the case
///   Detail              anything else: other candidates, why the start is only the earliest seen
/// </summary>
public sealed record RansomwareFinding
{
    public const string Found = "Found";
    public const string NoneFound = "None found";
    public const string NotChecked = "Not checked";
    public const string FailedStatus = "Failed";

    public const string Detected = "Detected";
    public const string Confirmed = "Confirmed";
    public const string Override = "Override";
    public const string Swept = "Swept";

    public static readonly string[] Columns =
    [
        "Collection", "Host", "Status", "Extension", "ExtensionBasis", "NoteName", "NoteBasis", "NoteSize",
        "NoteSha256", "NoteCopy", "NoteFolders", "StartUtc", "StartIsEarliestSeen", "FinishUtc",
        "FilesAffected", "RatePerMinute", "PeakPerMinute", "Source", "Differences", "Detail"
    ];

    /// <summary>The host summary's extra column: what the result was built with, to tell when it is out of date.</summary>
    internal const string ParametersColumn = "Parameters";

    public required string Collection { get; init; }
    public string Host { get; init; } = "";
    public required string Status { get; init; }
    public string Extension { get; init; } = "";
    public string ExtensionBasis { get; init; } = "";
    public string NoteName { get; init; } = "";
    public string NoteBasis { get; init; } = "";
    public long? NoteSize { get; init; }
    public string NoteSha256 { get; init; } = "";
    public string NoteCopy { get; init; } = "";
    public int NoteFolders { get; init; }
    public DateTime? StartUtc { get; init; }
    public bool StartIsEarliestSeen { get; init; }
    public DateTime? FinishUtc { get; init; }
    public long FilesAffected { get; init; }
    public double? RatePerMinute { get; init; }
    public int? PeakPerMinute { get; init; }
    public string Source { get; init; } = "";
    public string Differences { get; init; } = "";
    public string Detail { get; init; } = "";

    public bool IsFound => Status == Found;

    /// <summary>The one line the app shows for the host.</summary>
    public string Describe()
    {
        if (Status == NotChecked || Status == FailedStatus) return $"{Status}: {Detail}";
        if (!IsFound)
            return "No encrypted files or ransom note found." + (Differences.Length > 0 ? " Differs: " + Differences + "." : "");

        var parts = new List<string>();
        if (Extension.Length > 0) parts.Add($"{Extension} on {FilesAffected:N0} file{(FilesAffected == 1 ? "" : "s")}");
        if (NoteName.Length > 0) parts.Add($"note {NoteName} in {NoteFolders:N0} folder{(NoteFolders == 1 ? "" : "s")}");
        if (StartUtc is not null)
            parts.Add((StartIsEarliestSeen ? "earliest seen " : "from ") + IpHistoryRecord.Format(StartUtc)
                      + (FinishUtc is null ? "" : " to " + IpHistoryRecord.Format(FinishUtc)) + " UTC");
        var line = string.Join(", ", parts) + (Source.Length > 0 ? $" ({Source})." : ".");
        return Differences.Length > 0 ? line + " Differs: " + Differences + "." : line;
    }

    internal string[] ToCells() =>
    [
        Collection, Host, Status, Extension, ExtensionBasis, NoteName, NoteBasis,
        NoteSize?.ToString(CultureInfo.InvariantCulture) ?? "", NoteSha256, NoteCopy,
        NoteFolders > 0 ? NoteFolders.ToString(CultureInfo.InvariantCulture) : "",
        IpHistoryRecord.Format(StartUtc), StartUtc is null ? "" : StartIsEarliestSeen ? "True" : "False",
        IpHistoryRecord.Format(FinishUtc),
        FilesAffected > 0 ? FilesAffected.ToString(CultureInfo.InvariantCulture) : "",
        RatePerMinute?.ToString("0.#", CultureInfo.InvariantCulture) ?? "",
        PeakPerMinute?.ToString(CultureInfo.InvariantCulture) ?? "",
        Source, Differences, Detail
    ];

    /// <summary>Reads a case Ransomware.csv or a host summary. The parameters of a host summary come back too.</summary>
    public static List<RansomwareFinding> Read(string path) => ReadWithParameters(path).Select(r => r.Finding).ToList();

    internal static List<(RansomwareFinding Finding, string Parameters)> ReadWithParameters(string path)
    {
        var rows = new List<(RansomwareFinding, string)>();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return rows;
        var index = header.Select((name, i) => (name, i))
            .GroupBy(p => p.name.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().i, StringComparer.OrdinalIgnoreCase);
        if (!index.ContainsKey("Collection") || !index.ContainsKey("Status"))
            throw new InvalidDataException($"{Path.GetFileName(path)} has no Collection or Status column");

        while (reader.ReadRecord() is { } fields)
        {
            string Cell(string name) => index.TryGetValue(name, out var i) && i < fields.Count ? fields[i].Trim() : "";
            if (Cell("Collection").Length == 0) continue;
            rows.Add((new RansomwareFinding
            {
                Collection = Cell("Collection"),
                Host = Cell("Host"),
                Status = Cell("Status"),
                Extension = Cell("Extension"),
                ExtensionBasis = Cell("ExtensionBasis"),
                NoteName = Cell("NoteName"),
                NoteBasis = Cell("NoteBasis"),
                NoteSize = long.TryParse(Cell("NoteSize"), CultureInfo.InvariantCulture, out var size) ? size : null,
                NoteSha256 = Cell("NoteSha256"),
                NoteCopy = Cell("NoteCopy"),
                NoteFolders = int.TryParse(Cell("NoteFolders"), CultureInfo.InvariantCulture, out var folders) ? folders : 0,
                StartUtc = IpHistoryRecord.ParseTime(Cell("StartUtc")),
                StartIsEarliestSeen = Cell("StartIsEarliestSeen").Equals("True", StringComparison.OrdinalIgnoreCase),
                FinishUtc = IpHistoryRecord.ParseTime(Cell("FinishUtc")),
                FilesAffected = long.TryParse(Cell("FilesAffected"), CultureInfo.InvariantCulture, out var files) ? files : 0,
                RatePerMinute = double.TryParse(Cell("RatePerMinute"), NumberStyles.Float, CultureInfo.InvariantCulture, out var rate) ? rate : null,
                PeakPerMinute = int.TryParse(Cell("PeakPerMinute"), CultureInfo.InvariantCulture, out var peak) ? peak : null,
                Source = Cell("Source"),
                Differences = Cell("Differences"),
                Detail = Cell("Detail")
            }, Cell(ParametersColumn)));
        }
        return rows;
    }

    /// <summary>Writes the rows through a temporary file, with the parameters column when given.</summary>
    internal static void Write(string path, IEnumerable<RansomwareFinding> rows, string? parameters = null)
    {
        var temp = path + ".tmp";
        using (var csv = new StreamWriter(temp, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            CsvFile.WriteRow(csv, parameters is null ? Columns : [.. Columns, ParametersColumn]);
            foreach (var row in rows)
                CsvFile.WriteRow(csv, parameters is null ? row.ToCells() : [.. row.ToCells(), parameters]);
        }
        File.Move(temp, path, overwrite: true);
    }
}

/// <summary>
/// One row of a host's Ransomware\RansomwareEvidence.csv: a file behind the finding.
///
///   Kind          Renamed (a USN rename to the extension), Encrypted file (an MFT entry with the
///                 extension) or Ransom note (an MFT entry with the note's name)
///   TimeUtc       the rename, or the MFT entry's last record change (a note: its creation)
///   Path          the folder, as MFTECmd gives it (.\Users\alice\Documents)
///   Name          the file name
///   PreviousName  the name before the rename
///   Size          from the MFT
///   InUse         False for an MFT entry that has been deleted
///   Source        USN or MFT
/// </summary>
public sealed record RansomwareEvidence(
    string Kind, DateTime? TimeUtc, string Path, string Name, string PreviousName, long? Size, bool? InUse, string Source)
{
    public const string Renamed = "Renamed";
    public const string EncryptedFile = "Encrypted file";
    public const string RansomNote = "Ransom note";

    public static readonly string[] Columns = ["Kind", "TimeUtc", "Path", "Name", "PreviousName", "Size", "InUse", "Source"];

    internal static void Write(string path, IEnumerable<RansomwareEvidence> rows)
    {
        var temp = path + ".tmp";
        using (var csv = new StreamWriter(temp, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            CsvFile.WriteRow(csv, Columns);
            foreach (var r in rows.OrderBy(r => r.TimeUtc ?? DateTime.MaxValue).ThenBy(r => r.Kind, StringComparer.Ordinal))
                CsvFile.WriteRow(csv, r.Kind, IpHistoryRecord.Format(r.TimeUtc), r.Path, r.Name, r.PreviousName,
                                 r.Size?.ToString(CultureInfo.InvariantCulture) ?? "",
                                 r.InUse is null ? "" : r.InUse.Value ? "True" : "False", r.Source);
        }
        File.Move(temp, path, overwrite: true);
    }

    public static List<RansomwareEvidence> Read(string path)
    {
        var rows = new List<RansomwareEvidence>();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return rows;
        var index = header.Select((name, i) => (name, i))
            .ToDictionary(p => p.name.Trim(), p => p.i, StringComparer.OrdinalIgnoreCase);
        while (reader.ReadRecord() is { } fields)
        {
            string Cell(string name) => index.TryGetValue(name, out var i) && i < fields.Count ? fields[i] : "";
            if (Cell("Kind").Length == 0) continue;
            rows.Add(new RansomwareEvidence(
                Cell("Kind"), IpHistoryRecord.ParseTime(Cell("TimeUtc")), Cell("Path"), Cell("Name"), Cell("PreviousName"),
                long.TryParse(Cell("Size"), CultureInfo.InvariantCulture, out var size) ? size : null,
                bool.TryParse(Cell("InUse"), out var inUse) ? inUse : null, Cell("Source")));
        }
        return rows;
    }
}
