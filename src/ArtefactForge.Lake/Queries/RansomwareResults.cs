using System.Security.Cryptography;
using DuckDB.NET.Data;

namespace ArtefactForge.Lake.Queries;

/// <summary>What <see cref="RansomwareResults.Write"/> did.</summary>
public sealed record RansomwareResultsSummary(string OutputRoot, int Hosts, int Found, int NotChecked, int Failed, bool CaseFileWritten)
{
    public string Describe() =>
        $"{Hosts} host(s): {Found} with ransomware, {NotChecked} not checked, {Failed} failed" +
        (CaseFileWritten ? "" : "; no case file, as no host had MFTECmd output");
}

/// <summary>
/// ArtefactForge's ransomware files from the lake's saved queries: the same names, columns and
/// layout as the Ransomware step writes in the case (RansomwareSummary.csv, RansomwareEvidence.csv
/// and Note\ per host, Ransomware.csv for the case), under an output root of their own.
///
/// Every decision is the queries'. What is left here is what SQL does not do: reading the ransom
/// note from the collection (or from the MFT, when it is resident) to save a copy and its hash,
/// and writing the files.
/// </summary>
public static class RansomwareResults
{
    public const string Folder = "Ransomware";
    public const string SummaryFileName = "RansomwareSummary.csv";
    public const string EvidenceFileName = "RansomwareEvidence.csv";
    public const string NoteFolder = "Note";
    public const string CaseFileName = "Ransomware.csv";
    public const string OverridesFileName = "Ransomware-Overrides.csv";

    public static readonly string[] Columns =
    [
        "Collection", "Host", "Status", "Extension", "ExtensionBasis", "NoteName", "NoteBasis", "NoteSize",
        "NoteSha256", "NoteCopy", "NoteFolders", "StartUtc", "StartIsEarliestSeen", "FinishUtc",
        "FilesAffected", "RatePerMinute", "PeakPerMinute", "Source", "Differences", "Detail"
    ];

    public static readonly string[] EvidenceColumns = ["Kind", "TimeUtc", "Path", "Name", "PreviousName", "Size", "InUse", "Source"];

    /// <summary>Where the lake build writes them: &lt;lake&gt;\results\Ransomware.</summary>
    public static string OutputRootFor(string lakeDirectory) => Path.Combine(lakeDirectory, LakeNames.ResultsFolder, Folder);

    /// <summary>
    /// Runs the ransomware queries and writes the files under <paramref name="outputRoot"/>, laid
    /// out as a case folder: &lt;root&gt;\&lt;Collection&gt;\Ransomware\... and &lt;root&gt;\Ransomware.csv. What
    /// was there before is removed first. Throws InvalidDataException when the overrides file is
    /// not one: going on without it would quietly drop what the analyst settled.
    /// </summary>
    public static RansomwareResultsSummary Write(LakeQuerySession session, string outputRoot, CancellationToken cancellationToken = default)
    {
        var hostsQuery = Query("ransomware_hosts");
        var hosts = session.RunToRows(hostsQuery);
        CheckOverrides(session);
        cancellationToken.ThrowIfCancellationRequested();

        var evidence = session.RunToRows(Query("ransomware_evidence")).ToLookup(r => r["Collection"], StringComparer.Ordinal);
        var sources = session.RunToRows(Query("ransomware_note_sources")).ToLookup(r => r["Collection"], StringComparer.Ordinal);

        if (Directory.Exists(outputRoot)) Directory.Delete(outputRoot, recursive: true);
        Directory.CreateDirectory(outputRoot);

        foreach (var host in hosts.Where(Checked))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var collection = host["Collection"];
            var outDir = Path.Combine(outputRoot, collection, Folder);
            Directory.CreateDirectory(outDir);
            LakeCsv.Write(Path.Combine(outDir, EvidenceFileName), EvidenceColumns,
                evidence[collection].Select(r => EvidenceColumns.Select(c => r[c])));

            if (host["Status"] == "Found" && host["NoteName"].Length > 0 && host["NoteSize"].Length > 0)
                RecordCopy(session, collection, SaveNote(outputRoot, collection, host["NoteName"], long.Parse(host["NoteSize"]),
                                                        sources[collection]));
        }

        // Read again: the rows now carry the note copies and, where none could be saved, say so.
        hosts = session.RunToRows(hostsQuery);
        foreach (var host in hosts.Where(h => Checked(h) || h["Status"] == "Failed"))
        {
            var outDir = Path.Combine(outputRoot, host["Collection"], Folder);
            Directory.CreateDirectory(outDir);
            LakeCsv.Write(Path.Combine(outDir, SummaryFileName), [.. Columns, "Parameters"],
                [[.. Columns.Select(c => host[c]), host["Parameters"]]]);
        }

        var caseRows = session.RunToRows(Query("ransomware_case"));
        var caseFile = caseRows.Any(r => r["Status"] != "Not checked");
        if (caseFile)
            LakeCsv.Write(Path.Combine(outputRoot, CaseFileName), Columns, caseRows.Select(r => Columns.Select(c => r[c])));

        return new RansomwareResultsSummary(outputRoot, hosts.Count, hosts.Count(h => h["Status"] == "Found"),
            hosts.Count(h => h["Status"] == "Not checked"), hosts.Count(h => h["Status"] == "Failed"), caseFile);
    }

    private static bool Checked(Dictionary<string, string> host) => host["Status"] is "Found" or "None found";

    private static LakeQuery Query(string name) =>
        LakeQueryCatalogue.Find(name) ?? throw new InvalidDataException($"The saved query {name} is missing from the lake library");

    /// <summary>The overrides need a Collection column and an Extension or NoteName one, as the Ransomware step reads them.</summary>
    private static void CheckOverrides(LakeQuerySession session)
    {
        if (!session.InputHeaders.TryGetValue("ransomware_overrides", out var header)) return;
        bool Has(string column) => header.Any(h => h.Trim().Equals(column, StringComparison.OrdinalIgnoreCase));
        if (!Has("Collection") || (!Has("Extension") && !Has("NoteName")))
            throw new InvalidDataException(
                $"{OverridesFileName} needs the columns Collection, Extension, NoteName, Comment on its first line");
    }

    private sealed record NoteCopy(bool Saved, string Sha256, string Copy);

    /// <summary>
    /// Saves one copy of the note in the host's Note folder, from the collection or from the MFT
    /// when the note is resident, as the Ransomware step does. A note that is not .txt is saved
    /// with .txt added, so opening it from the case cannot run it (a .hta note is a program).
    /// </summary>
    private static NoteCopy SaveNote(string outputRoot, string collection, string noteName, long size,
        IEnumerable<Dictionary<string, string>> copies)
    {
        foreach (var copy in copies)
        {
            var sourceFile = copy["MftSourceFile"];
            var root = sourceFile.Length == 0 ? null : Path.GetDirectoryName(sourceFile);
            var path = root is null ? "" : Path.Combine(root, copy["Path"].TrimStart('.', '\\'), copy["Name"]);
            var resident = copy["ResidentDataBase64"];
            byte[]? content = null;
            try
            {
                if (path.Length > 0 && File.Exists(path) && new FileInfo(path).Length == size)
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    content = new byte[size];
                    stream.ReadExactly(content);
                }
                else if (resident.Length > 0)
                {
                    var bytes = Convert.FromBase64String(resident);
                    if (bytes.Length == size) content = bytes;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
            {
                continue;   // another copy may read
            }
            if (content is null) continue;

            var noteDir = Path.Combine(outputRoot, collection, Folder, NoteFolder);
            Directory.CreateDirectory(noteDir);
            var name = noteName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ? noteName : noteName + ".txt";
            var saved = Path.Combine(noteDir, name);
            File.WriteAllBytes(saved, content);
            return new NoteCopy(true, Convert.ToHexString(SHA256.HashData(content)), Path.GetRelativePath(outputRoot, saved));
        }
        return new NoteCopy(false, "", "");
    }

    private static void RecordCopy(LakeQuerySession session, string collection, NoteCopy copy)
    {
        using var command = session.CreateCommand();
        command.CommandText = "INSERT INTO ransomware_note_copies VALUES ($collection, true, $sha, $copy)";
        command.Parameters.Add(new DuckDBParameter("collection", collection));
        command.Parameters.Add(new DuckDBParameter("sha", copy.Saved ? copy.Sha256 : (object)DBNull.Value));
        command.Parameters.Add(new DuckDBParameter("copy", copy.Saved ? copy.Copy : (object)DBNull.Value));
        command.ExecuteNonQuery();
    }
}
