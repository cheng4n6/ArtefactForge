using System.Text.Json;
using ClosedXML.Excel;

namespace ArtefactForge.Core;

public enum EvidenceListOutcome
{
    /// <summary>The spreadsheet was written.</summary>
    Written,
    /// <summary>The spreadsheet already held exactly this list, so it was left alone.</summary>
    Unchanged,
    /// <summary>The spreadsheet is open in another program; it is out of date until rebuilt.</summary>
    Locked,
    /// <summary>The case has no collections yet, so there is nothing to list.</summary>
    NothingToList,
    /// <summary>The spreadsheet could not be read or written; it was not overwritten.</summary>
    Failed
}

public sealed class EvidenceListResult
{
    public required EvidenceListOutcome Outcome { get; init; }
    public required string Path { get; init; }
    public int Collections { get; init; }
    public int Added { get; init; }
    public int Missing { get; init; }
    public string? Error { get; init; }

    /// <summary>One line for the run summary: what happened and, if anything, what to do.</summary>
    public string Describe() => Outcome switch
    {
        EvidenceListOutcome.Written =>
            $"Evidence list updated: {Collections} collection(s)"
            + (Added > 0 ? $", {Added} new" : "") + (Missing > 0 ? $", {Missing} missing" : "") + ".",
        EvidenceListOutcome.Unchanged => $"Evidence list is up to date: {Collections} collection(s).",
        EvidenceListOutcome.Locked =>
            $"Evidence list is out of date: {System.IO.Path.GetFileName(Path)} is open in another "
            + "program, so it was not changed. Save and close it, then rebuild the evidence list.",
        EvidenceListOutcome.NothingToList => "No collections in the case yet, so no evidence list.",
        _ => $"Evidence list was not updated: {Error}"
    };
}

/// <summary>
/// The case's evidence list: EvidenceList.xlsx at the case root, one row per collection.
///
/// Some columns are rebuilt from the processed data every time (hostname, addresses, OS, the role
/// and serial number where the data has them). The rest belong to the analyst: evidence reference,
/// confirmed role, serial number, notes, and any column they add. What they type is never lost:
/// before the spreadsheet is rewritten, their columns are read back from the saved file into
/// _EvidenceList\EvidenceList.json, and written into the new one from there. That side file also
/// keeps a collection that has since gone from the case, so its row stays, marked missing.
///
/// Excel locks a workbook it has open. The saved copy can still be read, so the analyst's edits
/// are kept in the side file, but the spreadsheet is not rewritten and no second copy is made:
/// two copies end up with edits split between them. The list is reported out of date instead,
/// to be rebuilt once the file is closed.
/// </summary>
public static class EvidenceList
{
    public const string FileName = "EvidenceList.xlsx";
    private const string SideFolder = "_EvidenceList";
    private const string SideFileName = "EvidenceList.json";
    private const string SheetName = "Evidence list";

    private const string CollectionColumn = "Collection";
    private const string StatusColumn = "Status";
    private const string FileColumn = "Collection file";
    private const string AddedColumn = "Date added";
    private const string HostnameColumn = "Hostname";
    private const string DomainColumn = "Domain";
    private const string AddressesColumn = "IP addresses";
    private const string OsColumn = "OS version";
    private const string RoleColumn = "Role (detected)";
    private const string SerialColumn = "Serial number (detected)";

    /// <summary>Rebuilt from the data every time; anything else in the sheet is the analyst's.</summary>
    private static readonly string[] AutoColumns =
    [
        CollectionColumn, StatusColumn, FileColumn, AddedColumn, HostnameColumn, DomainColumn,
        AddressesColumn, OsColumn, RoleColumn, SerialColumn
    ];

    /// <summary>The analyst's columns a new list starts with.</summary>
    private static readonly string[] DefaultUserColumns =
        ["Evidence reference", "Confirmed role", "Serial number", "Notes"];

    private const string StatusPresent = "Present";
    private const string StatusNoSummary = "No system summary";
    private const string StatusMissing = "Missing";

    /// <summary>
    /// dmidecode's stand-ins for a serial number the vendor never set. Listed as found they would
    /// read as a real serial, and two hosts would appear to share one.
    /// </summary>
    private static readonly HashSet<string> PlaceholderSerials = new(StringComparer.OrdinalIgnoreCase)
    {
        "Not Specified", "Not Available", "Not Applicable", "None", "Default string",
        "To Be Filled By O.E.M.", "System Serial Number", "0", "00000000", "0123456789"
    };

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string PathFor(string caseDirectory) => Path.Combine(caseDirectory, FileName);

    /// <summary>
    /// True when another program holds the spreadsheet open for writing, as Excel does. Checked
    /// before a run so the analyst can close it first; edits not yet saved in Excel are invisible
    /// to anything reading the file.
    /// </summary>
    public static bool IsOpen(string caseDirectory)
    {
        var path = PathFor(caseDirectory);
        if (!File.Exists(path)) return false;
        try
        {
            using var _ = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException) { return true; }
        catch (UnauthorizedAccessException) { return false; }
    }

    /// <summary>
    /// Brings the evidence list up to date with the collections in the case. Safe to call at any
    /// time, with or without a run: the analyst's columns are always kept, and an unreadable or
    /// locked spreadsheet is reported rather than replaced.
    /// </summary>
    public static EvidenceListResult Rebuild(string caseDirectory, DateTimeOffset? now = null)
    {
        var path = PathFor(caseDirectory);
        try
        {
            return RebuildCore(caseDirectory, path, now ?? DateTimeOffset.Now);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Called at the end of a run: a list that cannot be updated is reported, and must not
            // cost the run its report.
            return new EvidenceListResult { Outcome = EvidenceListOutcome.Failed, Path = path, Error = ex.Message };
        }
    }

    private static EvidenceListResult RebuildCore(string caseDirectory, string path, DateTimeOffset now)
    {
        if (!Directory.Exists(caseDirectory))
            return new EvidenceListResult { Outcome = EvidenceListOutcome.NothingToList, Path = path };

        var sidePath = Path.Combine(caseDirectory, SideFolder, SideFileName);
        var state = LoadState(sidePath);

        // The saved spreadsheet is where the analyst edits, so what it holds wins over the side
        // file. A spreadsheet that cannot be read is left exactly as it is: rewriting it would
        // destroy whatever the analyst put in it.
        Sheet? existing = null;
        if (File.Exists(path))
        {
            existing = ReadSheet(path, out var error);
            if (existing is null)
                return new EvidenceListResult { Outcome = EvidenceListOutcome.Failed, Path = path, Error = error };
            TakeUserEdits(existing, state);
        }

        var added = UpdateCollections(caseDirectory, state, now);
        if (state.Collections.Count == 0 && state.ManualRows.Count == 0)
            return new EvidenceListResult { Outcome = EvidenceListOutcome.NothingToList, Path = path };

        SaveState(sidePath, state);

        var sheet = Compose(state);
        var result = new EvidenceListResult
        {
            Outcome = EvidenceListOutcome.Written,
            Path = path,
            Collections = state.Collections.Count,
            Added = added,
            Missing = state.Collections.Values.Count(c => c.Status == StatusMissing)
        };

        if (existing is not null && existing.SameAs(sheet))
            return Copy(result, EvidenceListOutcome.Unchanged);
        if (IsOpen(caseDirectory))
            return Copy(result, EvidenceListOutcome.Locked);

        // Written beside the target and moved over it, so a failure part-way never leaves a
        // truncated workbook where the analyst's list was.
        var temp = path + ".tmp";
        try
        {
            Write(sheet, temp);
            File.Move(temp, path, overwrite: true);
        }
        catch (IOException) when (IsOpen(caseDirectory))
        {
            TryDelete(temp);
            return Copy(result, EvidenceListOutcome.Locked);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }

        return result;
    }

    private static EvidenceListResult Copy(EvidenceListResult result, EvidenceListOutcome outcome) => new()
    {
        Outcome = outcome,
        Path = result.Path,
        Collections = result.Collections,
        Added = result.Added,
        Missing = result.Missing
    };

    // ------------------------------------------------------------------ the analyst's columns

    private static void TakeUserEdits(Sheet sheet, ListState state)
    {
        // The sheet's own columns, in its order: a column the analyst deleted stays deleted. Its
        // values stay in the side file all the same.
        var userColumns = sheet.Headers.Where(h => !IsAutoColumn(h)).ToList();
        state.UserColumns = userColumns;

        var manual = new List<Dictionary<string, string>>();
        foreach (var row in sheet.Rows)
        {
            var user = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var column in userColumns)
                user[column] = row.TryGetValue(column, out var v) ? v : "";

            var collection = row.TryGetValue(CollectionColumn, out var c) ? c.Trim() : "";
            if (collection.Length == 0)
            {
                // A row the analyst added by hand, for evidence ArtefactForge never processed
                // (a phone, a disk not yet imaged). It has no key, so it is kept as it stands.
                if (user.Values.Any(v => v.Length > 0)) manual.Add(user);
                continue;
            }

            if (!state.Collections.TryGetValue(collection, out var entry))
                state.Collections[collection] = entry = new CollectionEntry();
            entry.User = user;
        }

        // The sheet holds every hand-added row there is, so it replaces the saved set: a row the
        // analyst deleted from the sheet stays deleted.
        state.ManualRows = manual;
    }

    private static bool IsAutoColumn(string header) =>
        AutoColumns.Contains(header, StringComparer.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ the data's columns

    /// <summary>
    /// Refreshes the detected columns from the case and returns how many collections are new.
    /// A collection no longer in the case keeps its last known values, marked missing.
    /// </summary>
    private static int UpdateCollections(string caseDirectory, ListState state, DateTimeOffset now)
    {
        var summaries = SystemInventory.Collect(caseDirectory)
            .ToDictionary(s => s.Collection, s => s.Facts, StringComparer.OrdinalIgnoreCase);
        var sources = CollectionSources(caseDirectory);
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var added = 0;

        foreach (var folder in Directory.EnumerateDirectories(caseDirectory))
        {
            var name = Path.GetFileName(folder);
            if (name.StartsWith('_')) continue;   // _Logs, _Staging, _Extracted, _EvidenceList
            present.Add(name);

            if (!state.Collections.TryGetValue(name, out var entry))
            {
                state.Collections[name] = entry = new CollectionEntry();
                added++;
            }

            // The folder appears when a collection is first processed, so on a case that had a
            // list before this feature its age is a better "added" date than today.
            if (string.IsNullOrEmpty(entry.DateAdded))
            {
                var created = Directory.GetCreationTime(folder);
                entry.DateAdded = (created.Year > 1601 ? created : now.LocalDateTime).ToString("yyyy-MM-dd");
            }
            if (sources.TryGetValue(name, out var source)) entry.CollectionFile = source;

            if (summaries.TryGetValue(name, out var facts))
            {
                entry.Status = StatusPresent;
                entry.Detected = Detect(facts);
            }
            else
            {
                entry.Status = StatusNoSummary;
                entry.Detected = new(StringComparer.OrdinalIgnoreCase);
            }
        }

        foreach (var (name, entry) in state.Collections)
            if (!present.Contains(name)) entry.Status = StatusMissing;

        return added;
    }

    /// <summary>The detected columns from one collection's summary facts.</summary>
    private static Dictionary<string, string> Detect(IReadOnlyDictionary<string, string> facts)
    {
        string Fact(string item) => facts.TryGetValue(item, out var v) ? v.Trim() : "";

        // Windows: "Windows 10 Pro 22H2 (build 19045.4291)". Linux: os-release's PRETTY_NAME,
        // else lsb-release's description.
        var os = Fact("ProductName");
        if (os.Length > 0)
        {
            if (Fact("DisplayVersion") is { Length: > 0 } display) os += " " + display;
            if (Fact("Build") is { Length: > 0 } build) os += $" (build {build})";
        }
        else os = Fact("PRETTY_NAME") is { Length: > 0 } pretty ? pretty : Fact("DISTRIB_DESCRIPTION");

        // What the live system reported at collection time beats its static configuration, which
        // a DHCP host does not have at all.
        var addresses = Fact("LiveIPAddresses") is { Length: > 0 } live ? live : Fact("IPAddresses");

        var serial = Fact("SerialNumber");
        if (PlaceholderSerials.Contains(serial)) serial = "";

        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [HostnameColumn] = Fact("Hostname"),
            [DomainColumn] = Fact("Domain"),
            [AddressesColumn] = addresses,
            [OsColumn] = os,
            [RoleColumn] = Fact("ComputerRole"),
            [SerialColumn] = serial
        };
    }

    /// <summary>
    /// The zip or folder each collection was processed from, according to the last run's
    /// manifest. Earlier runs' sources are kept in the side file.
    /// </summary>
    private static Dictionary<string, string> CollectionSources(string caseDirectory)
    {
        var sources = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var manifest = Path.Combine(caseDirectory, "_Logs", "manifest.json");
        if (!File.Exists(manifest)) return sources;

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(manifest));
            if (!document.RootElement.TryGetProperty("Collections", out var collections)
                || collections.ValueKind != JsonValueKind.Array) return sources;

            foreach (var collection in collections.EnumerateArray())
            {
                var name = Text(collection, "CollectionName");
                var source = Text(collection, "Archive") ?? Text(collection, "Root");
                if (name is not null && source is not null) sources[name] = source;
            }
        }
        catch (JsonException) { }   // a damaged manifest costs the source column, not the list

        return sources;

        static string? Text(JsonElement element, string property) =>
            element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            && value.GetString() is { Length: > 0 } text ? text : null;
    }

    // ------------------------------------------------------------------ the spreadsheet

    private static Sheet Compose(ListState state)
    {
        var userColumns = state.UserColumns.Count > 0 ? state.UserColumns : [.. DefaultUserColumns];
        state.UserColumns = userColumns;

        // Evidence reference leads, as it does on a hand-made list; the analyst's other columns
        // follow the detected ones, so the two kinds are easy to tell apart.
        var lead = userColumns.Where(c => c.Equals(DefaultUserColumns[0], StringComparison.OrdinalIgnoreCase));
        var headers = lead.Concat(AutoColumns).Concat(userColumns.Except(lead)).ToList();

        var rows = new List<Dictionary<string, string>>();
        foreach (var (name, entry) in state.Collections.OrderBy(c => c.Key, StringComparer.OrdinalIgnoreCase))
        {
            var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [CollectionColumn] = name,
                [StatusColumn] = entry.Status,
                [FileColumn] = entry.CollectionFile,
                [AddedColumn] = entry.DateAdded
            };
            foreach (var (column, value) in entry.Detected) row[column] = value;
            foreach (var (column, value) in entry.User) row[column] = value;
            rows.Add(row);
        }
        rows.AddRange(state.ManualRows.Select(r => new Dictionary<string, string>(r, StringComparer.OrdinalIgnoreCase)));

        return new Sheet(headers, rows);
    }

    private static Sheet? ReadSheet(string path, out string? error)
    {
        error = null;
        try
        {
            // Shared for writing: Excel holds the file open while the analyst works in it, and
            // the last saved version is still there to be read.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var workbook = new XLWorkbook(stream);
            var sheet = workbook.Worksheets.FirstOrDefault(w => w.Name == SheetName)
                        ?? workbook.Worksheets.First();

            var lastColumn = sheet.LastColumnUsed()?.ColumnNumber() ?? 0;
            var lastRow = sheet.LastRowUsed()?.RowNumber() ?? 0;

            var headers = new List<string>();
            for (var c = 1; c <= lastColumn; c++)
                headers.Add(sheet.Cell(1, c).GetFormattedString().Trim());

            if (!headers.Contains(CollectionColumn, StringComparer.OrdinalIgnoreCase))
            {
                error = $"{FileName} has no \"{CollectionColumn}\" column, so its rows cannot be matched "
                        + "to collections. Put the column back, or move the file aside to start a new list.";
                return null;
            }

            var rows = new List<Dictionary<string, string>>();
            for (var r = 2; r <= lastRow; r++)
            {
                var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                for (var c = 1; c <= lastColumn; c++)
                    if (headers[c - 1].Length > 0) row[headers[c - 1]] = sheet.Cell(r, c).GetFormattedString();
                if (row.Values.Any(v => v.Length > 0)) rows.Add(row);
            }

            return new Sheet([.. headers.Where(h => h.Length > 0)], rows);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // ClosedXML and the OpenXML SDK throw a range of types for a damaged or foreign file.
            error = $"{FileName} could not be read ({ex.Message}). It was left as it is.";
            return null;
        }
    }

    private static void Write(Sheet sheet, string path)
    {
        using var workbook = new XLWorkbook();
        var ws = workbook.AddWorksheet(SheetName);

        for (var c = 0; c < sheet.Headers.Count; c++)
        {
            var header = sheet.Headers[c];
            ws.Cell(1, c + 1).Value = header;
            for (var r = 0; r < sheet.Rows.Count; r++)
            {
                var value = sheet.Rows[r].TryGetValue(header, out var v) ? v : "";
                ws.Cell(r + 2, c + 1).Value = value;
            }
        }

        var table = ws.Range(1, 1, Math.Max(2, sheet.Rows.Count + 1), sheet.Headers.Count)
                      .CreateTable("EvidenceList");
        table.Theme = XLTableTheme.TableStyleLight1;

        for (var c = 0; c < sheet.Headers.Count; c++)
        {
            var column = ws.Column(c + 1);
            var widest = sheet.Rows.Select(r => r.TryGetValue(sheet.Headers[c], out var v) ? v.Length : 0)
                              .Append(sheet.Headers[c].Length).Max();
            column.Width = Math.Clamp(widest + 2, 10, 60);

            if (!IsAutoColumn(sheet.Headers[c]))
            {
                // Text, so a reference such as 007 is not turned into the number 7, and a header
                // colour that marks where the analyst types.
                column.Style.NumberFormat.Format = "@";
                ws.Cell(1, c + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#FFF2CC");
            }
        }

        ws.SheetView.FreezeRows(1);

        var about = workbook.AddWorksheet("About");
        string[] notes =
        [
            "Evidence list, rebuilt by ArtefactForge after every run and by Rebuild evidence list.",
            "",
            "Shaded columns are yours. Whatever you type in them is kept when the list is rebuilt.",
            "You can add columns of your own; they are kept too.",
            "Rows you add with no Collection are kept as they are.",
            "The other columns come from the processed data and are rewritten every time.",
            "",
            "Status: Present, No system summary (the SystemInfo module did not run), or Missing",
            "(the collection is no longer in the case folder; its row is kept).",
            "",
            "Save and close this file before a run. ArtefactForge cannot update it while it is open,",
            "and only reads what has been saved."
        ];
        for (var i = 0; i < notes.Length; i++) about.Cell(i + 1, 1).Value = notes[i];
        about.Column(1).Width = 100;

        workbook.SaveAs(path);
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    // ------------------------------------------------------------------ side file

    private static ListState LoadState(string path)
    {
        if (!File.Exists(path)) return new ListState();
        var state = JsonSerializer.Deserialize<ListState>(File.ReadAllText(path)) ?? new ListState();

        // JSON does not carry a dictionary's comparer, and collection and column names are matched
        // without regard to case everywhere else.
        state.Collections = new(state.Collections, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in state.Collections.Values)
        {
            entry.Detected = new(entry.Detected, StringComparer.OrdinalIgnoreCase);
            entry.User = new(entry.User, StringComparer.OrdinalIgnoreCase);
        }
        state.ManualRows = [.. state.ManualRows.Select(r => new Dictionary<string, string>(r, StringComparer.OrdinalIgnoreCase))];
        return state;
    }

    private static void SaveState(string path, ListState state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions));
        File.Move(temp, path, overwrite: true);
    }

    private sealed class ListState
    {
        public int Version { get; set; } = 1;
        public List<string> UserColumns { get; set; } = [];
        public Dictionary<string, CollectionEntry> Collections { get; set; } =
            new(StringComparer.OrdinalIgnoreCase);
        public List<Dictionary<string, string>> ManualRows { get; set; } = [];
    }

    private sealed class CollectionEntry
    {
        public string Status { get; set; } = "";
        public string DateAdded { get; set; } = "";
        public string CollectionFile { get; set; } = "";
        public Dictionary<string, string> Detected { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> User { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed record Sheet(List<string> Headers, List<Dictionary<string, string>> Rows)
    {
        public bool SameAs(Sheet other)
        {
            if (!Headers.SequenceEqual(other.Headers, StringComparer.Ordinal)) return false;
            if (Rows.Count != other.Rows.Count) return false;
            for (var i = 0; i < Rows.Count; i++)
                foreach (var header in Headers)
                    if (Cell(Rows[i], header) != Cell(other.Rows[i], header)) return false;
            return true;

            static string Cell(Dictionary<string, string> row, string header) =>
                row.TryGetValue(header, out var v) ? v : "";
        }
    }
}
