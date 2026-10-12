using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Ioc;

public enum IocType { FileName, Path, Hash, IP, Domain, Account }

/// <summary>
/// One row of a case's IOCs.csv. The row keeps the type label and any extra columns exactly as
/// read, so writing the list back changes nothing the analyst did not ask to change.
/// </summary>
public sealed class IocEntry
{
    /// <summary>The type as written in the file; kept for the round trip even when not understood.</summary>
    public required string TypeLabel { get; init; }
    /// <summary>Null when the label is not a type ArtefactForge knows: the row is kept, not swept.</summary>
    public IocType? Type { get; init; }
    public required string Value { get; init; }
    public string Note { get; init; } = "";
    public string FoundOn { get; init; } = "";
    /// <summary>Columns the analyst added, by header name.</summary>
    public IReadOnlyDictionary<string, string> Extra { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>True when the row can be swept: a known type and a value.</summary>
    public bool IsSweepable => Type is not null && Value.Trim().Length > 0;

    /// <summary>Identity of an IOC: its type and value, ignoring case and surrounding spaces.</summary>
    public string Key => IocList.KeyFor(TypeLabel, Value);

    public static IocEntry Create(IocType type, string value, string note = "", string foundOn = "") => new()
    {
        TypeLabel = IocList.Label(type),
        Type = type,
        Value = value.Trim(),
        Note = note.Trim(),
        FoundOn = foundOn.Trim()
    };
}

/// <summary>What an import added, what was already on the list, and lines that were not used.</summary>
public sealed record IocImportResult(
    IReadOnlyList<IocEntry> Added, int AlreadyListed, IReadOnlyList<string> Rejected);

/// <summary>
/// The case's IOC list, IOCs.csv in the case folder. It is the analyst's own data: nothing in
/// ArtefactForge writes it except an analyst's add, remove or import, and each of those re-reads
/// the file first, so an edit made in Excel since the list was shown is kept rather than lost.
/// A save goes to a temporary file that then replaces the original, so a crash or a full disk
/// leaves the old list whole. A file that cannot be read is never saved over.
/// </summary>
public static partial class IocList
{
    public const string FileName = "IOCs.csv";

    private static readonly string[] Columns = ["Type", "Value", "Note", "Found on"];

    // A list is saved by one caller at a time within the process (the app's Add button and the
    // CLI never share a process, but two quick adds in the app can).
    private static readonly object SaveGate = new();

    public static string PathFor(string caseDirectory) => System.IO.Path.Combine(caseDirectory, FileName);

    public static bool Exists(string caseDirectory) => File.Exists(PathFor(caseDirectory));

    /// <summary>The list as it is on disk now; empty when the case has no IOCs.csv yet.</summary>
    /// <exception cref="InvalidDataException">The file has no Value column.</exception>
    public static IReadOnlyList<IocEntry> Load(string caseDirectory) => Read(PathFor(caseDirectory)).Entries;

    /// <summary>
    /// Adds the entries not already listed (same type and value) and returns those it added.
    /// </summary>
    public static IReadOnlyList<IocEntry> Add(string caseDirectory, IEnumerable<IocEntry> entries)
    {
        lock (SaveGate)
        {
            var path = PathFor(caseDirectory);
            var current = Read(path);
            var known = current.Entries.Select(e => e.Key).ToHashSet(StringComparer.Ordinal);
            var added = new List<IocEntry>();
            foreach (var entry in entries)
            {
                if (entry.Value.Trim().Length == 0 || !known.Add(entry.Key)) continue;
                added.Add(entry);
            }
            if (added.Count == 0) return added;

            Directory.CreateDirectory(caseDirectory);
            Write(path, current.ExtraColumns, [.. current.Entries, .. added]);
            return added;
        }
    }

    /// <summary>Removes the entries with the same type and value; returns those it removed.</summary>
    public static IReadOnlyList<IocEntry> Remove(string caseDirectory, IEnumerable<IocEntry> entries)
    {
        lock (SaveGate)
        {
            var path = PathFor(caseDirectory);
            if (!File.Exists(path)) return [];
            var current = Read(path);
            var keys = entries.Select(e => e.Key).ToHashSet(StringComparer.Ordinal);
            var removed = current.Entries.Where(e => keys.Contains(e.Key)).ToList();
            if (removed.Count == 0) return removed;

            Write(path, current.ExtraColumns, current.Entries.Where(e => !keys.Contains(e.Key)).ToList());
            return removed;
        }
    }

    /// <summary>
    /// Adds IOCs from another file: an IOCs.csv from another case (a Type and Value header), or a
    /// plain list with one value per line, whose types are worked out from the values.
    /// </summary>
    public static IocImportResult Import(string caseDirectory, string sourceFile)
    {
        var (entries, rejected) = ReadImport(sourceFile);
        var added = Add(caseDirectory, entries);
        var distinct = entries.Select(e => e.Key).Distinct(StringComparer.Ordinal).Count();
        return new IocImportResult(added, distinct - added.Count, rejected);
    }

    /// <summary>Reads a file to import without changing anything.</summary>
    public static (List<IocEntry> Entries, List<string> Rejected) ReadImport(string sourceFile)
    {
        var rejected = new List<string>();
        var lines = File.ReadAllLines(sourceFile);
        var firstLine = lines.FirstOrDefault(l => l.Trim().Length > 0);
        if (firstLine is not null)
        {
            var header = CsvText.Split(firstLine);
            if (Array.FindIndex(header, h => h.Trim().Equals("Value", StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                var parsed = Read(sourceFile).Entries.ToList();
                foreach (var bad in parsed.Where(e => !e.IsSweepable))
                    rejected.Add($"{bad.TypeLabel},{bad.Value}: type not recognised");
                return (parsed.Where(e => e.IsSweepable)
                              .Select(e => IocEntry.Create(e.Type!.Value, e.Value, e.Note, e.FoundOn)).ToList(),
                        rejected);
            }
        }

        var entries = new List<IocEntry>();
        foreach (var raw in lines)
        {
            var value = raw.Trim().Trim('"').Trim();
            if (value.Length == 0 || value.StartsWith('#')) continue;
            entries.Add(IocEntry.Create(Infer(value), value));
        }
        return (entries, rejected);
    }

    /// <summary>The label written in the Type column.</summary>
    public static string Label(IocType type) => type switch
    {
        IocType.FileName => "File name",
        IocType.Path => "Path",
        IocType.Hash => "Hash",
        IocType.IP => "IP",
        IocType.Domain => "Domain",
        _ => "Account"
    };

    /// <summary>Reads a Type label, accepting the usual ways of writing each one.</summary>
    public static IocType? ParseType(string label)
    {
        var compact = new string(label.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        return compact switch
        {
            "filename" or "file" => IocType.FileName,
            "path" or "filepath" or "fullpath" or "folder" => IocType.Path,
            "hash" or "md5" or "sha1" or "sha256" or "sha512" or "filehash" => IocType.Hash,
            "ip" or "ipaddress" or "ipv4" or "ipv6" => IocType.IP,
            "domain" or "domainname" or "hostname" or "fqdn" => IocType.Domain,
            "account" or "user" or "username" or "useraccount" or "sid" or "email" => IocType.Account,
            _ => null
        };
    }

    /// <summary>Identity used to tell whether an IOC is already listed.</summary>
    public static string KeyFor(string typeLabel, string value) =>
        (ParseType(typeLabel)?.ToString() ?? typeLabel.Trim().ToLowerInvariant()) + "|" + value.Trim().ToLowerInvariant();

    /// <summary>
    /// Works out an IOC's type from its value, for the app's Auto choice and plain-list imports.
    /// A value that looks like nothing else is an account: a bare name such as svc_backup is far
    /// more often a user than a file, and both match the same way, as a whole word in any line.
    /// </summary>
    public static IocType Infer(string value)
    {
        var v = value.Trim();
        if (HexHash().IsMatch(v)) return IocType.Hash;
        if (Ipv4().IsMatch(v) || (v.Contains(':') && !v.Contains('\\') && IPAddress.TryParse(v, out _))) return IocType.IP;
        if (DriveOrUncPath().IsMatch(v) || v.StartsWith('/') || v.StartsWith('%')) return IocType.Path;
        if (v.Contains('\\'))
        {
            // DOMAIN\user has one separator and no extension; anything else with a backslash is a path.
            var parts = v.Split('\\');
            return parts.Length == 2 && !parts[1].Contains('.') ? IocType.Account : IocType.Path;
        }
        if (v.Contains('/')) return IocType.Path;
        if (v.Contains('@')) return IocType.Account;
        var extension = System.IO.Path.GetExtension(v).TrimStart('.').ToLowerInvariant();
        if (FileExtensions.Contains(extension)) return IocType.FileName;
        if (DomainName().IsMatch(v)) return IocType.Domain;
        return IocType.Account;
    }

    // Extensions that make a value a file name rather than a domain. ".com" is left out on
    // purpose: as an IOC it is far more often a domain than a DOS program.
    private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "lnk",
        "scr", "msi", "msc", "cpl", "ocx", "zip", "rar", "7z", "gz", "tar", "iso", "img", "vhd",
        "vhdx", "txt", "log", "csv", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptm",
        "pdf", "rtf", "jar", "py", "sh", "elf", "so", "bin", "dat", "tmp", "ini", "xml", "json",
        "php", "asp", "aspx", "jsp", "war", "pl", "rb", "wsf", "sct", "inf", "reg", "job", "evtx"
    };

    [GeneratedRegex(@"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")]
    private static partial Regex HexHash();

    [GeneratedRegex(@"^\d{1,3}(?:\.\d{1,3}){3}$")]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"^(?:[A-Za-z]:[\\/]|\\\\)")]
    private static partial Regex DriveOrUncPath();

    [GeneratedRegex(@"^(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]*$")]
    private static partial Regex DomainName();

    private sealed record ListFile(List<string> ExtraColumns, List<IocEntry> Entries);

    private static ListFile Read(string path)
    {
        if (!File.Exists(path)) return new ListFile([], []);

        // Shared read, so a list that is open in Excel can still be read.
        string text;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
            text = reader.ReadToEnd();

        using var records = CsvText.Records(new StringReader(text)).GetEnumerator();
        if (!records.MoveNext()) return new ListFile([], []);

        var header = CsvText.Split(records.Current.Text).Select(h => h.Trim()).ToArray();
        int Find(string name) => Array.FindIndex(header, h => h.Equals(name, StringComparison.OrdinalIgnoreCase));
        var typeIndex = Find("Type");
        var valueIndex = Find("Value");
        var noteIndex = Find("Note");
        var foundIndex = Find("Found on");
        if (foundIndex < 0) foundIndex = Find("FoundOn");
        if (valueIndex < 0)
            throw new InvalidDataException(
                $"{path} has no Value column, so it was not read and will not be saved over. "
                + "Its first line should be: " + string.Join(",", Columns));

        var known = new[] { typeIndex, valueIndex, noteIndex, foundIndex };
        var extras = header.Select((name, index) => (name, index))
                           .Where(c => !known.Contains(c.index) && c.name.Length > 0)
                           .ToList();

        var entries = new List<IocEntry>();
        while (records.MoveNext())
        {
            if (records.Current.Text.Trim().Length == 0) continue;
            var fields = CsvText.Split(records.Current.Text);
            string At(int index) => index >= 0 && index < fields.Length ? fields[index] : "";

            var label = At(typeIndex);
            entries.Add(new IocEntry
            {
                TypeLabel = label,
                Type = ParseType(label),
                Value = At(valueIndex),
                Note = At(noteIndex),
                FoundOn = At(foundIndex),
                Extra = extras.ToDictionary(c => c.name, c => At(c.index), StringComparer.OrdinalIgnoreCase)
            });
        }
        return new ListFile(extras.Select(c => c.name).ToList(), entries);
    }

    private static void Write(string path, IReadOnlyList<string> extraColumns, IReadOnlyList<IocEntry> entries)
    {
        var csv = new StringBuilder();
        csv.AppendLine(string.Join(",", Columns.Concat(extraColumns).Select(CsvText.Escape)));
        foreach (var e in entries)
        {
            var fields = new[] { e.TypeLabel, e.Value, e.Note, e.FoundOn }
                .Concat(extraColumns.Select(c => e.Extra.TryGetValue(c, out var v) ? v : ""));
            csv.AppendLine(string.Join(",", fields.Select(CsvText.Escape)));
        }
        AtomicFile.WriteAllText(path, csv.ToString());
    }
}
