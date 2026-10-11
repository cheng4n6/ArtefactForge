using System.Text.Json;

namespace ArtefactForge.Core;

/// <summary>
/// Converts a Velociraptor offline collection into the drive-letter-folder shape every module
/// already reads. Verified against an offline collector, v0.77.3, Windows.Triage.Targets with
/// _SANS_Triage (2026-10-10). Its zip differs from a plain collection in four ways, each handled
/// here because the tools read real paths on disk:
/// <list type="bullet">
/// <item>One drive arrives under several roots, one per accessor: uploads/auto/C%3A,
/// uploads/ntfs/%5C%5C.%5CC%3A (raw NTFS reads such as $MFT) and uploads/auto/%5C%5C.%5CC%3A.</item>
/// <item>Every path component is percent-encoded. Names can contain a literal '%' (stored as %25),
/// so each component is decoded exactly once.</item>
/// <item>NTFS streams are named with ':' ($UsnJrnl:$J), which Windows would write as an alternate
/// data stream rather than a file.</item>
/// <item>Sparse files are stored as their data ranges only, with a &lt;name&gt;.idx companion
/// describing the holes. Unzipped as-is, hives and ESE databases come out shorter than the
/// originals.</item>
/// </list>
/// </summary>
public static class VelociraptorCollection
{
    public const string MetadataFolder = "_Velociraptor";

    /// <summary>
    /// Streams the modules look for under a different name. MFTECmd_USNJournal reads $Extend\$J,
    /// which is where other collectors put the journal.
    /// </summary>
    private static readonly Dictionary<string, string> StreamRenames = new(StringComparer.OrdinalIgnoreCase)
    {
        [@"$Extend\$UsnJrnl:$J"] = @"$Extend\$J",
        [@"$Extend\$UsnJrnl:$Max"] = @"$Extend\$Max"
    };

    /// <summary>An offline collector writes client_info.json and an uploads folder at the zip root.</summary>
    public static bool IsCollection(IEnumerable<string> entryNames)
    {
        var info = false;
        var uploads = false;
        foreach (var name in entryNames)
        {
            if (name.Equals("client_info.json", StringComparison.OrdinalIgnoreCase)) info = true;
            else if (name.StartsWith("uploads/", StringComparison.OrdinalIgnoreCase)) uploads = true;
            if (info && uploads) return true;
        }
        return false;
    }

    /// <summary>
    /// Where an entry belongs in the converted tree, as a relative path with '\' separators, or
    /// null with the reason it is left out. Velociraptor's own files go under _Velociraptor so no
    /// module mistakes them for evidence.
    /// </summary>
    public static string? MapEntry(string entryName, out string? skipReason)
    {
        skipReason = null;
        var parts = entryName.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) { skipReason = "empty entry name"; return null; }

        if (!parts[0].Equals("uploads", StringComparison.OrdinalIgnoreCase))
            return MetadataFolder + "\\" + string.Join('\\', parts.Select(Decode));

        // uploads/<accessor>/<device>/<path...>
        if (parts.Length < 4) { skipReason = "upload outside any device folder"; return null; }

        var device = Decode(parts[2]);
        var letter = DriveLetter(device);
        if (letter is null)
        {
            skipReason = device.Contains("ShadowCopy", StringComparison.OrdinalIgnoreCase)
                ? "volume shadow copies in Velociraptor collections are not supported yet: " + device
                : "not a drive letter: " + device;
            return null;
        }

        var relative = string.Join('\\', parts[3..].Select(Decode));
        if (StreamRenames.TryGetValue(relative, out var renamed)) relative = renamed;
        return letter + "\\" + relative;
    }

    /// <summary>"C:", "\\.\C:" and "\\?\C:" are all drive C; anything else is not a drive letter.</summary>
    internal static string? DriveLetter(string device)
    {
        var d = device;
        if (d.StartsWith(@"\\.\", StringComparison.Ordinal) || d.StartsWith(@"\\?\", StringComparison.Ordinal)) d = d[4..];
        return d.Length == 2 && char.IsAsciiLetter(d[0]) && d[1] == ':' ? char.ToUpperInvariant(d[0]).ToString() : null;
    }

    /// <summary>
    /// One pass of percent-decoding. Uri.UnescapeDataString is not used: it leaves an encoded
    /// sequence alone when the bytes are not valid UTF-8, where this keeps decoding what it can.
    /// </summary>
    public static string Decode(string component)
    {
        if (!component.Contains('%')) return component;

        var bytes = new List<byte>(component.Length);
        for (var i = 0; i < component.Length; i++)
        {
            if (component[i] == '%' && i + 2 < component.Length
                && byte.TryParse(component.AsSpan(i + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out var b))
            {
                bytes.Add(b);
                i += 2;
            }
            else
            {
                // A surrogate pair is one character to UTF-8; split, each half would encode as '?'.
                var length = char.IsHighSurrogate(component[i]) && i + 1 < component.Length ? 2 : 1;
                bytes.AddRange(System.Text.Encoding.UTF8.GetBytes(component.Substring(i, length)));
                i += length - 1;
            }
        }
        return System.Text.Encoding.UTF8.GetString(bytes.ToArray());
    }

    /// <summary>One run of a sparse file: data stored in the zip, or a hole when FileLength is 0.</summary>
    public sealed record SparseRange(long OriginalOffset, long FileOffset, long Length, long FileLength);

    /// <summary>
    /// Reads a &lt;name&gt;.idx. Returns null when it is not a sparse index after all - a file that
    /// merely ends in .idx.
    /// </summary>
    public static IReadOnlyList<SparseRange>? ReadIndex(Stream stream)
    {
        try
        {
            using var doc = JsonDocument.Parse(stream);
            if (!doc.RootElement.TryGetProperty("ranges", out var ranges) || ranges.ValueKind != JsonValueKind.Array)
                return null;

            return ranges.EnumerateArray().Select(r => new SparseRange(
                Long(r, "original_offset"), Long(r, "file_offset"), Long(r, "length"), Long(r, "file_length"))).ToList();
        }
        catch (JsonException)
        {
            return null;
        }

        // Velociraptor leaves a field out when it is zero.
        static long Long(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.TryGetInt64(out var n) ? n : 0;
    }

    /// <summary>The size the file had on the source system.</summary>
    public static long OriginalLength(IReadOnlyList<SparseRange> ranges) =>
        ranges.Count == 0 ? 0 : ranges.Max(r => r.OriginalOffset + r.Length);

    /// <summary>
    /// The USN journal is the one sparse file not expanded: it can be tens of gigabytes of leading
    /// zeros around a few megabytes of records. USN records carry their own USN and MFTECmd finds
    /// them by scanning, so the stored data ranges alone lose nothing.
    /// </summary>
    public static bool KeepCompact(string mappedPath) =>
        mappedPath.EndsWith(@"\$Extend\$J", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The same shape on disk: a Velociraptor zip that has already been unzipped. It still needs
    /// converting, so it is treated like the zip rather than as a collection folder.
    /// </summary>
    public static bool IsFolder(string path) =>
        File.Exists(Path.Combine(path, "client_info.json")) && Directory.Exists(Path.Combine(path, "uploads"));

    /// <summary>
    /// Opens a file from the collection by its name relative to the collection root, '/'-separated
    /// as in the zip, or returns null when it is not there. Works for a zip or an unzipped folder.
    /// </summary>
    public delegate Stream? Opener(string name);

    /// <summary>The host the collector ran on, from client_info.json.</summary>
    public static string? Hostname(Opener open)
    {
        try
        {
            using var stream = open("client_info.json");
            if (stream is null) return null;
            using var doc = JsonDocument.Parse(stream);
            return doc.RootElement.TryGetProperty("Hostname", out var h) && h.ValueKind == JsonValueKind.String
                ? h.GetString()
                : null;
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether the collector says it finished and uploaded everything it meant to, from
    /// collection_context.json. Null when it did; otherwise what the analyst needs to know, because
    /// a collection that stopped part-way parses into output that looks complete.
    /// </summary>
    public static string? IncompleteReason(Opener open)
    {
        try
        {
            using var stream = open("collection_context.json");
            if (stream is null) return "collection_context.json is missing, so completeness cannot be checked";
            using var doc = JsonDocument.Parse(stream);
            var root = doc.RootElement;
            long Get(string name) => root.TryGetProperty(name, out var v) && v.TryGetInt64(out var n) ? n : 0;

            // FlowContext state: 1 running, 2 finished, 3 error.
            var state = Get("state");
            if (state != 2)
                return state == 3 ? "the collector reports an error state" : $"the collector did not finish (state {state})";

            var expected = Get("total_expected_uploaded_bytes");
            var uploaded = Get("total_uploaded_bytes");
            if (uploaded < expected)
                return $"the collector uploaded {CollectionExtractor.Size(uploaded)} of {CollectionExtractor.Size(expected)}";
            return null;
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return "collection_context.json could not be read: " + ex.Message;
        }
    }

    /// <summary>Error-level lines in the collector's own log.json, which the analyst should read.</summary>
    public static int LogErrors(Opener open)
    {
        try
        {
            using var stream = open("log.json");
            if (stream is null) return 0;
            using var reader = new StreamReader(stream);
            var count = 0;
            while (reader.ReadLine() is { } line)
                if (line.Contains("\"level\":\"ERROR\"", StringComparison.Ordinal)) count++;
            return count;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }
}
