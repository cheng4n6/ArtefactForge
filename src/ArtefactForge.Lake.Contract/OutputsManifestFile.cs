using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArtefactForge.Lake.Contract;

/// <summary>Reads, writes and merges outputs.json.</summary>
public static class OutputsManifestFile
{
    public const string FileName = "outputs.json";

    /// <summary>
    /// The folder a killed or failed tool's partial output goes to. Nothing in it is complete, so
    /// nothing in it is ever listed.
    /// </summary>
    public const string IncompleteFolder = "_Incomplete";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        // Analysts read this file: a command line keeps its quotes and a build its '+', rather
        // than " and +. It is never embedded in HTML, where the escaping would matter.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>&lt;hostFolder&gt;\outputs.json.</summary>
    public static string PathIn(string hostFolder) => Path.Combine(hostFolder, FileName);

    /// <summary>
    /// Reads an outputs.json. Null when the file does not exist. Throws
    /// <see cref="InvalidDataException"/> when it is not one, and
    /// <see cref="UnsupportedFormatVersionException"/> for a format version this library cannot
    /// read, so a caller never mistakes either for an empty list.
    /// </summary>
    public static OutputsManifest? Read(string path)
    {
        if (!File.Exists(path)) return null;
        return Parse(File.ReadAllText(path), path);
    }

    /// <summary>Parses outputs.json text; <paramref name="source"/> names it in errors.</summary>
    public static OutputsManifest Parse(string json, string source = FileName)
    {
        OutputsManifest? manifest;
        try { manifest = JsonSerializer.Deserialize<OutputsManifest>(json, JsonOptions); }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"{source} could not be read: {ex.Message}", ex);
        }

        if (manifest is null) throw new InvalidDataException($"{source} is empty.");
        if (!string.Equals(manifest.Format, OutputsManifest.FormatName, StringComparison.Ordinal))
            throw new InvalidDataException(
                $"{source} is not an outputs list: its format is '{manifest.Format}', not '{OutputsManifest.FormatName}'.");
        if (manifest.FormatVersion != OutputsManifest.CurrentFormatVersion)
            throw new UnsupportedFormatVersionException(manifest.FormatVersion,
                $"{source} is format version {manifest.FormatVersion}; this build reads version " +
                $"{OutputsManifest.CurrentFormatVersion}. A newer program wrote it.");
        return manifest;
    }

    public static string Serialise(OutputsManifest manifest) => JsonSerializer.Serialize(manifest, JsonOptions);

    /// <summary>
    /// Writes the file whole or not at all: to a temporary file beside it, then moved over it, so
    /// a reader never sees half a list.
    /// </summary>
    public static void Write(string path, OutputsManifest manifest)
    {
        var temp = path + ".tmp";
        try
        {
            File.WriteAllText(temp, Serialise(manifest));
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The write itself has already failed and been reported; a stray .tmp is harmless.
            }
        }
    }

    /// <summary>
    /// The list after a run: <paramref name="update"/>'s entries replace the existing entries for
    /// the same paths, the rest are kept, and any entry whose file is no longer in
    /// <paramref name="hostFolder"/>, or that lies under <see cref="IncompleteFolder"/>, is dropped.
    /// Host details the update does not know (null) are kept from the existing list.
    /// </summary>
    public static OutputsManifest Merge(OutputsManifest? existing, OutputsManifest update, string hostFolder)
    {
        var byPath = new Dictionary<string, OutputEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in existing?.Outputs ?? [])
            byPath[NormalisePath(entry.Path)] = entry with { Path = NormalisePath(entry.Path) };
        foreach (var entry in update.Outputs)
            byPath[NormalisePath(entry.Path)] = entry with { Path = NormalisePath(entry.Path) };

        var kept = byPath.Values
            .Where(e => IsListable(e.Path) && File.Exists(Path.Combine(hostFolder, e.Path)))
            .OrderBy(e => e.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var host = existing is null ? update.Host : update.Host with
        {
            Hostname = update.Host.Hostname ?? existing.Host.Hostname,
            Platform = update.Host.Platform ?? existing.Host.Platform,
            TimeZone = update.Host.TimeZone ?? existing.Host.TimeZone,
            CollectedUtc = update.Host.CollectedUtc ?? existing.Host.CollectedUtc,
            Collector = update.Host.Collector ?? existing.Host.Collector
        };

        return update with { Host = host, Outputs = kept };
    }

    /// <summary>A path relative to the host folder, with '/' separators: "EventLogs/EvtxECmd_EventLogs.csv".</summary>
    public static string RelativePath(string hostFolder, string file) =>
        NormalisePath(Path.GetRelativePath(hostFolder, file));

    public static string NormalisePath(string path) => path.Replace('\\', '/');

    /// <summary>
    /// False for a path that is outside the host folder, absolute, or under
    /// <see cref="IncompleteFolder"/>: none of those may be listed.
    /// </summary>
    public static bool IsListable(string path)
    {
        var normal = NormalisePath(path);
        if (normal.Length == 0 || Path.IsPathRooted(normal)) return false;
        var parts = normal.Split('/');
        return !parts.Any(p => p is ".." or "." or "")
               && !string.Equals(parts[0], IncompleteFolder, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The JSON Schema of outputs.json.</summary>
    public static string Schema()
    {
        using var stream = typeof(OutputsManifestFile).Assembly
            .GetManifestResourceStream("ArtefactForge.Lake.Contract.outputs.schema.json")
            ?? throw new InvalidOperationException("outputs.schema.json is missing from ArtefactForge.Lake.Contract.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

/// <summary>
/// An outputs.json in a format version this build cannot read. A writer must leave such a file
/// alone: it was written by a newer program and replacing it would lose what that program knew.
/// </summary>
public sealed class UnsupportedFormatVersionException(int formatVersion, string message)
    : Exception(message)
{
    public int FormatVersion { get; } = formatVersion;
}
