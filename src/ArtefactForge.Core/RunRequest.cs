using System.Text.Json;

namespace ArtefactForge.Core;

/// <summary>
/// A saved module selection. Shared by the GUI's profile dropdown and the CLI's --profile, so a
/// selection built by clicking is the same file a scheduled task consumes.
/// </summary>
public sealed class ProfileFile
{
    public string Name { get; set; } = "";
    public List<string> Modules { get; set; } = [];

    /// <summary>
    /// Tuned module options, keyed by module then option. A profile that only picks modules leaves
    /// this empty, so profiles written before options existed still load unchanged.
    /// </summary>
    public Dictionary<string, Dictionary<string, string>> Options { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public static string Directory(string repoRoot) => Path.Combine(repoRoot, "Profiles");

    public static ProfileFile? Load(string repoRoot, string name)
    {
        var path = Path.Combine(Directory(repoRoot), name + ".json");
        if (!File.Exists(path)) return null;
        return JsonSerializer.Deserialize<ProfileFile>(File.ReadAllText(path), Json.Options);
    }
}

/// <summary>
/// A whole run described as data, for headless and scheduled use: ArtefactForge.Cli run --config
/// nightly.json. Command-line flags override anything the file sets.
/// </summary>
public sealed class RunRequest
{
    public string? CaseName { get; set; }
    /// <summary>
    /// Overrides the detected collection name. Single-target runs only: a mounted image is named
    /// after its drive letter, which says nothing about the host.
    /// </summary>
    public string? Host { get; set; }
    public string? Evidence { get; set; }
    public string? Output { get; set; }
    /// <summary>Treat each subfolder and .zip in Evidence as its own collection.</summary>
    public bool Batch { get; set; }
    /// <summary>Where zipped collections are extracted. Null means &lt;case&gt;\_Extracted.</summary>
    public string? ExtractTo { get; set; }
    /// <summary>Delete each zip's extracted data once its modules have finished.</summary>
    public bool CleanupExtracted { get; set; }
    /// <summary>Zips extracted and parsed at the same time. Null means the default, 2.</summary>
    public int? ZipsAtOnce { get; set; }
    /// <summary>Explicit module names. Takes precedence over Categories and Profile.</summary>
    public List<string> Modules { get; set; } = [];
    public List<string> Categories { get; set; } = [];
    /// <summary>Name of a file in \Profiles, without the .json extension.</summary>
    public string? Profile { get; set; }
    /// <summary>Extra folders to search for module executables.</summary>
    public List<string> ToolRoots { get; set; } = [];
    public int? Workers { get; set; }
    public int? HeavyWorkers { get; set; }
    public bool Vss { get; set; }
    public bool SkipCompleted { get; set; } = true;

    /// <summary>Per-module option overrides as "Module.Option" -> value, so they survive a config file.</summary>
    public Dictionary<string, string> Set { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public static RunRequest Load(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Run config not found.", path);
        return JsonSerializer.Deserialize<RunRequest>(File.ReadAllText(path), Json.Options)
               ?? throw new FormatException("Run config is empty or not valid JSON.");
    }

    public void Save(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory)) System.IO.Directory.CreateDirectory(directory);
        File.WriteAllText(path, JsonSerializer.Serialize(this, Json.Indented));
    }
}

internal static class Json
{
    internal static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };
    internal static readonly JsonSerializerOptions Indented =
        new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
}
