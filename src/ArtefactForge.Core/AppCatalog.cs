namespace ArtefactForge.Core;

/// <summary>A GUI program listed in Apps.yaml, and where it was found - if it was.</summary>
public sealed record AppEntry(
    string Name,
    string Description,
    string Executable,
    string? ResolvedPath,
    string LookedFor)
{
    public bool Found => ResolvedPath is not null;
}

public sealed class AppCatalogResult
{
    public List<AppEntry> Apps { get; } = [];

    /// <summary>Why the file could not be used. Null when it loaded, including when it listed nothing.</summary>
    public string? Error { get; set; }

    public bool FileMissing { get; set; }
}

/// <summary>
/// The Apps list on the Tools tab: the GUI programs an analyst opens alongside ArtefactForge.
/// Read from Apps.yaml only - there is deliberately no automatic discovery, so the list is exactly
/// what the file says and installers or uninstallers never turn up because they happen to be GUI
/// executables under a tool root.
/// </summary>
public static class AppCatalog
{
    public const string FileName = "Apps.yaml";

    /// <summary>Written when the analyst presses Edit list and no file exists yet.</summary>
    public const string Template = """
        # Programs listed on the Tools tab, each with an Open button. Order here is display order.
        # Executable is either relative to a tool root (Tools\, or a sibling EZ-Tools\) or a full path.
        #
        # Apps:
        #   -
        #     Name: Timeline Explorer
        #     Description: Filter, sort and search CSV output
        #     Executable: eztools\TimelineExplorer\TimelineExplorer.exe

        Apps:
        """;

    /// <summary>Never throws: a missing or malformed file is reported in the result.</summary>
    public static AppCatalogResult Load(string path, IReadOnlyList<string> toolRoots)
    {
        var result = new AppCatalogResult();
        if (!File.Exists(path))
        {
            result.FileMissing = true;
            return result;
        }

        AppsDto? dto;
        try
        {
            dto = Yaml.Deserializer.Deserialize<AppsDto>(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            // YamlDotNet's message already carries the line and column.
            result.Error = $"{FileName} could not be read: {ex.Message}";
            return result;
        }

        var entries = dto?.Apps ?? [];
        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            if (e is null) continue;

            var name = string.IsNullOrWhiteSpace(e.Name) ? $"Entry {i + 1}" : e.Name.Trim();
            if (string.IsNullOrWhiteSpace(e.Executable))
            {
                result.Apps.Add(new AppEntry(name, "no Executable given in " + FileName, "", null, ""));
                continue;
            }

            var executable = e.Executable.Trim();
            result.Apps.Add(new AppEntry(
                name,
                e.Description?.Trim() ?? "",
                executable,
                Resolve(executable, toolRoots),
                Path.IsPathRooted(executable) || toolRoots.Count == 0
                    ? executable
                    : Path.Combine(toolRoots[0], executable)));
        }
        return result;
    }

    /// <summary>
    /// Same rules as a module's Executable: a full path as-is, otherwise the first tool root that
    /// holds it. Not ToolResolver, which also hashes the file - pointless work for a launcher.
    /// </summary>
    private static string? Resolve(string executable, IReadOnlyList<string> toolRoots)
    {
        if (Path.IsPathRooted(executable)) return File.Exists(executable) ? executable : null;
        foreach (var root in toolRoots)
        {
            var candidate = Path.Combine(root, executable);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private sealed class AppsDto
    {
        public List<AppDto?>? Apps { get; set; }
    }

    private sealed class AppDto
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? Executable { get; set; }
    }
}
