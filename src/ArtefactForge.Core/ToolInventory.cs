namespace ArtefactForge.Core;

/// <summary>One executable referenced by the module library, and whether it can actually be found.</summary>
public sealed record ToolUsage(
    string Executable,
    IReadOnlyList<string> Modules,
    string? ResolvedPath,
    string? Version,
    string? Sha256,
    string? ToolRoot,
    bool IsSystem)
{
    public bool Found => ResolvedPath is not null;
    public int ModuleCount => Modules.Count;

    /// <summary>Top-level folder under the tool root, e.g. "eztools" - the thing you update.</summary>
    public string Package => IsSystem
        ? "windows"
        : Builtins.IsBuiltin(Executable)
            ? "ArtefactForge"
            : Executable.Split('\\', '/').FirstOrDefault() ?? Executable;
}

public static class ToolInventory
{
    /// <summary>
    /// The tool roots a run searches: the package's own Tools\, a sibling EZ-Tools\ when there is
    /// one, then any roots the analyst added. One list, so the tool check and a run agree.
    /// </summary>
    public static List<string> Roots(string appRoot, IEnumerable<string>? extra = null)
    {
        var roots = new List<string> { Path.Combine(appRoot, "Tools") };
        // Convenience: EZ Tools usually live beside the package rather than inside it.
        var sibling = Path.GetFullPath(Path.Combine(appRoot, "..", "EZ-Tools"));
        if (Directory.Exists(sibling)) roots.Add(sibling);
        if (extra is not null) roots.AddRange(extra);
        return roots;
    }

    /// <summary>
    /// Every executable the selected modules need, resolved against the tool roots. Answers the
    /// question a module list cannot: will these modules actually run on this machine.
    /// </summary>
    public static IReadOnlyList<ToolUsage> Scan(
        IEnumerable<ModuleDefinition> modules, IReadOnlyList<string> toolRoots)
    {
        var users = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var module in modules)
        foreach (var processor in module.Processors.Concat(module.Prepare))
        {
            if (!users.TryGetValue(processor.Executable, out var list))
                users[processor.Executable] = list = [];
            if (!list.Contains(module.Name)) list.Add(module.Name);
        }

        return users
            .Select(entry =>
            {
                var resolved = ToolResolver.Resolve(entry.Key, toolRoots);
                return new ToolUsage(
                    entry.Key,
                    entry.Value.OrderBy(m => m, StringComparer.OrdinalIgnoreCase).ToList(),
                    resolved?.FullPath,
                    resolved?.Version,
                    resolved?.Sha256,
                    resolved?.ToolRoot,
                    // Absolute paths are Windows' own tools - esentutl, reg - not something to update.
                    Path.IsPathRooted(entry.Key));
            })
            .OrderBy(t => t.IsSystem)
            .ThenBy(t => t.Package, StringComparer.OrdinalIgnoreCase)
            .ThenBy(t => t.Executable, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Reads Tools\VERSIONS.txt, written when the tools were staged.</summary>
    public static string? DeclaredVersion(string toolRoot, string package)
    {
        var path = Path.Combine(toolRoot, "VERSIONS.txt");
        if (!File.Exists(path)) return null;

        try
        {
            foreach (var line in File.ReadLines(path))
            {
                var trimmed = line.TrimStart();
                if (!trimmed.StartsWith(package, StringComparison.OrdinalIgnoreCase)) continue;

                var version = trimmed.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries)
                                     .FirstOrDefault(part => part.StartsWith('v') && part.Any(char.IsDigit));
                if (version is not null) return version.TrimStart('v');
            }
        }
        catch { /* the inventory is still useful without it */ }
        return null;
    }
}
