using System.Text;

namespace ArtefactForge.Core;

/// <summary>Values a module's CommandLine can reference. Names are matched case-insensitively.</summary>
public sealed class PlaceholderContext
{
    public required string Root { get; init; }
    public required string DestinationDirectory { get; init; }
    public required string ToolsDir { get; init; }
    /// <summary>ArtefactForge's own parser scripts.</summary>
    public string ScriptsDir { get; init; } = "";
    /// <summary>Scratch space for Prepare steps. Deleted after the module; never harvested.</summary>
    public string WorkDir { get; init; } = "";
    /// <summary>
    /// A folder under the case's _Logs\Console for a tool's own log files - Hayabusa writes an
    /// error log into its working directory. Kept with the run, never harvested as output.
    /// </summary>
    public string ToolLogDir { get; init; } = "";
    public required string CaseName { get; init; }
    public required string CollectionName { get; init; }
    public required string ModuleName { get; init; }
    public string? User { get; init; }
    /// <summary>Full path to the current profile directory under Iterate: userprofile.</summary>
    public string? UserHome { get; init; }
    public string? Match { get; init; }
    /// <summary>Resolved module options, already expanded to command-line fragments.</summary>
    public string Options { get; init; } = "";
    public bool VssEnabled { get; init; }
}

public static class Placeholders
{
    /// <summary>
    /// Expands %name% tokens. %sourceDirectory% and %destinationDirectory% are the KAPE-compatible
    /// spellings; the rest are ArtefactForge additions.
    /// </summary>
    public static string Resolve(string template, PlaceholderContext ctx)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["root"]                 = ctx.Root.TrimEnd(Path.DirectorySeparatorChar),
            ["sourceDirectory"]      = ctx.Root.TrimEnd(Path.DirectorySeparatorChar),
            ["destinationDirectory"] = ctx.DestinationDirectory.TrimEnd(Path.DirectorySeparatorChar),
            ["toolsDir"]             = ctx.ToolsDir.TrimEnd(Path.DirectorySeparatorChar),
            ["scriptsDir"]           = ctx.ScriptsDir.TrimEnd(Path.DirectorySeparatorChar),
            ["workDir"]              = ctx.WorkDir.TrimEnd(Path.DirectorySeparatorChar),
            ["toolLogDir"]           = ctx.ToolLogDir.TrimEnd(Path.DirectorySeparatorChar),
            ["options"]              = ctx.Options,
            ["caseName"]             = ctx.CaseName,
            ["collectionName"]       = ctx.CollectionName,
            ["moduleName"]           = ctx.ModuleName,
            ["user"]                 = ctx.User ?? "",
            ["userHome"]             = ctx.UserHome?.TrimEnd(Path.DirectorySeparatorChar) ?? "",
            ["match"]                = ctx.Match ?? "",
            ["matchDir"]             = ctx.Match is null ? "" : (Path.GetDirectoryName(ctx.Match) ?? ""),
            ["matchName"]            = ctx.Match is null ? "" : Path.GetFileName(ctx.Match),
            // Expands to nothing unless the run enables VSS and the tool supports it, so the
            // switch can sit unconditionally in every CommandLine.
            ["vss"]                  = ctx.VssEnabled ? "--vss" : ""
        };

        var result = new StringBuilder();
        for (var i = 0; i < template.Length; i++)
        {
            if (template[i] != '%') { result.Append(template[i]); continue; }

            var close = template.IndexOf('%', i + 1);
            if (close < 0) { result.Append(template[i]); continue; }

            var name = template[(i + 1)..close];
            if (!map.TryGetValue(name, out var value)) { result.Append(template[i]); continue; }

            // A placeholder that resolves to nothing - a disabled %vss%, an absent %user% - would
            // otherwise leave a double space behind. Drop the separator that preceded it rather
            // than collapsing runs of spaces globally, which would corrupt any evidence path
            // containing consecutive spaces.
            if (value.Length == 0 && result.Length > 0 && result[^1] == ' ') result.Length--;
            else result.Append(value);

            i = close;
        }
        return result.ToString().Trim();
    }
}
