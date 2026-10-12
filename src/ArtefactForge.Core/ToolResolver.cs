using System.Security.Cryptography;

namespace ArtefactForge.Core;

public sealed record ResolvedTool(string FullPath, string ToolRoot, string? Version, string Sha256);

/// <summary>
/// Finds a module's Executable across the configured tool roots and records what was actually
/// run - version and hash - so a report can state which binary produced a given output.
/// </summary>
public static class ToolResolver
{
    private static readonly Dictionary<string, ResolvedTool> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Lock Gate = new();

    public static ResolvedTool? Resolve(string executable, IReadOnlyList<string> toolRoots)
    {
        // A builtin parser is part of this build: its version and hash are ArtefactForge's own.
        if (Builtins.IsBuiltin(executable))
            return Builtins.Exists(executable)
                ? new ResolvedTool(executable, AppContext.BaseDirectory, BuildInfo.InformationalVersion, BuildInfo.Sha256 ?? "")
                : null;

        var candidates = Path.IsPathRooted(executable)
            ? [executable]
            : toolRoots.Select(root => Path.Combine(root, executable)).ToArray();

        foreach (var candidate in candidates)
        {
            if (!File.Exists(candidate)) continue;

            lock (Gate)
            {
                if (Cache.TryGetValue(candidate, out var cached)) return cached;

                var root = Path.IsPathRooted(executable)
                    ? Path.GetDirectoryName(candidate) ?? ""
                    : toolRoots.First(r => candidate.StartsWith(r, StringComparison.OrdinalIgnoreCase));

                var resolved = new ResolvedTool(candidate, root, ToolVersion.Read(candidate), Hash(candidate));
                Cache[candidate] = resolved;
                return resolved;
            }
        }
        return null;
    }

    private static string Hash(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch { return ""; }
    }
}
