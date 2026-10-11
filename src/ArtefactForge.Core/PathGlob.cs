namespace ArtefactForge.Core;

/// <summary>
/// Wildcard expansion over a rooted path. Supports '*' and '?' within a segment, which is all
/// the module Requires globs need; recursive '**' is deliberately not supported because
/// artefact locations are known and unbounded recursion over a Users tree is ruinous.
/// </summary>
public static class PathGlob
{
    private static readonly char[] Separators = [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar];

    public static bool HasWildcard(string value) => value.Contains('*') || value.Contains('?');

    public static IReadOnlyList<string> Expand(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return [];

        var root = Path.GetPathRoot(pattern);
        if (string.IsNullOrEmpty(root)) return [];

        var segments = pattern[root.Length..].Split(Separators, StringSplitOptions.RemoveEmptyEntries);
        var current = new List<string> { root };

        for (var i = 0; i < segments.Length; i++)
        {
            var segment = segments[i];
            var isLast = i == segments.Length - 1;
            var next = new List<string>();

            foreach (var dir in current)
            {
                try
                {
                    if (HasWildcard(segment))
                    {
                        // Directory-only for intermediate segments: a file cannot be descended into.
                        next.AddRange(isLast
                            ? Directory.EnumerateFileSystemEntries(dir, segment)
                            : Directory.EnumerateDirectories(dir, segment));
                    }
                    else
                    {
                        var combined = Path.Combine(dir, segment);
                        if (isLast ? (File.Exists(combined) || Directory.Exists(combined))
                                   : Directory.Exists(combined))
                            next.Add(combined);
                    }
                }
                catch (UnauthorizedAccessException) { /* locked live-system paths are expected */ }
                catch (DirectoryNotFoundException) { }
                catch (IOException) { }
            }
            current = next;
            if (current.Count == 0) return [];
        }
        return current;
    }

    /// <summary>True when the pattern matches at least one file or directory.</summary>
    public static bool AnyMatch(string pattern) => Expand(pattern).Count > 0;
}
