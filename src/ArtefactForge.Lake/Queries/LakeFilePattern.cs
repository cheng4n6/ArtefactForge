using System.IO.Enumeration;

namespace ArtefactForge.Lake.Queries;

/// <summary>
/// A host-relative file pattern as a saved query's <c>files:</c> line gives it, matched against
/// the lake's source paths ('/' separators) the way ArtefactForge's own steps find their input
/// with Directory.EnumerateFiles: the folder names without regard to case, the file name with
/// Windows' wildcard rules.
///
///   Registry/*ProfileList*.csv            files directly in Registry
///   LNKFiles/**/*LECmd_Recent*.csv        files in LNKFiles or any folder below it
/// </summary>
public static class LakeFilePattern
{
    private const string AnyDepth = "**";

    public static bool IsValid(string pattern)
    {
        var parts = pattern.Split('/');
        if (parts.Length < 2 || parts.Any(p => p.Length == 0)) return false;
        var folders = parts[..^1];
        // ** only as the last folder, and no wildcards in the folders before it.
        for (var i = 0; i < folders.Length; i++)
        {
            if (folders[i] == AnyDepth) { if (i != folders.Length - 1 || i == 0) return false; continue; }
            if (folders[i].IndexOfAny(['*', '?']) >= 0) return false;
        }
        return true;
    }

    /// <summary>Whether <paramref name="path"/> (relative to the host folder, '/' separators) matches.</summary>
    public static bool Matches(string pattern, string path)
    {
        var parts = pattern.Split('/');
        var recursive = parts[^2] == AnyDepth;
        var folders = recursive ? parts[..^2] : parts[..^1];
        var name = parts[^1];

        var segments = path.Split('/');
        if (recursive ? segments.Length < folders.Length + 1 : segments.Length != folders.Length + 1) return false;
        for (var i = 0; i < folders.Length; i++)
            if (!segments[i].Equals(folders[i], StringComparison.OrdinalIgnoreCase)) return false;
        return FileSystemName.MatchesWin32Expression(FileSystemName.TranslateWin32Expression(name), segments[^1], ignoreCase: true);
    }
}
