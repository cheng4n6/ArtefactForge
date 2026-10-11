namespace ArtefactForge.Core.Update;

/// <summary>
/// <c>files.txt</c> at the package root: every file the package installed, with its SHA-256. Written
/// by package.ps1. It is how an update tells the package's own files - which it may replace or
/// remove - from anything the analyst added or edited, which it must leave alone.
///
/// Format, one file per line: <c>&lt;64 hex&gt; &lt;relative\path&gt;</c>. Lines starting '#' are comments.
/// Tools\ is never listed: tools are versioned separately and an update never touches them.
/// </summary>
public sealed class PackageManifest
{
    public const string FileName = "files.txt";

    /// <summary>Relative path (backslash-separated, as written) to upper-case hex SHA-256.</summary>
    public IReadOnlyDictionary<string, string> Files { get; }

    private PackageManifest(Dictionary<string, string> files) => Files = files;

    public static PackageManifest Empty { get; } = new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    public static PackageManifest? Load(string packageRoot)
    {
        var path = Path.Combine(packageRoot, FileName);
        return File.Exists(path) ? Parse(File.ReadAllLines(path)) : null;
    }

    public static PackageManifest Parse(IEnumerable<string> lines)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            var space = line.IndexOf(' ');
            if (space != 64 || !line[..64].All(Uri.IsHexDigit))
                throw new UpdateException($"{FileName} has a malformed line: '{line}'.");

            var relative = Normalise(line[(space + 1)..].Trim());
            CheckSafe(relative);
            files[relative] = line[..64].ToUpperInvariant();
        }
        return new PackageManifest(files);
    }

    /// <summary>One separator style, so a manifest written on Windows compares equal everywhere.</summary>
    public static string Normalise(string relative) => relative.Replace('/', '\\').TrimStart('\\');

    /// <summary>The path on this machine for a manifest-relative path.</summary>
    public static string Local(string root, string relative) =>
        Path.Combine(root, relative.Replace('\\', Path.DirectorySeparatorChar));

    /// <summary>
    /// A signed package still only gets to write inside the application folder, and never into the
    /// parts of it that belong to the analyst or to the updater itself.
    /// </summary>
    private static void CheckSafe(string relative)
    {
        var parts = relative.Split('\\');
        var bad = relative.Length == 0 || relative.Contains(':') || Path.IsPathRooted(relative.Replace('\\', '/'))
                  || parts.Any(p => p is "" or "." or "..")
                  || parts[0].Equals("Tools", StringComparison.OrdinalIgnoreCase)
                  || parts[0].Equals(SelfUpdater.UpdateFolder, StringComparison.OrdinalIgnoreCase)
                  || parts[0].Equals(SelfUpdater.PreviousFolder, StringComparison.OrdinalIgnoreCase)
                  || relative.Equals(FileName, StringComparison.OrdinalIgnoreCase);
        if (bad) throw new UpdateException($"{FileName} lists a path an update may not write: '{relative}'.");
    }
}
