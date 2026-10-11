using System.Text.RegularExpressions;

namespace ArtefactForge.Core;

/// <summary>
/// Converts a UAC (Unix-like Artifacts Collector) collection into the Linux filesystem-root shape
/// the Linux modules already read. UAC writes a .tar.gz by default, or a .tar where the target has
/// no gzip, or a .zip; all three hold the same tree:
/// <list type="bullet">
/// <item>[root]/ - the collected files at their original paths: [root]/etc/passwd.</item>
/// <item>uac.log - the collector's own log, which records the host name.</item>
/// <item>live_response/, bodyfile/, hash_executables/ and others - command output and lists
/// UAC made on the system, not files from it.</item>
/// </list>
/// [root] becomes the root of the converted tree, and everything else goes under _UAC so no
/// module mistakes the collector's output for the system's files.
/// </summary>
public static partial class UacCollection
{
    public const string MetadataFolder = "_UAC";
    private const string RootFolder = "[root]";
    private const string Log = "uac.log";

    /// <summary>UAC always writes uac.log at the top, beside [root].</summary>
    public static bool IsCollection(IEnumerable<string> entryNames)
    {
        var log = false;
        var root = false;
        foreach (var name in entryNames)
        {
            if (name.Equals(Log, StringComparison.Ordinal)) log = true;
            else if (name.StartsWith(RootFolder + "/", StringComparison.Ordinal)) root = true;
            if (log && root) return true;
        }
        return false;
    }

    /// <summary>The same shape on disk: a UAC archive that has already been unpacked, or one made with --output-format none.</summary>
    public static bool IsFolder(string path) =>
        File.Exists(Path.Combine(path, Log)) && Directory.Exists(Path.Combine(path, RootFolder));

    /// <summary>
    /// Where an entry belongs in the converted tree, '/'-separated, or null for the [root] folder
    /// itself, which becomes the tree's root.
    /// </summary>
    public static string? MapEntry(string entryName)
    {
        var name = entryName.TrimEnd('/');
        if (name == RootFolder) return null;
        if (name.StartsWith(RootFolder + "/", StringComparison.Ordinal))
            return entryName[(RootFolder.Length + 1)..];
        return MetadataFolder + "/" + entryName;
    }

    /// <summary>
    /// The host, from the "Hostname:" line uac.log opens with, or failing that from UAC's default
    /// archive name, uac-&lt;host&gt;-&lt;os&gt;-&lt;yyyyMMddHHmmss&gt;.
    /// </summary>
    public static string? Hostname(VelociraptorCollection.Opener open, string archivePath)
    {
        try
        {
            using var stream = open(Log);
            if (stream is not null)
            {
                using var reader = new StreamReader(stream);
                for (var i = 0; i < 200 && reader.ReadLine() is { } line; i++)
                {
                    var match = HostLine().Match(line);
                    if (match.Success) return match.Groups[1].Value;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            // Unreadable here means the extraction will report it; the archive name still serves.
        }

        var named = ArchiveName().Match(CollectionSource.Stem(archivePath));
        return named.Success ? named.Groups[1].Value : null;
    }

    /// <summary>Error lines in uac.log: commands that failed on the system, which the analyst should read.</summary>
    public static int LogErrors(VelociraptorCollection.Opener open)
    {
        try
        {
            using var stream = open(Log);
            if (stream is null) return 0;
            using var reader = new StreamReader(stream);
            var count = 0;
            while (reader.ReadLine() is { } line)
                if (line.Contains(" ERR ", StringComparison.Ordinal)) count++;
            return count;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    [GeneratedRegex(@"\bINF\s+Hostname:\s*(\S+)\s*$")]
    private static partial Regex HostLine();

    // A host name can contain '-', so the OS and timestamp are anchored from the end.
    [GeneratedRegex(@"^uac-(.+)-(?:aix|android|esxi|freebsd|linux|macos|netbsd|netscaler|openbsd|solaris)-\d{14}$",
                    RegexOptions.IgnoreCase)]
    private static partial Regex ArchiveName();
}
