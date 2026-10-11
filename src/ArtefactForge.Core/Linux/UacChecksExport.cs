using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// Two small outputs of a UAC collection that are lists, not files from the system:
///
///   LinuxExecutableHashes.csv  hash_executables: a hash of every executable file UAC found, one
///                              row per file with whichever of MD5, SHA-1 and SHA-256 it recorded,
///                              ready to check against a hash set; files in temporary folders or
///                              hidden ones are marked
///   LinuxChkrootkit.csv        chkrootkit's verdict for each check, with anything it found listed,
///                              and the findings marked for review
/// </summary>
public static partial class UacChecksExport
{
    public static int Hashes(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var dir = Path.Combine(root, UacCollection.MetadataFolder, "hash_executables");
        var lists = new[] { "md5", "sha1", "sha256" }
            .Select(a => (Algorithm: a, Path: Path.Combine(dir, "hash_executables." + a)))
            .Where(l => File.Exists(l.Path))
            .ToList();
        if (lists.Count == 0)
        {
            log.WriteLine($"No hash_executables lists under {dir}");
            return 0;
        }

        // One row per file: the lists are separate runs over the same files.
        var rows = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var (algorithm, path) in lists)
        {
            var read = 0;
            foreach (var (hash, file) in LiveResponseExport.HashLines(path))
            {
                cancellationToken.ThrowIfCancellationRequested();
                read++;
                if (!rows.TryGetValue(file, out var row))
                {
                    rows[file] = row = new Dictionary<string, string>(StringComparer.Ordinal);
                    order.Add(file);
                }
                row[algorithm] = hash;
            }
            var lines = File.ReadLines(path).Count(l => !string.IsNullOrWhiteSpace(l));
            if (read < lines)
                errors.WriteLine($"{Path.GetFileName(path)}: {lines - read} line(s) not in a hash-and-path format - not parsed");
        }

        Directory.CreateDirectory(outputDirectory);
        using var csv = new CsvFile(Path.Combine(outputDirectory, "LinuxExecutableHashes.csv"),
            "Path", "MD5", "SHA1", "SHA256", "Review", "SourceFile");
        var source = string.Join("; ", lists.Select(l => Path.GetRelativePath(root, l.Path).Replace('\\', '/')));
        foreach (var file in order.OrderBy(f => f, StringComparer.Ordinal))
        {
            var row = rows[file];
            csv.Write(file, row.GetValueOrDefault("md5", ""), row.GetValueOrDefault("sha1", ""),
                      row.GetValueOrDefault("sha256", ""), PathReview(file), source);
        }
        log.WriteLine($"  {csv.FileName,-32} {csv.Rows} row(s)");
        return 0;
    }

    internal static string PathReview(string path)
    {
        if (TempFolder().IsMatch(path)) return "executable in a temporary or shared-memory folder";
        if (HiddenFolder().IsMatch(path)) return "executable in a hidden folder";
        return "";
    }

    [GeneratedRegex(@"^/(tmp|var/tmp|dev/shm|run/shm|run/user/\d+)/")]
    private static partial Regex TempFolder();

    [GeneratedRegex(@"/\.[^/]+/")]
    private static partial Regex HiddenFolder();

    public static int Chkrootkit(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var dir = new DirectoryInfo(Path.Combine(root, UacCollection.MetadataFolder, "chkrootkit"));
        var files = dir.Exists ? dir.EnumerateFiles("*.txt").OrderBy(f => f.Name, StringComparer.Ordinal).ToList() : [];
        if (files.Count == 0)
        {
            log.WriteLine($"No chkrootkit output under {dir.FullName}");
            return 0;
        }

        Directory.CreateDirectory(outputDirectory);
        using var csv = new CsvFile(Path.Combine(outputDirectory, "LinuxChkrootkit.csv"), "Check", "Result", "Detail", "Review", "SourceFile");
        foreach (var file in files)
        {
            var source = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
            string? check = null, result = null;
            var detail = new List<string>();
            void Flush()
            {
                if (check is null) return;
                var all = result + " " + string.Join(" ", detail);
                var review = Finding().IsMatch(all) && !Clean().IsMatch(result ?? "") ? "yes" : "";
                csv.Write(check, result ?? "", string.Join(" | ", detail), review, source);
            }

            foreach (var line in File.ReadLines(file.FullName))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("ROOTDIR is", StringComparison.Ordinal)) continue;
                var m = CheckLine().Match(line);
                if (m.Success)
                {
                    Flush();
                    (check, result, detail) = (m.Groups[1].Value + m.Groups[2].Value, m.Groups[3].Value.Trim(), []);
                    continue;
                }
                if (check is null) { (check, result, detail) = ("(preamble)", "", []); }
                detail.Add(line.Trim());
            }
            Flush();
        }
        log.WriteLine($"  {csv.FileName,-32} {csv.Rows} row(s)");
        return 0;
    }

    // Checking `sshd'...   not infected      /     Searching for Linux.Xor.DDoS ... INFECTED: ...
    [GeneratedRegex(@"^(?:Checking `([^']+)'|(Searching for .+?))\s*\.\.\.\s*(.*)$")]
    private static partial Regex CheckLine();

    [GeneratedRegex(@"INFECTED|Vulnerable|WARNING|Warning|suspicious|Possible", RegexOptions.None)]
    private static partial Regex Finding();

    [GeneratedRegex(@"^(not infected|not found|nothing found|nothing detected|no suspicious|not tested|not vulnerable)", RegexOptions.IgnoreCase)]
    private static partial Regex Clean();
}
