using System.Globalization;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxBodyfile module: a filesystem timeline from the bodyfile UAC writes on the live system
/// (bodyfile/bodyfile.txt), in the way mactime reads one.
///
///   LinuxBodyfile_Timeline.csv  one row per file per distinct time, oldest first, with MACB saying
///                               which of its times fall then: m modified, a accessed, c changed
///                               (metadata), b born
///
/// UAC fills the bodyfile with stat on the running system: 0|name|inode|mode|uid|gid|size|atime|
/// mtime|ctime|crtime, times as seconds since the epoch (UTC). A symbolic link's name carries its
/// target ("/etc/localtime -> /usr/share/zoneinfo/UTC"), which is split into its own column. A
/// time of 0 means the system did not record it (birth time on older kernels) and is left out.
///
/// The timeline is sorted in memory, so a bodyfile of several million files needs a few GB; the
/// module is marked memory-heavy so it runs alone.
/// </summary>
public static class BodyfileExport
{
    private readonly record struct Entry(string Path, string Link, string Inode, string Mode, string Uid, string Gid, string Size);

    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var dir = new DirectoryInfo(Path.Combine(root, UacCollection.MetadataFolder, "bodyfile"));
        var files = dir.Exists ? dir.EnumerateFiles("*.txt").OrderBy(f => f.Name, StringComparer.Ordinal).ToList() : [];
        if (files.Count == 0)
        {
            log.WriteLine($"No bodyfile under {dir.FullName}");
            return 0;
        }

        var users = Names(Path.Combine(root, "etc", "passwd"));
        var groups = Names(Path.Combine(root, "etc", "group"));
        var entries = new List<Entry>();
        var sources = new List<string>();
        // time, entry, MACB bits (m=8 a=4 c=2 b=1) - one per file per distinct time.
        var events = new List<(long Time, int Entry, byte Flags)>();

        foreach (var file in files)
        {
            var source = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
            var unread = 0;
            foreach (var line in File.ReadLines(file.FullName))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(line)) continue;
                var parsed = Parse(line);
                if (parsed is null) { unread++; continue; }
                var (entry, times) = parsed.Value;
                var index = entries.Count;
                entries.Add(entry);
                sources.Add(source);

                // Times that coincide are one row: 'm.c.' rather than two.
                foreach (var group in times.Select((t, i) => (Time: t, Bit: (byte)(8 >> i)))
                                           .Where(t => t.Time > 0)
                                           .GroupBy(t => t.Time))
                    events.Add((group.Key, index, (byte)group.Sum(g => g.Bit)));
            }
            if (unread > 0)
                errors.WriteLine($"{source}: {unread} line(s) not in the bodyfile format (11 fields separated by '|') - not parsed");
        }

        events.Sort((x, y) => x.Time != y.Time ? x.Time.CompareTo(y.Time) : string.CompareOrdinal(entries[x.Entry].Path, entries[y.Entry].Path));

        Directory.CreateDirectory(outputDirectory);
        using var csv = new CsvFile(Path.Combine(outputDirectory, "LinuxBodyfile_Timeline.csv"),
            "TimestampUtc", "MACB", "Path", "LinkTarget", "Size", "Mode", "User", "Group", "Inode", "SourceFile");
        foreach (var (time, index, flags) in events)
        {
            var e = entries[index];
            csv.Write(DateTime.UnixEpoch.AddSeconds(time).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                      Macb(flags), e.Path, e.Link, e.Size, e.Mode, Named(users, e.Uid), Named(groups, e.Gid), e.Inode, sources[index]);
        }

        log.WriteLine($"  {csv.FileName,-32} {csv.Rows} row(s) from {entries.Count} file(s)");
        return 0;
    }

    /// <summary>
    /// One bodyfile line. A name may itself contain '|', so the ten fixed fields are taken from
    /// the ends and the name is whatever lies between.
    /// </summary>
    private static (Entry Entry, long[] Times)? Parse(string line)
    {
        var parts = line.Split('|');
        if (parts.Length < 11) return null;
        var tail = parts[^9..];
        var name = string.Join('|', parts[1..^9]);

        var times = new long[4];
        // bodyfile order is atime, mtime, ctime, crtime; MACB order is m, a, c, b.
        int[] order = [1, 0, 2, 3];
        for (var i = 0; i < 4; i++)
        {
            var raw = tail[5 + order[i]];
            if (!long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out times[i]))
            {
                if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d)) times[i] = (long)d;
                else if (raw is "" or "-" or "?") times[i] = 0;
                else return null;
            }
        }

        var link = "";
        var arrow = name.IndexOf(" -> ", StringComparison.Ordinal);
        if (arrow > 0 && tail[1].StartsWith('l'))
        {
            link = name[(arrow + 4)..];
            name = name[..arrow];
        }
        return (new Entry(name, link, tail[0], tail[1], tail[2], tail[3], tail[4]), times);
    }

    private static string Macb(byte flags) => new([
        (flags & 8) != 0 ? 'm' : '.', (flags & 4) != 0 ? 'a' : '.', (flags & 2) != 0 ? 'c' : '.', (flags & 1) != 0 ? 'b' : '.'
    ]);

    private static Dictionary<string, string> Names(string path)
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!File.Exists(path)) return names;
        foreach (var line in File.ReadLines(path))
        {
            var f = line.Split(':');
            if (f.Length >= 3) names.TryAdd(f[2], f[0]);
        }
        return names;
    }

    private static string Named(Dictionary<string, string> names, string id) =>
        names.TryGetValue(id, out var name) ? $"{name} ({id})" : id;
}
