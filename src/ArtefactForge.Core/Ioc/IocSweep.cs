using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using ArtefactForge.Core.Report;

namespace ArtefactForge.Core.Ioc;

/// <summary>One row of IocHits.csv: an IOC found in one line of one host's output.</summary>
public sealed record IocHit(
    string IocType, string Ioc, string Host, string Module, string Time, string OutputFile,
    long LineNumber, string MatchingLine);

/// <summary>Hits and hosts for one IOC, for the count beside it in the list.</summary>
public sealed record IocHitCount(int Hits, int Hosts);

public sealed class IocSweepResult
{
    public int Iocs { get; init; }
    public int Hosts { get; init; }
    public int FilesScanned { get; init; }
    public long BytesScanned { get; init; }
    public int Hits { get; init; }
    public int HostsWithHits { get; init; }
    public double DurationSeconds { get; init; }
    /// <summary>Files or folders that could not be read: the sweep is incomplete for those.</summary>
    public IReadOnlyList<string> Problems { get; init; } = [];

    /// <summary>One line for the app and the log.</summary>
    public string Describe()
    {
        var size = BytesScanned >= 1L << 30 ? $"{BytesScanned / (double)(1L << 30):N1} GB"
                 : BytesScanned >= 1L << 20 ? $"{BytesScanned / (double)(1L << 20):N0} MB"
                 : $"{Math.Ceiling(BytesScanned / 1024.0):N0} KB";
        var line = $"Swept {Iocs} IOC{S(Iocs)} across {Hosts} host{S(Hosts)} ({FilesScanned:N0} file{S(FilesScanned)}, {size}) "
                   + $"in {DurationSeconds:N0}s: "
                   + (Hits == 0 ? "no hits." : $"{Hits:N0} hit{S(Hits)} on {HostsWithHits} host{S(HostsWithHits)}.");
        if (Problems.Count > 0)
            line += $" {Problems.Count} file{S(Problems.Count)} could not be read, so the sweep is incomplete - see _Logs\\{LogName}.";
        return line;
    }

    private static string S(long n) => n == 1 ? "" : "s";

    internal const string LogName = "IocSweep.log";
}

/// <summary>
/// Searches the parsed output of a case's hosts for the IOCs on its list, and keeps the results
/// in IocHits.csv in the case folder. The hits file is derived: it is rebuilt in parts, never
/// edited by hand, and is the data the case report reads.
///
/// Work is kept to what changed. A new IOC is searched for alone, across every host. A host that
/// is processed again has its own hits rebuilt against the whole list, and every other host's
/// hits are left as they are. Output is read a line at a time, as some of it runs to gigabytes.
/// </summary>
public static class IocSweep
{
    public const string HitsFileName = "IocHits.csv";

    private static readonly string[] HitColumns =
        ["IocType", "Ioc", "Host", "Module", "Time", "OutputFile", "LineNumber", "MatchingLine"];

    // Excel's limit for one cell. A longer line (an event payload) is cut, and says so.
    private const int MaxLineChars = 32000;

    // One sweep writes the hits file at a time; a second waits rather than losing the first's rows.
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static string HitsPathFor(string caseDirectory) => Path.Combine(caseDirectory, HitsFileName);

    /// <summary>The host folders in a case: every folder not starting with "_" (_Logs, _Extracted).</summary>
    public static IReadOnlyList<string> Hosts(string caseDirectory)
    {
        if (!Directory.Exists(caseDirectory)) return [];
        return Directory.EnumerateDirectories(caseDirectory)
            .Select(Path.GetFileName)
            .Where(n => n is not null && !n.StartsWith('_'))
            .Select(n => n!)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Searches every host for these IOCs only, replacing any hits they had. Used when IOCs are
    /// added: nothing already searched for is searched for again.
    /// </summary>
    public static async Task<IocSweepResult> SweepAsync(
        string caseDirectory, IReadOnlyCollection<IocEntry> iocs,
        IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        var keys = iocs.Select(i => i.Key).ToHashSet(StringComparer.Ordinal);
        return await ThenReport(caseDirectory, RunAsync(caseDirectory, iocs, Hosts(caseDirectory),
            hit => keys.Contains(IocList.KeyFor(hit.IocType, hit.Ioc)), progress, cancellationToken));
    }

    /// <summary>
    /// Rebuilds the hits of these hosts against the whole list. Every other host's hits stay.
    /// Used when hosts have been processed again.
    /// </summary>
    public static async Task<IocSweepResult> RebuildHostsAsync(
        string caseDirectory, IEnumerable<string> hosts,
        IProgress<string>? progress = null, CancellationToken cancellationToken = default) =>
        await ThenReport(caseDirectory, SweepHostsAsync(caseDirectory, hosts, progress, cancellationToken));

    private static async Task<IocSweepResult> SweepHostsAsync(
        string caseDirectory, IEnumerable<string> hosts, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var set = hosts.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var present = Hosts(caseDirectory).Where(set.Contains).ToList();
        return await RunAsync(caseDirectory, IocList.Load(caseDirectory), present,
            hit => set.Contains(hit.Host), progress, cancellationToken);
    }

    /// <summary>Rebuilds the whole hits file: every IOC on the list against every host.</summary>
    public static async Task<IocSweepResult> RebuildAllAsync(
        string caseDirectory, IProgress<string>? progress = null, CancellationToken cancellationToken = default) =>
        await ThenReport(caseDirectory, RunAsync(caseDirectory, IocList.Load(caseDirectory), Hosts(caseDirectory),
            _ => true, progress, cancellationToken));

    /// <summary>Drops the hits of IOCs taken off the list.</summary>
    public static async Task RemoveHitsAsync(string caseDirectory, IEnumerable<IocEntry> removed)
    {
        var keys = removed.Select(i => i.Key).ToHashSet(StringComparer.Ordinal);
        if (keys.Count == 0 || !File.Exists(HitsPathFor(caseDirectory))) return;
        await Gate.WaitAsync();
        try { Rewrite(caseDirectory, hit => keys.Contains(IocList.KeyFor(hit.IocType, hit.Ioc)), []); }
        finally { Gate.Release(); }
        CaseReport.Rebuild(caseDirectory);
    }

    /// <summary>
    /// Rebuilds the case report once the sweep has written its hits. The run's own sweep does not:
    /// the run rebuilds the report itself at the end, from everything it produced.
    /// </summary>
    private static async Task<IocSweepResult> ThenReport(string caseDirectory, Task<IocSweepResult> sweep)
    {
        var result = await sweep;
        CaseReport.Rebuild(caseDirectory);
        return result;
    }

    /// <summary>
    /// The post-run step: rebuilds the hits of the hosts this run processed. Does nothing for a
    /// case without an IOC list. Never throws: a sweep that fails is logged, and the run's own
    /// result stands.
    /// </summary>
    public static async Task AfterRunAsync(RunReport report)
    {
        var caseDirectory = report.CaseDirectory;
        try
        {
            if (!IocList.Exists(caseDirectory)) return;
            var hosts = report.Results
                .Where(r => r.Status != WorkStatus.Skipped && r.Module != "Extract")
                .Select(r => r.Collection)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (hosts.Count == 0) return;

            if (report.Cancelled)
            {
                Log(caseDirectory, "The run was stopped, so the IOC hits of " + string.Join(", ", hosts)
                                   + " were not rebuilt and may be out of date. Sweep those hosts again from Analysis > IOCs "
                                   + "or with 'ioc sweep'.", []);
                return;
            }

            await SweepHostsAsync(caseDirectory, hosts, null, CancellationToken.None);
        }
        catch (Exception ex)
        {
            try { Log(caseDirectory, "The IOC sweep after the run failed: " + ex.Message, []); }
            catch { /* the run is over and reported; a lost log line cannot be reported anywhere */ }
        }
    }

    /// <summary>Hits and hosts per IOC (by <see cref="IocEntry.Key"/>), read from IocHits.csv.</summary>
    public static Dictionary<string, IocHitCount> Summarise(string caseDirectory)
    {
        var counts = new Dictionary<string, (int Hits, HashSet<string> Hosts)>(StringComparer.Ordinal);
        foreach (var hit in ReadHits(HitsPathFor(caseDirectory)))
        {
            var key = IocList.KeyFor(hit.IocType, hit.Ioc);
            if (!counts.TryGetValue(key, out var entry))
                counts[key] = entry = (0, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            entry.Hosts.Add(hit.Host);
            counts[key] = (entry.Hits + 1, entry.Hosts);
        }
        return counts.ToDictionary(c => c.Key, c => new IocHitCount(c.Value.Hits, c.Value.Hosts.Count), StringComparer.Ordinal);
    }

    /// <summary>The last sweep's one-line result from the case's sweep log, if there has been one.</summary>
    public static string? LastResult(string caseDirectory)
    {
        var path = Path.Combine(caseDirectory, "_Logs", IocSweepResult.LogName);
        try
        {
            if (!File.Exists(path)) return null;
            return File.ReadLines(path).LastOrDefault(l => l.Length > 0 && !l.StartsWith(' '));
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>Every row of a hits file, streamed.</summary>
    public static IEnumerable<IocHit> ReadHits(string path)
    {
        if (!File.Exists(path)) yield break;
        using var reader = CsvText.OpenRead(path);
        using var records = CsvText.Records(reader).GetEnumerator();
        if (!records.MoveNext()) yield break;

        var header = CsvText.Split(records.Current.Text).Select(h => h.Trim()).ToArray();
        int Find(string name) => Array.FindIndex(header, h => h.Equals(name, StringComparison.OrdinalIgnoreCase));
        var index = HitColumns.Select(Find).ToArray();

        while (records.MoveNext())
        {
            if (records.Current.Text.Length == 0) continue;
            var f = CsvText.Split(records.Current.Text);
            string At(int column) => index[column] >= 0 && index[column] < f.Length ? f[index[column]] : "";
            yield return new IocHit(At(0), At(1), At(2), At(3), At(4), At(5),
                                    long.TryParse(At(6), out var line) ? line : 0, At(7));
        }
    }

    private static async Task<IocSweepResult> RunAsync(
        string caseDirectory, IReadOnlyCollection<IocEntry> iocs, IReadOnlyList<string> hosts,
        Func<IocHit, bool> replaced, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        await Gate.WaitAsync(cancellationToken);
        try
        {
            var watch = Stopwatch.StartNew();
            var matcher = new IocMatcher(iocs);
            var problems = new ConcurrentBag<string>();
            var hits = new ConcurrentBag<IocHit>();
            var files = 0;
            long bytes = 0;

            if (!matcher.IsEmpty)
            {
                var modules = ModuleMap(caseDirectory);
                var work = new List<(string Host, string File, long Size)>();
                foreach (var host in hosts)
                {
                    try
                    {
                        work.AddRange(new DirectoryInfo(Path.Combine(caseDirectory, host))
                                          .EnumerateFiles("*.csv", SearchOption.AllDirectories)
                                          .Select(f => (host, f.FullName, f.Length)));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        problems.Add($"{host}: could not list its output: {ex.Message}");
                    }
                }

                // Largest first: a multi-GB MFT or event log CSV met last would be swept alone at
                // the end while the other workers sat idle.
                work.Sort((a, b) => b.Size.CompareTo(a.Size));

                var done = 0;
                // A few files at once: the disk, not the CPU, sets the pace of a plain scan.
                var options = new ParallelOptions
                {
                    CancellationToken = cancellationToken,
                    MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount / 2, 1, 4)
                };
                await Task.Run(() => Parallel.ForEach(work, options, item =>
                {
                    try
                    {
                        foreach (var hit in ScanFile(caseDirectory, item.Host, item.File, matcher, modules, cancellationToken))
                            hits.Add(hit);
                        Interlocked.Increment(ref files);
                        Interlocked.Add(ref bytes, item.Size);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        problems.Add($"{Path.GetRelativePath(caseDirectory, item.File)}: {ex.Message}");
                    }
                    var count = Interlocked.Increment(ref done);
                    progress?.Report($"Sweeping {item.Host}: {count:N0} of {work.Count:N0} files");
                }), cancellationToken);
            }

            // Stopped part-way, nothing is written: a partial search must not pass for a complete one.
            cancellationToken.ThrowIfCancellationRequested();

            var ordered = hits.OrderBy(h => h.Ioc, StringComparer.OrdinalIgnoreCase)
                              .ThenBy(h => h.Host, StringComparer.OrdinalIgnoreCase)
                              .ThenBy(h => h.OutputFile, StringComparer.OrdinalIgnoreCase)
                              .ThenBy(h => h.LineNumber)
                              .ToList();
            Rewrite(caseDirectory, replaced, ordered);

            var result = new IocSweepResult
            {
                Iocs = matcher.Iocs.Count,
                Hosts = hosts.Count,
                FilesScanned = files,
                BytesScanned = bytes,
                Hits = ordered.Count,
                HostsWithHits = ordered.Select(h => h.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                DurationSeconds = watch.Elapsed.TotalSeconds,
                Problems = problems.Order(StringComparer.OrdinalIgnoreCase).ToList()
            };
            Log(caseDirectory, result.Describe(), result.Problems);
            return result;
        }
        finally
        {
            Gate.Release();
        }
    }

    private static IEnumerable<IocHit> ScanFile(
        string caseDirectory, string host, string file, IocMatcher matcher,
        IReadOnlyDictionary<string, string> modules, CancellationToken cancellationToken)
    {
        var relative = Path.GetRelativePath(caseDirectory, file);
        var module = modules.TryGetValue(relative, out var name) ? name : CategoryOf(relative);
        var found = new List<IocHit>();

        using var reader = CsvText.OpenRead(file);
        CsvHeader? header = null;
        var checkedAt = 0;
        foreach (var record in CsvText.Records(reader))
        {
            if (header is null) { header = CsvHeader.Parse(record.Text); continue; }
            if (++checkedAt % 65536 == 0) cancellationToken.ThrowIfCancellationRequested();

            var matches = matcher.Match(record.Text, header, out var fields);
            if (matches.Count == 0) continue;
            fields ??= CsvText.Split(record.Text);
            var time = header.TimeOf(fields);
            var line = record.Text.Length <= MaxLineChars
                ? record.Text
                : record.Text[..MaxLineChars] + $" [cut: {record.Text.Length:N0} characters in the output file]";
            foreach (var ioc in matches)
                found.Add(new IocHit(ioc.TypeLabel, ioc.Value, host, module, time, relative, record.LineNumber, line));
        }
        return found;
    }

    /// <summary>
    /// The module that wrote each output file, from the case's last manifest. A file it does not
    /// list (written by an earlier run of another batch) is named by its category folder instead.
    /// </summary>
    private static Dictionary<string, string> ModuleMap(string caseDirectory)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var manifest = Path.Combine(caseDirectory, "_Logs", "manifest.json");
        try
        {
            if (!File.Exists(manifest)) return map;
            using var document = JsonDocument.Parse(File.ReadAllText(manifest));
            if (!document.RootElement.TryGetProperty("Results", out var results)) return map;
            foreach (var result in results.EnumerateArray())
            {
                var module = result.GetProperty("Module").GetString() ?? "";
                var collection = result.GetProperty("Collection").GetString() ?? "";
                var destination = result.GetProperty("Destination").GetString() ?? "";
                if (destination.Length == 0 || !result.TryGetProperty("Processors", out var processors)) continue;

                // Keyed from the collection folder down, not by full path, so a case that has been
                // moved or copied since (to a share, say) still finds its modules.
                var parts = destination.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                var from = Array.FindLastIndex(parts, p => p.Equals(collection, StringComparison.OrdinalIgnoreCase));
                if (from < 0) continue;
                var folder = Path.Combine(parts[from..]);
                foreach (var processor in processors.EnumerateArray())
                {
                    if (!processor.TryGetProperty("OutputFiles", out var outputs)) continue;
                    foreach (var output in outputs.EnumerateArray())
                    {
                        var text = output.GetString() ?? "";
                        if (text.Contains("=> FAILED", StringComparison.Ordinal)) continue;
                        var arrow = text.IndexOf(" => ", StringComparison.Ordinal);
                        var delivered = arrow < 0 ? text : text[(arrow + 4)..];
                        map[Path.Combine(folder, delivered)] = module;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
                                       or InvalidOperationException or KeyNotFoundException)
        {
            // Without the manifest every file is named by its category folder; the hits stand.
        }
        return map;
    }

    /// <summary>host\Category\...\file.csv gives Category.</summary>
    private static string CategoryOf(string relative)
    {
        var parts = relative.Split(Path.DirectorySeparatorChar);
        return parts.Length >= 3 ? parts[1] : "";
    }

    /// <summary>
    /// Writes the hits file again: the rows kept from the old one, then the new ones, through a
    /// temporary file so a crash leaves the previous hits whole.
    /// </summary>
    private static void Rewrite(string caseDirectory, Func<IocHit, bool> replaced, IReadOnlyList<IocHit> added)
    {
        var path = HitsPathFor(caseDirectory);
        Directory.CreateDirectory(caseDirectory);
        AtomicFile.Write(path, writer =>
        {
            writer.WriteLine(string.Join(",", HitColumns));
            foreach (var hit in ReadHits(path).Where(h => !replaced(h))) WriteHit(writer, hit);
            foreach (var hit in added) WriteHit(writer, hit);
        });
    }

    private static void WriteHit(StreamWriter writer, IocHit hit) =>
        writer.WriteLine(string.Join(",", new[]
        {
            hit.IocType, hit.Ioc, hit.Host, hit.Module, hit.Time, hit.OutputFile,
            hit.LineNumber.ToString(), hit.MatchingLine
        }.Select(CsvText.Escape)));

    private static void Log(string caseDirectory, string line, IReadOnlyList<string> problems)
    {
        var logs = Path.Combine(caseDirectory, "_Logs");
        Directory.CreateDirectory(logs);
        var text = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}  {line}{Environment.NewLine}"
                   + string.Concat(problems.Select(p => "    could not read " + p + Environment.NewLine));
        File.AppendAllText(Path.Combine(logs, IocSweepResult.LogName), text);
    }
}
