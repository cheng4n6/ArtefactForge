using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ArtefactForge.Lake.Contract;

namespace ArtefactForge.Core;

/// <summary>What a run knows about a host that is not in its folder: its layout's platform and its collector.</summary>
public sealed record HostContext(Platform Platform, CollectorTimes? Times);

/// <summary>
/// Writes &lt;Case&gt;\&lt;Host&gt;\outputs.json for each host a run touched: which tool produced each
/// file in the host folder, from what command line, and how it finished. It is the evidence lake's
/// way into a case, so the lake never reads ArtefactForge's own run manifest, and it is kept
/// across runs, unlike _Logs\manifest.json, which lists the last run only.
/// </summary>
public static partial class HostOutputs
{
    /// <summary>The Module name of a result reporting a problem with outputs.json.</summary>
    public const string ModuleName = "outputs.json";
    public const string Category = "Manifest";
    /// <summary>The parser named for ArtefactForge's own analyses.</summary>
    public const string OwnParser = "ArtefactForge";

    /// <summary>ArtefactForge's own per-host analyses, by module name, and the folder each writes.</summary>
    private static readonly (string Module, string Folder)[] Derived =
    [
        (Windows.IpHistory.ModuleName, Windows.IpHistory.Folder),
        (Windows.RemoteAccess.ModuleName, Windows.RemoteAccess.Folder),
        (Windows.Ransomware.ModuleName, Windows.Ransomware.Folder),
        (DataAccess.DataAccessReport.ModuleName, DataAccess.DataAccessReport.Folder)
    ];

    /// <summary>
    /// Writes outputs.json in every host folder the results name, merged with the one already
    /// there. Returns a result for each host whose file could not be read or written; a problem
    /// here is reported but never stops the run, because the run's own output is unaffected.
    /// </summary>
    public static List<WorkResult> Write(
        string caseDirectory, IReadOnlyList<WorkResult> results, IReadOnlyList<ModuleDefinition> modules,
        IReadOnlyDictionary<string, HostContext> hosts, DateTime nowUtc)
    {
        var problems = new List<WorkResult>();
        var byName = modules.GroupBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
                            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var hostResults in results.GroupBy(r => r.Collection, StringComparer.OrdinalIgnoreCase))
        {
            var host = hostResults.Key;
            if (host.Length == 0 || host.StartsWith('_')) continue;   // not a host folder
            var hostDir = Path.Combine(caseDirectory, host);
            if (!Directory.Exists(hostDir)) continue;                  // nothing of it on disk to list

            var path = OutputsManifestFile.PathIn(hostDir);
            string? note = null;
            OutputsManifest? existing;
            try
            {
                existing = OutputsManifestFile.Read(path);
            }
            catch (UnsupportedFormatVersionException ex)
            {
                problems.Add(Problem(host, hostDir, WorkStatus.Failed, ex.Message + " It was left as it is, so it does not list this run's files."));
                continue;
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
            {
                // Rebuilt from this run: a list that cannot be read is no use to the lake either.
                existing = null;
                note = ex.Message + " It was written again from this run, so files from earlier runs are not listed in it.";
            }

            try
            {
                var update = new OutputsManifest
                {
                    Producer = new OutputsProducer
                    {
                        Name = OwnParser, Version = BuildInfo.Version, Build = BuildInfo.InformationalVersion
                    },
                    UpdatedUtc = nowUtc,
                    Host = DescribeHost(host, hostDir, hosts.GetValueOrDefault(host)),
                    Outputs = Entries(hostDir, hostResults.ToList(), byName)
                };
                OutputsManifestFile.Write(path, OutputsManifestFile.Merge(existing, update, hostDir));
                if (note is not null) problems.Add(Problem(host, hostDir, WorkStatus.CheckLog, note));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problems.Add(Problem(host, hostDir, WorkStatus.Failed,
                    $"could not write {OutputsManifestFile.FileName}: {ex.Message}" + (note is null ? "" : " " + note)));
            }
        }
        return problems;
    }

    /// <summary>The host's details from its system summary, its layout and its collector.</summary>
    internal static OutputsHost DescribeHost(string host, string hostDir, HostContext? context)
    {
        var facts = SystemInventory.Facts(hostDir);
        string? Fact(string item) => facts.TryGetValue(item, out var v) && v.Trim().Length > 0 ? v.Trim() : null;

        var platform = context?.Platform switch
        {
            Platform.Windows => Platforms.Windows,
            Platform.Linux => Platforms.Linux,
            _ => Fact("ProductName") is not null ? Platforms.Windows
                 : Fact("PRETTY_NAME") is not null || Fact("DISTRIB_DESCRIPTION") is not null ? Platforms.Linux
                 : null
        };
        var times = context?.Times;
        return new OutputsHost
        {
            Name = host,
            Hostname = Fact("Hostname"),
            Platform = platform,
            TimeZone = SystemInventory.TimeZone(facts)?.Zone
                       ?? (times is { TimeZone.Length: > 0 } ? times.TimeZone : null),
            CollectedUtc = times?.CollectedUtc,
            Collector = times?.Collector
        };
    }

    /// <summary>One entry per file this run delivered into the host folder.</summary>
    internal static List<OutputEntry> Entries(
        string hostDir, IReadOnlyList<WorkResult> results, IReadOnlyDictionary<string, ModuleDefinition> modules)
    {
        var entries = new List<OutputEntry>();
        foreach (var (derived, folder) in Derived)
        {
            var own = results.Where(r => string.Equals(r.Module, derived, StringComparison.OrdinalIgnoreCase)).ToList();
            entries.AddRange(DerivedEntries(hostDir, derived, folder, own));
        }

        foreach (var result in results)
        {
            if (Derived.Any(d => string.Equals(d.Module, result.Module, StringComparison.OrdinalIgnoreCase))) continue;

            modules.TryGetValue(result.Module, out var module);
            foreach (var processor in result.Processors)
            {
                if (processor.OutputFiles.Count == 0) continue;
                var folder = processor.DeliveredTo ?? result.Destination;
                var (parser, version, sha) = Parser(processor);
                foreach (var listed in processor.OutputFiles)
                {
                    var (toolName, delivered) = SplitOutputFile(listed);
                    if (delivered is null) continue;   // the move failed; the file is not in the host folder
                    var file = Path.Combine(folder, delivered);
                    var relative = OutputsManifestFile.RelativePath(hostDir, file);
                    if (!OutputsManifestFile.IsListable(relative) || !File.Exists(file)) continue;
                    entries.Add(new OutputEntry
                    {
                        Path = relative,
                        Format = FormatOf(file),
                        Parser = parser,
                        ParserVersion = version,
                        ParserSha256 = sha,
                        ToolFileName = toolName,
                        Module = result.Module,
                        ModuleVersion = module?.Version,
                        User = module?.Iterate == IterationMode.UserProfile ? result.Iteration : null,
                        Arguments = processor.Arguments,
                        Status = StatusWord(result.Status),
                        ProducedUtc = (result.Started + TimeSpan.FromSeconds(result.DurationSeconds)).UtcDateTime,
                        Bytes = new FileInfo(file).Length
                    });
                }
            }
        }
        return entries;
    }

    /// <summary>
    /// The CSVs an analysis has in its folder of the host. It reports a result for a host only
    /// when there is something to say (DataAccess writes Users.csv and reports only a failure),
    /// so no result means it finished. A result that failed or found nothing may have left an
    /// earlier run's files, which keep the entries that run gave them.
    /// </summary>
    private static IEnumerable<OutputEntry> DerivedEntries(
        string hostDir, string module, string folder, IReadOnlyList<WorkResult> results)
    {
        if (results.Any(r => r.Status is not (WorkStatus.Completed or WorkStatus.CheckLog))) yield break;
        var status = results.Any(r => r.Status == WorkStatus.CheckLog) ? WorkStatus.CheckLog : WorkStatus.Completed;
        var dir = Path.Combine(hostDir, folder);
        if (!Directory.Exists(dir)) yield break;
        foreach (var file in Directory.EnumerateFiles(dir, "*.csv").Order(StringComparer.OrdinalIgnoreCase))
        {
            var info = new FileInfo(file);
            yield return new OutputEntry
            {
                Path = OutputsManifestFile.RelativePath(hostDir, file),
                Format = FormatOf(file),
                Parser = OwnParser,
                ParserVersion = BuildInfo.InformationalVersion,
                ParserSha256 = BuildInfo.Sha256,
                ToolFileName = info.Name,
                Module = module,
                Status = StatusWord(status),
                ProducedUtc = info.LastWriteTimeUtc,
                Bytes = info.Length
            };
        }
    }

    /// <summary>
    /// "tool name => delivered name" as the harvest records it, or one name when the file kept its
    /// name. The delivered name is null when the move failed ("tool name => FAILED: ...").
    /// </summary>
    internal static (string ToolName, string? Delivered) SplitOutputFile(string listed)
    {
        var arrow = listed.IndexOf(" => ", StringComparison.Ordinal);
        if (arrow < 0) return (listed, listed);
        var tool = listed[..arrow];
        var delivered = listed[(arrow + 4)..];
        return (tool, delivered.StartsWith("FAILED:", StringComparison.Ordinal) ? null : delivered);
    }

    /// <summary>
    /// The tool that wrote the files. A PowerShell processor is named after its script, which
    /// ships with ArtefactForge and so carries its build, as a builtin does; powershell.exe's own
    /// version says nothing about the parser.
    /// </summary>
    internal static (string Name, string? Version, string? Sha256) Parser(ProcessorRecord processor)
    {
        var exe = processor.Executable;
        if (Builtins.IsBuiltin(exe))
            return (exe[Builtins.Prefix.Length..], processor.ToolVersion, Blank(processor.ToolSha256));

        var name = Path.GetFileNameWithoutExtension(exe);
        if (name.Equals("powershell", StringComparison.OrdinalIgnoreCase) || name.Equals("pwsh", StringComparison.OrdinalIgnoreCase))
        {
            var script = ScriptArgument().Match(processor.Arguments);
            if (script.Success)
            {
                var path = script.Groups["path"].Value;
                return (Path.GetFileNameWithoutExtension(path), BuildInfo.InformationalVersion, HashOf(path));
            }
        }
        return (name, Blank(processor.ToolVersion), Blank(processor.ToolSha256));
    }

    internal static string StatusWord(WorkStatus status) => status switch
    {
        WorkStatus.Completed => OutputStatus.Completed,
        WorkStatus.CheckLog => OutputStatus.CheckLog,
        WorkStatus.NoOutput => OutputStatus.NoOutput,
        WorkStatus.TimedOut => OutputStatus.TimedOut,
        WorkStatus.Cancelled => OutputStatus.Cancelled,
        // Failed, and anything a result with files should never have: never read as complete.
        _ => OutputStatus.Failed
    };

    private static string? FormatOf(string file) =>
        Path.GetExtension(file) is { Length: > 1 } ext ? ext[1..].ToLowerInvariant() : null;

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string? HashOf(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;   // the script ran; its hash is a detail the entry can do without
        }
    }

    private static WorkResult Problem(string host, string hostDir, WorkStatus status, string reason) => new()
    {
        Collection = host,
        Module = ModuleName,
        Category = Category,
        Status = status,
        Reason = reason,
        Destination = hostDir,
        Started = DateTimeOffset.Now
    };

    /// <summary>-File "...\Parse-LinuxAuth.ps1", quoted or not.</summary>
    [GeneratedRegex(@"-File\s+(?:""(?<path>[^""]+\.ps1)""|(?<path>\S+\.ps1))", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptArgument();
}
