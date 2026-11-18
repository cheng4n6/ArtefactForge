using System.Text.Json;
using ArtefactForge.Lake;
using ArtefactForge.Lake.Contract;

namespace ArtefactForge.Core;

/// <summary>What <see cref="HostOutputs.BackFill"/> did.</summary>
public sealed record BackFillResult(IReadOnlyList<string> Hosts, bool FromManifest, IReadOnlyList<string> Problems);

public static partial class HostOutputs
{
    /// <summary>
    /// Writes outputs.json for every host folder of the case that has none, as a case processed
    /// before outputs.json existed: one entry per CSV and JSON file in the folder (outside
    /// _Incomplete). A file the case's _Logs\manifest.json lists takes its tool, version, command
    /// line and status from there; the rest are named after their file, with no version. Only the
    /// case output is written to. A host that already has an outputs.json is left alone.
    /// </summary>
    public static BackFillResult BackFill(string caseDirectory, DateTime nowUtc)
    {
        var problems = new List<string>();
        var hosts = Directory.EnumerateDirectories(caseDirectory)
            .Where(d => !Path.GetFileName(d).StartsWith('_'))
            .Where(d => !File.Exists(OutputsManifestFile.PathIn(d)))
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (hosts.Count == 0) return new BackFillResult([], false, problems);

        var manifestPath = Path.Combine(caseDirectory, "_Logs", "manifest.json");
        IReadOnlyList<WorkResult> listed = [];
        var fromManifest = false;
        if (File.Exists(manifestPath))
        {
            try
            {
                listed = ReadManifestResults(File.ReadAllText(manifestPath));
                fromManifest = true;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or InvalidDataException)
            {
                problems.Add($"_Logs\\manifest.json could not be read ({ex.Message}); outputs.json was written from the files alone");
            }
        }

        var written = new List<string>();
        var noModules = new Dictionary<string, ModuleDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var hostDir in hosts)
        {
            var host = Path.GetFileName(hostDir);
            var results = listed.Where(r => string.Equals(r.Collection, host, StringComparison.OrdinalIgnoreCase))
                                .Select(r => Rebased(r, host, hostDir))
                                .ToList();
            var entries = new Dictionary<string, OutputEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var result in results)
                foreach (var entry in Entries(hostDir, [result], noModules))
                    entries.TryAdd(entry.Path, entry with { User = entry.User ?? UserOf(entry.Path, result.Iteration) });

            foreach (var file in FilesOnDisk(hostDir))
            {
                var relative = OutputsManifestFile.RelativePath(hostDir, file);
                if (entries.ContainsKey(relative)) continue;
                entries[relative] = FromFileAlone(hostDir, file, relative);
            }

            var manifest = new OutputsManifest
            {
                Producer = new OutputsProducer { Name = OwnParser, Version = BuildInfo.Version, Build = BuildInfo.InformationalVersion },
                UpdatedUtc = nowUtc,
                Host = DescribeHost(host, hostDir, null),
                Outputs = entries.Values.OrderBy(e => e.Path, StringComparer.OrdinalIgnoreCase).ToList()
            };
            try
            {
                OutputsManifestFile.Write(OutputsManifestFile.PathIn(hostDir), OutputsManifestFile.Merge(null, manifest, hostDir));
                written.Add(host);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problems.Add($"{host}: could not write {OutputsManifestFile.FileName} ({ex.Message}); the lake searched its folder instead");
            }
        }
        return new BackFillResult(written, fromManifest, problems);
    }

    /// <summary>
    /// The result with its folders moved to where the host folder is now. The manifest records
    /// absolute paths, so a case copied or moved since its run (to a share, another drive) would
    /// otherwise match none of its files: the part of the path after the host's folder is kept.
    /// </summary>
    private static WorkResult Rebased(WorkResult result, string host, string hostDir)
    {
        var copy = new WorkResult
        {
            Collection = result.Collection, Module = result.Module, Category = result.Category, Iteration = result.Iteration,
            Status = result.Status, Reason = result.Reason, Destination = Rebase(result.Destination, host, hostDir) ?? "",
            Started = result.Started, DurationSeconds = result.DurationSeconds
        };
        foreach (var p in result.Processors)
            copy.Processors.Add(new ProcessorRecord
            {
                Executable = p.Executable, Arguments = p.Arguments, ToolVersion = p.ToolVersion, ToolSha256 = p.ToolSha256,
                OutputFiles = p.OutputFiles, DeliveredTo = Rebase(p.DeliveredTo, host, hostDir)
            });
        return copy;
    }

    private static string? Rebase(string? path, string host, string hostDir)
    {
        // Rebased whenever it is outside the host folder, even if it exists: the case may have
        // been copied, and the original is then still there.
        if (string.IsNullOrEmpty(path)) return path;
        var relative = Path.GetRelativePath(hostDir, path);
        if (relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !Path.IsPathRooted(relative)) return path;
        var parts = path.Split('\\', '/');
        var at = Array.FindLastIndex(parts, p => string.Equals(p, host, StringComparison.OrdinalIgnoreCase));
        return at < 0 ? path : Path.Combine([hostDir, .. parts[(at + 1)..]]);
    }

    private static IEnumerable<string> FilesOnDisk(string hostDir) =>
        Directory.EnumerateFiles(hostDir, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
            .Where(f => Path.GetExtension(f).ToLowerInvariant() is ".csv" or ".json")
            .Where(f => !string.Equals(Path.GetFileName(f), OutputsManifestFile.FileName, StringComparison.OrdinalIgnoreCase))
            .Where(f => OutputsManifestFile.IsListable(OutputsManifestFile.RelativePath(hostDir, f)));

    /// <summary>
    /// An entry for a file no manifest lists. It is in the host folder rather than _Incomplete,
    /// where ArtefactForge puts the output of anything that did not finish, so it is listed as
    /// completed; its tool is the first word of its name and its version is not known.
    /// </summary>
    private static OutputEntry FromFileAlone(string hostDir, string file, string relative)
    {
        var info = new FileInfo(file);
        var user = UserOf(relative, null);
        var toolName = SourceDiscovery.StripName(info.Name, user);
        var derived = Derived.FirstOrDefault(d => relative.StartsWith(d.Folder + "/", StringComparison.OrdinalIgnoreCase));
        return new OutputEntry
        {
            Path = relative,
            Format = FormatOf(file),
            Parser = derived.Module is not null ? OwnParser : SourceDiscovery.ParserFromName(toolName),
            ToolFileName = toolName,
            Module = derived.Module,
            User = user,
            Status = OutputStatus.Completed,
            ProducedUtc = info.LastWriteTimeUtc,
            Bytes = info.Length
        };
    }

    /// <summary>
    /// The user a file belongs to: ArtefactForge puts a user's files in &lt;Category&gt;\&lt;User&gt;\
    /// named &lt;User&gt;_..., so the folder two down is the user when the file is named after it.
    /// With the manifest's iteration (the user the module ran for) it is that user whenever the
    /// file is named after them: earlier versions put a user's file straight in the category
    /// folder (Timeline\User_WxTCmd_Activity.csv).
    /// </summary>
    private static string? UserOf(string relative, string? iteration)
    {
        var parts = relative.Split('/');
        var name = parts[^1];
        if (iteration is not null)
            return name.StartsWith(iteration + "_", StringComparison.OrdinalIgnoreCase) ? iteration : null;
        if (parts.Length < 3) return null;
        var folder = parts[^2];
        return name.StartsWith(folder + "_", StringComparison.OrdinalIgnoreCase) ? folder : null;
    }

    /// <summary>
    /// The Results of a _Logs\manifest.json, as far as outputs.json needs them. The manifest is
    /// ArtefactForge's own record of its last run; Status is the WorkStatus number it was written
    /// with (or its name).
    /// </summary>
    public static List<WorkResult> ReadManifestResults(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("Results", out var results) || results.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("it has no Results list");

        var list = new List<WorkResult>();
        foreach (var r in results.EnumerateArray())
        {
            string? Text(JsonElement e, string name) =>
                e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

            var status = r.TryGetProperty("Status", out var s) ? s : default;
            WorkStatus parsed;
            if (status.ValueKind == JsonValueKind.Number && status.TryGetInt32(out var n) && Enum.IsDefined(typeof(WorkStatus), n))
                parsed = (WorkStatus)n;
            else if (status.ValueKind == JsonValueKind.String && Enum.TryParse(status.GetString(), true, out WorkStatus named))
                parsed = named;
            else
                parsed = WorkStatus.Failed;   // unknown: never read as complete

            var result = new WorkResult
            {
                Collection = Text(r, "Collection") ?? "",
                Module = Text(r, "Module") ?? "",
                Category = Text(r, "Category") ?? "",
                Iteration = Text(r, "Iteration"),
                Status = parsed,
                Destination = Text(r, "Destination") ?? "",
                Started = r.TryGetProperty("Started", out var st) && st.TryGetDateTimeOffset(out var when) ? when : default,
                DurationSeconds = r.TryGetProperty("DurationSeconds", out var d) && d.TryGetDouble(out var secs) ? secs : 0
            };
            if (r.TryGetProperty("Processors", out var processors) && processors.ValueKind == JsonValueKind.Array)
            {
                foreach (var p in processors.EnumerateArray())
                {
                    var files = p.TryGetProperty("OutputFiles", out var f) && f.ValueKind == JsonValueKind.Array
                        ? f.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
                        : [];
                    result.Processors.Add(new ProcessorRecord
                    {
                        Executable = Text(p, "Executable") ?? "",
                        Arguments = Text(p, "Arguments") ?? "",
                        ToolVersion = Text(p, "ToolVersion"),
                        ToolSha256 = Text(p, "ToolSha256"),
                        OutputFiles = files,
                        DeliveredTo = Text(p, "DeliveredTo")
                    });
                }
            }
            list.Add(result);
        }
        return list;
    }
}
