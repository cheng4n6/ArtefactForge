using System.Globalization;
using System.Text.Json;
using ArtefactForge.Lake;

namespace ArtefactForge.Core;

/// <summary>
/// The evidence lake as a step of ArtefactForge: one DuckDB file built from every host's output,
/// in &lt;Case&gt;\_Lake\ (a "_" folder, so nothing treats it as a host). The lake itself is
/// ArtefactForge.Lake, which reads each host's outputs.json and never ArtefactForge's internals;
/// this maps a run's settings to its options and its result to a <see cref="WorkResult"/>. It is
/// built only when the analyst asks: a run option, the Analysis tab's button, or lake build.
/// </summary>
public static class EvidenceLakeStep
{
    public const string FolderName = LakeNames.LakeFolder;
    public const string ModuleName = "EvidenceLake";
    public const string Category = "Lake";
    /// <summary>The Collection of the step's result: it is about the case, not one host.</summary>
    public const string CaseCollection = "(case)";

    /// <summary>The lake's memory limit is never set below this, however little is free: DuckDB spills beyond it.</summary>
    public const long MinimumMemoryBytes = 1L << 30;

    public static string FolderFor(string caseDirectory) => Path.Combine(caseDirectory, FolderName);

    /// <summary>
    /// The lake's options for a run's settings: memory is what is free now less the run's Keep
    /// free (at least 1 GB, as DuckDB spills to the case volume past it), threads are the run's
    /// workers. Null free memory leaves the lake its own default.
    /// </summary>
    public static LakeOptions OptionsFor(int maxWorkers, long keepFreeBytes, long? freeBytes, IReadOnlyList<string>? notes = null) => new()
    {
        MemoryLimitBytes = MemoryBudget.FromFree(freeBytes, keepFreeBytes) is { } budget
            ? Math.Max(MinimumMemoryBytes, budget)
            : null,
        Threads = Math.Max(1, maxWorkers),
        Producer = "ArtefactForge " + BuildInfo.InformationalVersion,
        Notes = notes ?? []
    };

    /// <summary>A result saying the lake the analyst asked for was not built, and why.</summary>
    public static WorkResult NotBuilt(string caseDirectory, string reason) => new()
    {
        Collection = CaseCollection,
        Module = ModuleName,
        Category = Category,
        Status = WorkStatus.Skipped,
        Reason = reason,
        Destination = FolderFor(caseDirectory),
        Started = DateTimeOffset.Now
    };

    /// <summary>
    /// Builds the case's lake. Hosts with no outputs.json (cases from before it existed) get one
    /// written first from their files and the case's last run manifest, and lake.log says which.
    /// Never throws for a lake that could not be built: the result says why.
    /// </summary>
    public static WorkResult Build(string caseDirectory, int maxWorkers, long keepFreeBytes,
        IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.Now;
        WorkResult Result(WorkStatus status, string reason) => new()
        {
            Collection = CaseCollection,
            Module = ModuleName,
            Category = Category,
            Status = status,
            Reason = reason,
            Destination = FolderFor(caseDirectory),
            Started = started,
            DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds
        };

        if (!Directory.Exists(caseDirectory)) return Result(WorkStatus.Failed, $"Case folder not found: {caseDirectory}");

        var notes = new List<string>();
        var backFill = HostOutputs.BackFill(caseDirectory, DateTime.UtcNow);
        if (backFill.Hosts.Count > 0)
            notes.Add("outputs.json written from the files on disk for host(s) that had none: " + string.Join(", ", backFill.Hosts) +
                      (backFill.FromManifest ? " (versions from _Logs\\manifest.json where it lists the file)" : " (no _Logs\\manifest.json, so versions are unknown)"));
        notes.AddRange(backFill.Problems);

        try
        {
            var result = Build(caseDirectory, OptionsFor(maxWorkers, keepFreeBytes, MemoryBudget.Available(), notes), progress, cancellationToken);
            return Result(result.Status, result.Reason);
        }
        catch (OperationCanceledException)
        {
            return Result(WorkStatus.Cancelled, "Stopped before the evidence lake was finished; the previous lake, if any, is unchanged");
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException or TypeInitializationException
                                       or EntryPointNotFoundException)
        {
            // duckdb.dll is loaded on the first build, not at start-up, so a missing or wrong copy
            // shows here and nowhere else.
            return Result(WorkStatus.Failed, "DuckDB's native library (duckdb.dll, beside the exe) could not be loaded: " +
                                             (ex.InnerException ?? ex).Message);
        }
    }

    private static (WorkStatus Status, string Reason) Build(string caseDirectory, LakeOptions options,
        IProgress<string>? progress, CancellationToken cancellationToken) =>
        Describe(LakeBuilder.Build(caseDirectory, options, progress, cancellationToken));

    /// <summary>The step's status and reason for a lake build's result.</summary>
    public static (WorkStatus Status, string Reason) Describe(LakeResult result)
    {
        var trimmed = result.Message.TrimEnd('.');
        return result.Outcome switch
        {
            LakeOutcome.Built => (WorkStatus.Completed, trimmed),
            LakeOutcome.BuiltCheckLog => (WorkStatus.CheckLog, CheckLogReason(result)),
            _ => (WorkStatus.Failed, trimmed)
        };
    }

    private static string CheckLogReason(LakeResult result)
    {
        var parts = new List<string>();
        if (result.Mismatched > 0) parts.Add($"{result.Mismatched} with a header that does not fit (loaded raw, not mapped)");
        if (result.FailedSources > 0) parts.Add($"{result.FailedSources} not loaded");
        var rejected = result.Sources.Where(s => s.RowsRejected > 0).ToList();
        if (rejected.Count > 0)
            parts.Add($"{rejected.Count} with rows that could not be read ({rejected.Sum(s => s.RowsRejected).ToString("N0", CultureInfo.InvariantCulture)} rows)");
        var untimed = result.Sources.Where(s => s.TimeUnread > 0).ToList();
        if (untimed.Count > 0)
            parts.Add($"{untimed.Count} with rows kept out of the timeline for want of a UTC time ({untimed.Sum(s => s.TimeUnread).ToString("N0", CultureInfo.InvariantCulture)} rows)");
        parts.AddRange(result.Warnings);
        return $"Built, {result.Loaded} of {result.Sources.Count} source(s) loaded, " +
               $"{result.TimelineRows.ToString("N0", CultureInfo.InvariantCulture)} timeline rows; check: " +
               string.Join("; ", parts) + $". See {FolderName}\\{LakeNames.LogFile}";
    }

    /// <summary>What the last build recorded in build.json, or null when the case has no lake yet.</summary>
    public static LakeStatus? Status(string caseDirectory)
    {
        var path = Path.Combine(FolderFor(caseDirectory), LakeNames.BuildFile);
        if (!File.Exists(path)) return null;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            string? Text(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            long Number(string name) => root.TryGetProperty(name, out var v) && v.TryGetInt64(out var n) ? n : 0;
            var hosts = root.TryGetProperty("hosts", out var h) && h.ValueKind == JsonValueKind.Array ? h.GetArrayLength() : 0;
            var started = DateTime.TryParse(Text("startedUtc"), CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : (DateTime?)null;
            var database = Text("database");
            return new LakeStatus
            {
                Result = Text("result") ?? "unknown",
                Message = Text("message") ?? "",
                BuiltUtc = started,
                Hosts = hosts,
                TimelineRows = Number("timelineRows"),
                SourcesLoaded = (int)Number("sourcesLoaded"),
                NeedingReview = (int)(Number("sourcesHeaderMismatch") + Number("sourcesFailed")),
                Warnings = root.TryGetProperty("warnings", out var w) && w.ValueKind == JsonValueKind.Array ? w.GetArrayLength() : 0,
                DatabasePath = database is null ? null : Path.Combine(FolderFor(caseDirectory), database),
                DuckDbVersion = Text("duckDbVersion")
            };
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return new LakeStatus { Result = "unreadable", Message = $"{LakeNames.BuildFile} could not be read: {ex.Message}" };
        }
    }
}

/// <summary>The last lake build of a case, as build.json records it.</summary>
public sealed record LakeStatus
{
    /// <summary>built, checklog, notswapped, failed, or unreadable when build.json could not be read.</summary>
    public required string Result { get; init; }
    public required string Message { get; init; }
    public DateTime? BuiltUtc { get; init; }
    public int Hosts { get; init; }
    public long TimelineRows { get; init; }
    public int SourcesLoaded { get; init; }
    /// <summary>Sources with a header that did not fit or that failed to load.</summary>
    public int NeedingReview { get; init; }
    public int Warnings { get; init; }
    public string? DatabasePath { get; init; }
    /// <summary>The DuckDB version that wrote the lake: a program opening it must be this version or later.</summary>
    public string? DuckDbVersion { get; init; }

    /// <summary>True when there is a lake to open, whatever else needs a look.</summary>
    public bool HasLake => Result is "built" or "checklog" or "notswapped";

    /// <summary>True when the analyst should look: the build failed, was not swapped in, or something in it needs a look.</summary>
    public bool NeedsAttention => Result is not "built";

    /// <summary>One line for the Analysis tab and the case report.</summary>
    public string Describe()
    {
        var when = BuiltUtc is { } t ? t.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "at an unknown time";
        var contents = $"{Hosts} host{(Hosts == 1 ? "" : "s")}, {TimelineRows.ToString("N0", CultureInfo.InvariantCulture)} timeline rows";
        return Result switch
        {
            "built" => $"Built {when}: {contents}.",
            "checklog" => $"Built {when}: {contents}; " +
                          (NeedingReview > 0 ? $"{NeedingReview} source{(NeedingReview == 1 ? "" : "s")} need a look" : "something needs a look") +
                          $" (see {LakeNames.LogFile}).",
            "notswapped" => $"Built {when}, but the previous lake was open in another program, so the new one is case.duckdb.new. Close it and build again.",
            "failed" => $"The last build ({when}) failed: {Message}",
            _ => Message
        };
    }
}
