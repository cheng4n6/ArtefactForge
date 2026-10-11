namespace ArtefactForge.Core;

public enum WorkStatus
{
    Pending, Running, Completed, NoOutput, CheckLog,
    Failed, Skipped, ToolMissing, TimedOut, Cancelled
}

public sealed class RunConfiguration
{
    public required string CaseName { get; init; }
    public required string OutputRoot { get; init; }
    /// <summary>Searched in order for a module's Executable. Lets EZ Tools stay where they are.</summary>
    public required IReadOnlyList<string> ToolRoots { get; init; }
    public required IReadOnlyList<ResolvedTarget> Targets { get; init; }
    public required IReadOnlyList<ModuleDefinition> Modules { get; init; }
    public int MaxWorkers { get; init; } = Environment.ProcessorCount;
    /// <summary>Concurrent IoWeight=heavy modules. Disk, not CPU, is the real ceiling.</summary>
    public int MaxHeavyWorkers { get; init; } = 2;
    public bool Vss { get; init; }
    /// <summary>Skip work already recorded complete, so a failed batch resumes where it stopped.</summary>
    public bool SkipCompleted { get; init; } = true;

    /// <summary>
    /// Folder holding ArtefactForge's own parser scripts, exposed as %scriptsDir%. Distinct from
    /// the tool roots: those hold third-party binaries and are excluded from git, these are source.
    /// </summary>
    public string ScriptsDirectory { get; init; } = "";

    /// <summary>
    /// Per-module option overrides, keyed by module name then option name. Only options a module
    /// declares can be overridden; anything else is rejected before the run starts.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> OptionOverrides { get; init; }
        = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Layouts used to find the collection inside a zip once it is extracted. Needed only when a
    /// target is an archive.
    /// </summary>
    public IReadOnlyList<LayoutProfile> Layouts { get; init; } = [];

    /// <summary>Where zips are extracted. Null means &lt;case&gt;\_Extracted.</summary>
    public string? ExtractionRoot { get; init; }

    /// <summary>
    /// Delete each zip's extracted data once its modules have finished, so a batch of zips needs
    /// space for the few being worked on. Off by default: the data stays for review.
    /// </summary>
    public bool CleanupExtracted { get; init; }

    /// <summary>
    /// Zips extracted and parsed at the same time. Two keeps the worker pool busy - the next zip
    /// extracts while the previous one finishes its long-running tools - while a batch with
    /// cleanup on still only needs space for two extracted collections.
    /// </summary>
    public int ArchivesAtOnce { get; init; } = 2;
}

public enum ExtractionStage { Extracting, Extracted, Failed, CleanedUp, Skipped }

/// <summary>
/// Progress of one zip, which holds one collection per drive-letter folder inside it (usually
/// one). On <see cref="ExtractionStage.Extracted"/>, <see cref="Planned"/> holds the work found
/// inside, which could not be known before the run started.
/// </summary>
public sealed record ExtractionEvent(
    string ArchivePath, IReadOnlyList<ResolvedTarget> Collections, ExtractionStage Stage, string? Message = null,
    long BytesDone = 0, long BytesTotal = 0, IReadOnlyList<WorkItem>? Planned = null);

/// <summary>One module against one target, for one iteration (a user, or a glob match).</summary>
public sealed class WorkItem
{
    public required ModuleDefinition Module { get; init; }
    public required ResolvedTarget Target { get; init; }
    public required string Destination { get; init; }
    /// <summary>
    /// The user's subfolder within the category, when this item belongs to one profile; Destination
    /// already ends with it. Null for collection-wide output, which sits in the category folder.
    /// </summary>
    public string? UserFolder { get; init; }
    /// <summary>User name or match name; null when the module does not iterate.</summary>
    public string? IterationKey { get; init; }
    public string? MatchPath { get; init; }
    /// <summary>
    /// Full path to the profile directory under Iterate: userprofile. Modules should use this
    /// rather than assuming every profile sits under one shared parent, which does not hold on
    /// Linux where root lives outside /home.
    /// </summary>
    public string? UserHome { get; init; }

    public string Label => IterationKey is null
        ? $"{Target.CollectionName}/{Module.Name}"
        : $"{Target.CollectionName}/{Module.Name}[{IterationKey}]";

    /// <summary>Stable identity used by the resume state file.</summary>
    public string Key => $"{Target.CollectionName}|{Module.Name}|{IterationKey ?? "-"}";
}

public sealed class ProcessorRecord
{
    /// <summary>"prepare" for a staging step, "process" for one that produces output.</summary>
    public string Phase { get; init; } = "process";
    public required string Executable { get; init; }
    public required string Arguments { get; init; }
    public string? ToolVersion { get; init; }
    public string? ToolSha256 { get; init; }
    public string WorkingDirectory { get; init; } = "";
    public int ExitCode { get; init; }
    public bool WroteToStderr { get; init; }
    /// <summary>True when everything on stderr matched the processor's ExpectedStderr patterns.</summary>
    public bool StderrExpected { get; init; }
    public double DurationSeconds { get; init; }
    public string? StdoutLog { get; init; }
    public string? StderrLog { get; init; }
    public int OutputFilesCreated { get; init; }
    public long OutputBytes { get; init; }
    /// <summary>
    /// What this processor produced, as 'tool filename => delivered filename' when the file was
    /// renamed. Recorded so the chain from command line to the file on disk survives the rename.
    /// </summary>
    public List<string> OutputFiles { get; init; } = [];
    public string? Error { get; init; }
}

public sealed class WorkResult
{
    public required string Collection { get; init; }
    public required string Module { get; init; }
    public required string Category { get; init; }
    public string? Iteration { get; init; }
    public required WorkStatus Status { get; set; }
    public string? Reason { get; set; }
    public string Destination { get; init; } = "";
    public DateTimeOffset Started { get; init; }
    public double DurationSeconds { get; set; }
    public List<ProcessorRecord> Processors { get; } = [];
}

public sealed record ProgressEvent(WorkItem Item, WorkStatus Status, string? Message = null);

/// <summary>A user profile directory found under the layout's declared profile patterns.</summary>
public sealed record UserProfileDirectory(string Name, string Path);
