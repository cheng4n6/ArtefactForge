namespace ArtefactForge.Core;

public enum IterationMode { None, Match, UserProfile }
public enum IoWeight { Light, Heavy }
public enum MemoryWeight { Light, Heavy }
/// <summary>
/// Required: never runs unelevated. Live: needs elevation only against a live system, where the
/// files it reads are locked or ACL'd to administrators; a collection is readable either way.
/// </summary>
public enum ElevationRequirement { None, Required, Live }
public enum TargetScope { Any, LiveOnly, OfflineOnly }
public enum UnescapeMode { None, Url }
public enum MarkerMatchMode { Any, All }
public enum OptionKind { Flag, Choice, Text }

/// <summary>
/// Which operating system's artefacts a module parses. Grouping by this keeps the two families
/// apart in the selector - sorted alphabetically the Linux categories land in the middle of the
/// Windows ones, which is how a module gets missed.
/// </summary>
public enum Platform { Any, Windows, Linux }

/// <summary>
/// A switch a module exposes for tuning without editing the file. The module author decides what
/// is adjustable and what the safe default is; the analyst picks a value per run. Anything not
/// declared here cannot be changed at run time, which keeps a run reproducible from the manifest.
/// </summary>
public sealed class ModuleOption
{
    public required string Name { get; init; }
    public string? Description { get; init; }
    public OptionKind Kind { get; init; } = OptionKind.Flag;
    /// <summary>Permitted values for a Choice. Ignored otherwise.</summary>
    public IReadOnlyList<string> Choices { get; init; } = [];
    /// <summary>Value applied when the analyst does not set one. "true"/"false" for a Flag.</summary>
    public string Default { get; init; } = "";
    /// <summary>
    /// Command-line fragment this contributes. '%value%' is replaced for Choice and Text; a Flag
    /// emits the fragment verbatim when on, and nothing when off.
    /// </summary>
    public required string Expand { get; init; }
}

/// <summary>One tool invocation. Maps 1:1 onto a KAPE mkape processor.</summary>
public sealed class ProcessorDefinition
{
    public string Executable { get; init; } = "";
    public string CommandLine { get; init; } = "";
    public string? ExportFormat { get; init; }
    public string? ExportFile { get; init; }

    /// <summary>
    /// Overrides the default working directory (the executable's own folder). Needed by tools that
    /// act on the current directory rather than on a path argument - esentutl's log replay, for one.
    /// </summary>
    public string? WorkingDirectory { get; init; }

    /// <summary>
    /// Keep going when this step exits non-zero. Some staging tools report failure for conditions
    /// that do not actually prevent the artefact being parsed - esentutl log recovery is the case
    /// this exists for.
    /// </summary>
    public bool ContinueOnError { get; init; }

    /// <summary>
    /// Patterns for stderr lines this tool always writes on a good run - a banner, progress lines.
    /// A run whose stderr holds nothing else is not flagged CheckLog. Any line that matches none of
    /// them still is, so a real warning is never hidden. ANSI colour codes are removed before
    /// matching and blank lines are ignored. Needed for tools with no quiet switch, such as
    /// Chainsaw's analyse shimcache.
    /// </summary>
    public List<string> ExpectedStderr { get; init; } = [];

    /// <summary>
    /// The switch that makes this tool read a dirty registry hive whose transaction logs were not
    /// collected (<c>--nl</c> for the EZ Tools hive readers). Without it they skip such a hive,
    /// say so on stdout and still exit 0. When the log says that, the step is run once more with
    /// this added, and the module is flagged CheckLog because recent entries may be missing.
    /// </summary>
    public string? NoLogsArgument { get; init; }
}

/// <summary>
/// A .forge module. KAPE mkape fields are honoured as-is; the remainder are
/// ArtefactForge extensions that KAPE ignores, so files stay portable both ways.
/// </summary>
public sealed class ModuleDefinition
{
    // --- KAPE-compatible ---
    public string Description { get; init; } = "";
    public string Category { get; init; } = "Uncategorised";
    public string? Author { get; init; }
    public string? Version { get; init; }
    public string? Id { get; init; }
    public string? ExportFormat { get; init; }
    public string? FileMask { get; init; }
    public IReadOnlyList<ProcessorDefinition> Processors { get; init; } = [];

    /// <summary>
    /// Steps run before Processors, for staging artefacts that cannot be parsed in place - a
    /// locked ESE database on a live system, say. They write to %workDir%, which is scratch space
    /// deleted after the module finishes and never delivered as output.
    /// </summary>
    public IReadOnlyList<ProcessorDefinition> Prepare { get; init; } = [];

    // --- ArtefactForge extensions ---
    /// <summary>Canonical globs that must resolve or the module is skipped with a reason.</summary>
    public IReadOnlyList<string> Requires { get; init; } = [];
    public IterationMode Iterate { get; init; } = IterationMode.None;
    public Platform Platform { get; init; } = Platform.Any;
    public int Priority { get; init; } = 50;
    public IoWeight IoWeight { get; init; } = IoWeight.Light;
    /// <summary>
    /// Heavy: the tool can take several GB (Chainsaw and Hayabusa over a full Logs folder), so only
    /// one memory-heavy module runs at a time across the whole run.
    /// </summary>
    public MemoryWeight MemoryWeight { get; init; } = MemoryWeight.Light;
    public ElevationRequirement Elevation { get; init; } = ElevationRequirement.None;
    public TargetScope Scope { get; init; } = TargetScope.Any;
    public bool SupportsVss { get; init; }
    public int? Timeout { get; init; }
    /// <summary>
    /// False keeps the module out of "select all" and must be ticked explicitly. Mirrors the
    /// existing script's treatment of SQLECmd, which is far too slow to run by default.
    /// </summary>
    public bool DefaultEnabled { get; init; } = true;
    /// <summary>
    /// Filename prefix for this module's output. Category folders are shared, so this is what
    /// identifies the producing tool. Defaults to the module name.
    /// </summary>
    public string? OutputName { get; init; }

    /// <summary>
    /// Switches the analyst may set per run. The resolved fragments replace '%options%' in the
    /// command line, in declaration order.
    /// </summary>
    public IReadOnlyList<ModuleOption> Options { get; init; } = [];

    /// <summary>Absolute path of the file this was loaded from.</summary>
    public string SourcePath { get; init; } = "";
    public string Name => Path.GetFileNameWithoutExtension(SourcePath);
}

public sealed class LayoutDetectRules
{
    /// <summary>True when the selected path is itself the drive root (mounted drive, live C:).</summary>
    public bool RootIsSelection { get; init; }
    /// <summary>Marker paths; '?' stands for the drive-letter folder.</summary>
    public IReadOnlyList<string> Markers { get; init; } = [];
    public MarkerMatchMode MatchMode { get; init; } = MarkerMatchMode.Any;
    /// <summary>Look for single-character drive-letter folders beneath the selection.</summary>
    public bool DriveLetterFolder { get; init; }
    public int MaxDepth { get; init; } = 1;
}

public sealed class LayoutResolveRules
{
    /// <summary>'.' = selection, '?' = the matched drive-letter folder.</summary>
    public string RootOffset { get; init; } = ".";
    public UnescapeMode Unescape { get; init; } = UnescapeMode.None;

    /// <summary>
    /// Where user profile directories live, relative to the root, for Iterate: userprofile.
    /// Globs are allowed, and a pattern may name a single profile rather than a container of them -
    /// Linux keeps ordinary users under /home but root has its own directory outside it.
    /// </summary>
    public IReadOnlyList<string> UserProfiles { get; init; } = ["Users/*"];
}

public sealed class LayoutProfile
{
    public string Name { get; init; } = "";
    public string Id { get; init; } = "";
    public int Priority { get; init; } = 50;
    /// <summary>Written from documentation rather than verified against a real collection.</summary>
    public bool Provisional { get; init; }
    public string? Description { get; init; }
    public string? Notes { get; init; }
    public LayoutDetectRules Detect { get; init; } = new();
    public LayoutResolveRules Resolve { get; init; } = new();
    /// <summary>
    /// Which operating system a matching folder holds. Modules for the other platform are dropped
    /// from the plan for that collection before their Requires are evaluated. Any, the default,
    /// filters nothing, so a layout that does not say keeps every module in play.
    /// </summary>
    public Platform Platform { get; init; } = Platform.Any;
    public string SourcePath { get; init; } = "";
}

/// <summary>Evidence resolved to a canonical drive root, ready for module execution.</summary>
public sealed class ResolvedTarget
{
    public required string SelectionPath { get; init; }
    public required string Root { get; init; }
    public required LayoutProfile Layout { get; init; }
    /// <summary>Drive letter when known, e.g. "C".</summary>
    public string? DriveLetter { get; init; }
    public bool IsLive { get; init; }
    /// <summary>Name used for the output folder.</summary>
    public required string CollectionName { get; init; }

    /// <summary>
    /// The zip this collection is still packed in - or a collector's folder that must be converted
    /// first, such as an unzipped Velociraptor collection - or null for evidence ready on disk.
    /// Until the engine extracts it, Root and SelectionPath name the source, so nothing may plan
    /// against them.
    /// </summary>
    public string? ArchivePath { get; init; }

    public bool IsArchive => ArchivePath is not null;

    /// <summary>What was detected, in the words the analyst checks before a run: "Windows, collected".</summary>
    public string Kind => (Layout.Platform == Platform.Any ? "" : Layout.Platform + ", ")
                          + (IsLive ? "live"
                             : IsArchive ? (Directory.Exists(ArchivePath) ? "collected, to convert"
                                : ArchivePath!.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ? "collected, zipped"
                                : "collected, archived")
                             : "collected");

    /// <summary>
    /// A copy under a different name. Detection can only name a mounted image after its drive
    /// letter, which is an accident of what was free at mount time; the analyst usually knows the
    /// host. Everything else about the target is unchanged.
    /// </summary>
    public ResolvedTarget Renamed(string collectionName) => new()
    {
        SelectionPath  = SelectionPath,
        Root           = Root,
        Layout         = Layout,
        DriveLetter    = DriveLetter,
        IsLive         = IsLive,
        CollectionName = collectionName,
        ArchivePath    = ArchivePath
    };
}

/// <summary>A file that failed to load, kept so the GUI can explain rather than silently drop it.</summary>
public sealed record LoadError(string Path, string Message);

public sealed class LoadResult<T>
{
    public List<T> Items { get; } = [];
    public List<LoadError> Errors { get; } = [];
}
