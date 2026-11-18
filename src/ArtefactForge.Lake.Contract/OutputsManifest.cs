using System.Text.Json.Serialization;

namespace ArtefactForge.Lake.Contract;

/// <summary>
/// &lt;Case&gt;\&lt;Host&gt;\outputs.json: what produced each file in one host folder. Cumulative across
/// runs, so it describes the whole folder rather than the last run, and every path in it is
/// relative to the host folder so the folder can be moved or copied on its own.
/// </summary>
public sealed record OutputsManifest
{
    /// <summary>The value of <see cref="Format"/> in every outputs.json.</summary>
    public const string FormatName = "evidence-lake-outputs";

    /// <summary>
    /// The format version this library reads and writes. New optional fields keep it; a change a
    /// reader of this version would misread bumps it.
    /// </summary>
    public const int CurrentFormatVersion = 1;

    public string Format { get; init; } = FormatName;
    public int FormatVersion { get; init; } = CurrentFormatVersion;
    public required OutputsProducer Producer { get; init; }
    [JsonConverter(typeof(UtcSecondsConverter))]
    public DateTime UpdatedUtc { get; init; }
    public required OutputsHost Host { get; init; }
    public IReadOnlyList<OutputEntry> Outputs { get; init; } = [];
}

/// <summary>The program that last wrote the file.</summary>
public sealed record OutputsProducer
{
    public required string Name { get; init; }
    public string? Version { get; init; }
    /// <summary>The full build, such as "0.6.0+abc1234", so a file can be traced to its source.</summary>
    public string? Build { get; init; }
}

/// <summary>The host the folder holds.</summary>
public sealed record OutputsHost
{
    /// <summary>The host folder's name, which is the collection name, not necessarily the hostname.</summary>
    public required string Name { get; init; }
    /// <summary>The machine's own name, from its system summary. Null when it was not recorded.</summary>
    public string? Hostname { get; init; }
    /// <summary><see cref="Platforms.Windows"/>, <see cref="Platforms.Linux"/>, or null when not known.</summary>
    public string? Platform { get; init; }
    public string? TimeZone { get; init; }
    [JsonConverter(typeof(UtcSecondsConverter))]
    public DateTime? CollectedUtc { get; init; }
    /// <summary>The collector that took the collection, lower case: "velociraptor", "uac", "kape", "live".</summary>
    public string? Collector { get; init; }
}

/// <summary>One file in the host folder and what produced it.</summary>
public sealed record OutputEntry
{
    /// <summary>Relative to the host folder, with '/' separators: "EventLogs/EvtxECmd_EventLogs.csv".</summary>
    public required string Path { get; init; }
    /// <summary>The file's extension in lower case without the dot: "csv", "json".</summary>
    public string? Format { get; init; }
    /// <summary>The tool that wrote the file, such as "EvtxECmd", or "ArtefactForge" for its own analyses.</summary>
    public required string Parser { get; init; }
    public string? ParserVersion { get; init; }
    public string? ParserSha256 { get; init; }
    /// <summary>
    /// The name the tool gave the file, before it was renamed into the host folder. With
    /// <see cref="Parser"/> it says which mapping applies to the file.
    /// </summary>
    public string? ToolFileName { get; init; }
    public string? Module { get; init; }
    public string? ModuleVersion { get; init; }
    /// <summary>The user profile the file belongs to; null for host-wide output.</summary>
    public string? User { get; init; }
    /// <summary>The tool's command line, so options that change its columns are on record.</summary>
    public string? Arguments { get; init; }
    /// <summary>One of <see cref="OutputStatus"/>: never a number.</summary>
    public required string Status { get; init; }
    [JsonConverter(typeof(UtcSecondsConverter))]
    public DateTime? ProducedUtc { get; init; }
    public long? Bytes { get; init; }
}

/// <summary>The words <see cref="OutputEntry.Status"/> takes.</summary>
public static class OutputStatus
{
    public const string Completed = "completed";
    /// <summary>Completed, but the tool wrote something to its log that needs a look.</summary>
    public const string CheckLog = "checklog";
    public const string NoOutput = "nooutput";
    public const string Failed = "failed";
    public const string TimedOut = "timedout";
    public const string Cancelled = "cancelled";
}

/// <summary>The words <see cref="OutputsHost.Platform"/> takes.</summary>
public static class Platforms
{
    public const string Windows = "windows";
    public const string Linux = "linux";
}
