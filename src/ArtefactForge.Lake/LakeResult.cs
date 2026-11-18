namespace ArtefactForge.Lake;

/// <summary>How a build ended.</summary>
public enum LakeOutcome
{
    /// <summary>Built and in place, and every source that should load did.</summary>
    Built,
    /// <summary>Built and in place, but something needs a look: a header mismatch, rejected rows, a source that failed.</summary>
    BuiltCheckLog,
    /// <summary>
    /// Built, but the old case.duckdb could not be replaced (it is open in another program). The
    /// new lake is left beside it as case.duckdb.new.
    /// </summary>
    NotSwapped,
    /// <summary>No lake was built; the old one, if any, is unchanged.</summary>
    Failed
}

/// <summary>What happened to one source file.</summary>
public sealed record LakeSourceResult
{
    public required int SourceId { get; init; }
    public required string Host { get; init; }
    public required string Path { get; init; }
    public string? Kind { get; init; }
    public string? Parser { get; init; }
    public string? ParserVersion { get; init; }
    public string? OutputStatus { get; init; }
    /// <summary>loaded, skipped, header_mismatch or failed.</summary>
    public required string Status { get; init; }
    public string? Reason { get; init; }
    public long RowsLoaded { get; init; }
    public long RowsRejected { get; init; }
    /// <summary>Rows whose time could not be read: in the raw table, not the timeline.</summary>
    public long TimeUnread { get; init; }
    /// <summary>Rows with only the host's local time, converted to UTC with its time zone.</summary>
    public long TimeConverted { get; init; }
    public long TimelineRows { get; init; }

    public bool NeedsReview => Status is SourceStatus.HeaderMismatch or SourceStatus.Failed || RowsRejected > 0 || TimeUnread > 0;
}

/// <summary>The words <see cref="LakeSourceResult.Status"/> takes.</summary>
public static class SourceStatus
{
    public const string Loaded = "loaded";
    public const string Skipped = "skipped";
    public const string HeaderMismatch = "header_mismatch";
    public const string Failed = "failed";
}

/// <summary>The outcome of <see cref="LakeBuilder.Build"/>.</summary>
public sealed record LakeResult
{
    public required LakeOutcome Outcome { get; init; }
    /// <summary>One line for the analyst: what was built, or why not.</summary>
    public required string Message { get; init; }
    /// <summary>The lake: case.duckdb, or case.duckdb.new when it could not be swapped in. Null when none was built.</summary>
    public string? DatabasePath { get; init; }
    public string? LakeDirectory { get; init; }
    public IReadOnlyList<string> Hosts { get; init; } = [];
    public IReadOnlyList<LakeSourceResult> Sources { get; init; } = [];
    /// <summary>Problems that are not about one source: an unreadable outputs.json, a host with no CSVs.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
    public long RawRows { get; init; }
    public long TimelineRows { get; init; }
    public string? DuckDbVersion { get; init; }
    public DateTime StartedUtc { get; init; }
    public TimeSpan Duration { get; init; }

    public int Loaded => Sources.Count(s => s.Status == SourceStatus.Loaded);
    public int Skipped => Sources.Count(s => s.Status == SourceStatus.Skipped);
    public int Mismatched => Sources.Count(s => s.Status == SourceStatus.HeaderMismatch);
    public int FailedSources => Sources.Count(s => s.Status == SourceStatus.Failed);
}
