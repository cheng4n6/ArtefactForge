namespace ArtefactForge.Lake;

/// <summary>How a lake is built.</summary>
public sealed record LakeOptions
{
    /// <summary>
    /// The most memory DuckDB may use, in bytes; it spills to &lt;lake&gt;\tmp beyond that. Null takes
    /// a quarter of the machine's memory, at least 1 GB: DuckDB's own default is 80%, which has
    /// taken workstations down alongside the rest of a run.
    /// </summary>
    public long? MemoryLimitBytes { get; init; }

    /// <summary>Threads DuckDB may use. Null takes half the logical processors, at least one.</summary>
    public int? Threads { get; init; }

    /// <summary>
    /// Treat the whole folder as one host of this name instead of one host per subfolder: for a
    /// folder of parser output from a single machine.
    /// </summary>
    public string? SingleHost { get; init; }

    /// <summary>
    /// Where the lake is written. Null is &lt;case&gt;\_Lake. Set it to build from a folder that
    /// must not be written to.
    /// </summary>
    public string? LakeDirectory { get; init; }

    /// <summary>The program building the lake, recorded in lake_meta and build.json.</summary>
    public string Producer { get; init; } = "af-lake";

    /// <summary>
    /// Lines the caller wants at the top of lake.log, such as what it did to the case before the
    /// build (ArtefactForge writes outputs.json for hosts that had none).
    /// </summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    internal long EffectiveMemoryLimitBytes()
    {
        if (MemoryLimitBytes is > 0) return MemoryLimitBytes.Value;
        var total = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        return Math.Max(1L << 30, total / 4);
    }

    internal int EffectiveThreads() =>
        Threads is > 0 ? Threads.Value : Math.Max(1, Environment.ProcessorCount / 2);
}
