namespace ArtefactForge.Core;

/// <summary>
/// The Setup tab's run options as last used, so they come back on the next launch. Values are
/// clamped on the way in: a hand-edited or older settings file must not start a run with no
/// workers or hundreds of zips extracting at once.
/// </summary>
public sealed class SavedRunOptions
{
    /// <summary>Upper bounds for values read back. Well past any sensible setting.</summary>
    public const int MaxWorkersLimit = 64;
    public const int MaxZipsAtOnce = 16;

    public int Workers { get; set; } = 8;
    public int HeavyWorkers { get; set; } = 2;
    public int ZipsAtOnce { get; set; } = 2;
    public bool Vss { get; set; }
    public bool SkipCompleted { get; set; } = true;
    public bool CleanupExtracted { get; set; }

    /// <summary>A copy with every number in range. Heavy IO never exceeds the worker count.</summary>
    public SavedRunOptions Clamped()
    {
        var workers = Math.Clamp(Workers, 1, MaxWorkersLimit);
        return new SavedRunOptions
        {
            Workers = workers,
            HeavyWorkers = Math.Clamp(HeavyWorkers, 1, workers),
            ZipsAtOnce = Math.Clamp(ZipsAtOnce, 1, MaxZipsAtOnce),
            Vss = Vss,
            SkipCompleted = SkipCompleted,
            CleanupExtracted = CleanupExtracted
        };
    }
}
