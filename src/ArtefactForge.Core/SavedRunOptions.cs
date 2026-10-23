using System.Globalization;

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
    public const double MaxKeepFreeGB = 64;

    public int Workers { get; set; } = 8;
    public int HeavyWorkers { get; set; } = 2;
    public int ZipsAtOnce { get; set; } = 2;
    public bool Vss { get; set; }
    public bool SkipCompleted { get; set; } = true;
    public bool CleanupExtracted { get; set; }
    /// <summary>No new module starts while free memory is under this; 0 turns it off.</summary>
    public double KeepFreeGB { get; set; } = 1;

    /// <summary>Keep free in bytes, as the engine takes it.</summary>
    public static long ToBytes(double gb) => (long)(gb * (1L << 30));

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
            CleanupExtracted = CleanupExtracted,
            KeepFreeGB = double.IsFinite(KeepFreeGB) ? Math.Clamp(KeepFreeGB, 0, MaxKeepFreeGB) : 1
        };
    }

    /// <summary>
    /// One line for each number <see cref="Clamped"/> changed, so a front end says so instead of
    /// running with a value the analyst did not type.
    /// </summary>
    public List<string> Adjustments(SavedRunOptions clamped)
    {
        var lines = new List<string>();
        Check("Workers", Workers, clamped.Workers);
        Check("Heavy IO", HeavyWorkers, clamped.HeavyWorkers);
        Check("Zips at once", ZipsAtOnce, clamped.ZipsAtOnce);
        Check("Keep free (GB)", KeepFreeGB, clamped.KeepFreeGB);
        return lines;

        void Check(string name, double typed, double used)
        {
            if (typed.Equals(used)) return;
            var why = name == "Heavy IO" && used == clamped.Workers && typed > used ? "more than the workers" : "out of range";
            lines.Add($"{name} {Format(typed)} is {why}; using {Format(used)}.");
        }

        static string Format(double value) => value.ToString("0.##", CultureInfo.InvariantCulture);
    }

    /// <summary>A whole number typed into a box or after a flag. Anything else is refused, not defaulted.</summary>
    public static bool TryParseCount(string? text, out int value) =>
        int.TryParse(text?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    /// <summary>A size in GB, in the given culture (the GUI's, or invariant on the command line). NaN and infinity are refused.</summary>
    public static bool TryParseGB(string? text, IFormatProvider culture, out double value) =>
        double.TryParse(text?.Trim(), NumberStyles.Float, culture, out value) && double.IsFinite(value);
}
