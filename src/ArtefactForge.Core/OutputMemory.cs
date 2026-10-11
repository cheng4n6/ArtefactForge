namespace ArtefactForge.Core;

/// <summary>Where one evidence folder's output went the last time it was run.</summary>
public sealed class RememberedOutput
{
    /// <summary>The evidence folder or zip, as a full path.</summary>
    public required string EvidencePath { get; init; }

    public required string OutputRoot { get; init; }

    public required string CaseName { get; init; }

    /// <summary>
    /// The output root relative to the evidence path, or null when the two are on different
    /// drives. Kept so a case folder holding both (`triagedata` beside `triageoutput`) can be
    /// recognised after it moves.
    /// </summary>
    public string? OutputRelative { get; init; }

    /// <summary>
    /// Collections the analyst renamed, keyed by their folder or zip relative to the evidence path
    /// so the names survive the case folder moving. Without them a renamed collection comes back
    /// under its detected name and is processed again into a second folder.
    /// </summary>
    public Dictionary<string, string> CollectionNames { get; init; } = [];

    public required DateTimeOffset LastUsed { get; init; }
}

/// <summary>How sure a recall is, which decides whether the analyst is asked to confirm.</summary>
public enum RecallCertainty
{
    /// <summary>This evidence path was run before and its case folder is still there.</summary>
    Remembered,

    /// <summary>A match that is likely but not proven: the case folder moved, or the output is gone.</summary>
    BestGuess,

    /// <summary>Nothing is known about this evidence; the default output applies.</summary>
    Unknown
}

public sealed class OutputRecall
{
    public required RecallCertainty Certainty { get; init; }

    /// <summary>The output root to use, or null to keep the default.</summary>
    public string? OutputRoot { get; init; }

    /// <summary>The case name to use, or null to keep the detected one.</summary>
    public string? CaseName { get; init; }

    /// <summary>One line for the analyst: what was matched, or why it is not certain.</summary>
    public required string Message { get; init; }

    /// <summary>Renamed collections from the matched run, keyed by full source path as it is now.</summary>
    public IReadOnlyDictionary<string, string> CollectionNames { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The remembered name for a collection's folder or zip, or null to keep the detected one.</summary>
    public string? NameFor(string sourcePath) =>
        CollectionNames.TryGetValue(OutputMemory.Normalise(sourcePath), out var name) ? name : null;
}

/// <summary>A collection as it stood when a run started: its folder or zip, and its name if renamed.</summary>
public sealed record CollectionNameChoice(string SourcePath, string? Rename);

/// <summary>
/// Remembers, per evidence folder, the output folder and case name of its last run, so coming back
/// to a case with new evidence writes into the same case directory. Only an exact path whose case
/// folder still exists counts as remembered; anything less is a guess the analyst confirms, because
/// output written to the wrong case is worse than a question.
/// </summary>
public static class OutputMemory
{
    /// <summary>Enough for every live case; the oldest entries drop off beyond it.</summary>
    public const int MaxEntries = 50;

    public static OutputRecall Recall(IReadOnlyList<RememberedOutput> entries, string evidencePath)
    {
        var evidence = Normalise(evidencePath);
        var exact = entries.FirstOrDefault(e => SamePath(e.EvidencePath, evidence));

        if (exact is not null)
        {
            var caseDirectory = Path.Combine(exact.OutputRoot, exact.CaseName);
            if (Directory.Exists(caseDirectory))
            {
                return new OutputRecall
                {
                    Certainty = RecallCertainty.Remembered,
                    OutputRoot = exact.OutputRoot,
                    CaseName = exact.CaseName,
                    Message = $"Remembered from the last run of this evidence on {exact.LastUsed.LocalDateTime:d MMM yyyy}.",
                    CollectionNames = Resolve(exact, evidence)
                };
            }

            // The output was moved or deleted. Offer it again rather than the default - the engine
            // recreates it - but the analyst has to say so, since it may have moved on purpose.
            return new OutputRecall
            {
                Certainty = RecallCertainty.BestGuess,
                OutputRoot = exact.OutputRoot,
                CaseName = exact.CaseName,
                Message = $"Last run's case folder {caseDirectory} no longer exists. "
                          + "Confirm to recreate it there, or choose another output folder.",
                CollectionNames = Resolve(exact, evidence)
            };
        }

        // Not seen at this path: the case folder may have moved with its output beside it. Every
        // case laid out the same way gives the same relative path, so it only counts if the case
        // folder it points at is really there.
        foreach (var entry in entries.Where(e => e.OutputRelative is not null).OrderByDescending(e => e.LastUsed))
        {
            var candidate = Normalise(Path.Combine(evidence, entry.OutputRelative!));
            if (!Directory.Exists(Path.Combine(candidate, entry.CaseName))) continue;

            return new OutputRecall
            {
                Certainty = RecallCertainty.BestGuess,
                OutputRoot = candidate,
                CaseName = entry.CaseName,
                Message = $"New evidence path, but case '{entry.CaseName}' is in the same place relative to it "
                          + $"as when it was run from {entry.EvidencePath}. Has the case folder moved? Please confirm.",
                CollectionNames = Resolve(entry, evidence)
            };
        }

        return new OutputRecall
        {
            Certainty = RecallCertainty.Unknown,
            Message = "New evidence folder, so the default output folder is shown. Please confirm where the output should go."
        };
    }

    /// <summary>
    /// Records a run, replacing any earlier entry for the same evidence path. Renames of collections
    /// not in this run are kept, so running a subset of the folder does not forget the rest.
    /// </summary>
    public static void Record(List<RememberedOutput> entries, string evidencePath, string outputRoot,
                              string caseName, DateTimeOffset when,
                              IReadOnlyList<CollectionNameChoice>? collections = null)
    {
        var evidence = Normalise(evidencePath);
        var output = Normalise(outputRoot);
        var relative = Path.GetRelativePath(evidence, output);

        var previous = entries.FirstOrDefault(e => SamePath(e.EvidencePath, evidence));
        var names = new Dictionary<string, string>(previous?.CollectionNames ?? [], StringComparer.OrdinalIgnoreCase);
        foreach (var collection in collections ?? [])
        {
            var key = Path.GetRelativePath(evidence, Normalise(collection.SourcePath));
            if (collection.Rename is null) names.Remove(key);
            else names[key] = collection.Rename;
        }

        entries.RemoveAll(e => SamePath(e.EvidencePath, evidence));
        entries.Insert(0, new RememberedOutput
        {
            EvidencePath = evidence,
            OutputRoot = output,
            CaseName = caseName,
            // GetRelativePath hands back the absolute path when there is no relative one.
            OutputRelative = Path.IsPathRooted(relative) ? null : relative,
            CollectionNames = names,
            LastUsed = when
        });

        if (entries.Count > MaxEntries)
        {
            var keep = entries.OrderByDescending(e => e.LastUsed).Take(MaxEntries).ToList();
            entries.Clear();
            entries.AddRange(keep);
        }
    }

    /// <summary>An entry's renames keyed by where those collections are now, under this evidence path.</summary>
    private static Dictionary<string, string> Resolve(RememberedOutput entry, string evidence) =>
        entry.CollectionNames.ToDictionary(n => Normalise(Path.Combine(evidence, n.Key)), n => n.Value,
                                           StringComparer.OrdinalIgnoreCase);

    internal static string Normalise(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path.Trim()));

    private static bool SamePath(string a, string b) =>
        StringComparer.OrdinalIgnoreCase.Equals(Normalise(a), b);
}
