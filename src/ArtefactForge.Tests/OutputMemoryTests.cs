using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Coming back to a case with new evidence should write into the same case folder as before, but
/// only an exact, still-present match is trusted without asking. A guess has to be confirmed.
/// </summary>
public class OutputMemoryTests
{
    private static readonly DateTimeOffset Earlier = new(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Later = new(2026, 10, 3, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Evidence_never_run_before_falls_back_to_the_default()
    {
        using var temp = new TempDirectory();
        var evidence = temp.Dir(Path.Combine("CaseA", "triagedata"));

        var recall = OutputMemory.Recall([], evidence);

        Assert.Equal(RecallCertainty.Unknown, recall.Certainty);
        Assert.Null(recall.OutputRoot);
        Assert.Null(recall.CaseName);
    }

    [Fact]
    public void Same_evidence_with_its_case_folder_present_is_remembered()
    {
        using var temp = new TempDirectory();
        var evidence = temp.Dir(Path.Combine("CaseA", "triagedata"));
        var output = temp.Dir(Path.Combine("CaseA", "triageoutput"));
        Directory.CreateDirectory(Path.Combine(output, "CaseA"));
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, evidence, output, "CaseA", Earlier);

        var recall = OutputMemory.Recall(entries, evidence + Path.DirectorySeparatorChar);

        Assert.Equal(RecallCertainty.Remembered, recall.Certainty);
        Assert.Equal(output, recall.OutputRoot);
        Assert.Equal("CaseA", recall.CaseName);
    }

    [Fact]
    public void Evidence_path_matches_regardless_of_case()
    {
        using var temp = new TempDirectory();
        var evidence = temp.Dir(Path.Combine("CaseA", "triagedata"));
        var output = temp.Dir(Path.Combine("CaseA", "triageoutput", "CaseA"));
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, evidence, Path.GetDirectoryName(output)!, "CaseA", Earlier);

        var recall = OutputMemory.Recall(entries, evidence.ToUpperInvariant());

        Assert.Equal(RecallCertainty.Remembered, recall.Certainty);
    }

    [Fact]
    public void A_missing_case_folder_is_offered_but_must_be_confirmed()
    {
        using var temp = new TempDirectory();
        var evidence = temp.Dir(Path.Combine("CaseA", "triagedata"));
        var output = Path.Combine(temp.Path, "CaseA", "triageoutput");
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, evidence, output, "CaseA", Earlier);

        var recall = OutputMemory.Recall(entries, evidence);

        Assert.Equal(RecallCertainty.BestGuess, recall.Certainty);
        Assert.Equal(output, recall.OutputRoot);
        Assert.Contains("no longer exists", recall.Message);
    }

    [Fact]
    public void A_moved_case_folder_is_found_beside_the_evidence_but_must_be_confirmed()
    {
        using var temp = new TempDirectory();
        var oldEvidence = Path.Combine(temp.Path, "Old", "CaseA", "triagedata");
        var oldOutput = Path.Combine(temp.Path, "Old", "CaseA", "triageoutput");
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, oldEvidence, oldOutput, "CaseA", Earlier);

        var newEvidence = temp.Dir(Path.Combine("New", "CaseA", "triagedata"));
        var newOutput = temp.Dir(Path.Combine("New", "CaseA", "triageoutput"));
        Directory.CreateDirectory(Path.Combine(newOutput, "CaseA"));

        var recall = OutputMemory.Recall(entries, newEvidence);

        Assert.Equal(RecallCertainty.BestGuess, recall.Certainty);
        Assert.Equal(newOutput, recall.OutputRoot);
        Assert.Equal("CaseA", recall.CaseName);
    }

    [Fact]
    public void A_new_case_laid_out_like_an_old_one_is_not_mistaken_for_it()
    {
        // Every case uses triagedata and triageoutput, so the relative path alone proves nothing.
        using var temp = new TempDirectory();
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, Path.Combine(temp.Path, "CaseA", "triagedata"),
                            Path.Combine(temp.Path, "CaseA", "triageoutput"), "CaseA", Earlier);

        var evidence = temp.Dir(Path.Combine("CaseB", "triagedata"));
        temp.Dir(Path.Combine("CaseB", "triageoutput"));

        var recall = OutputMemory.Recall(entries, evidence);

        Assert.Equal(RecallCertainty.Unknown, recall.Certainty);
    }

    [Fact]
    public void Recording_the_same_evidence_again_replaces_the_earlier_entry()
    {
        using var temp = new TempDirectory();
        var evidence = Path.Combine(temp.Path, "CaseA", "triagedata");
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, evidence, Path.Combine(temp.Path, "First"), "CaseA", Earlier);
        OutputMemory.Record(entries, evidence, Path.Combine(temp.Path, "Second"), "CaseA", Later);

        var entry = Assert.Single(entries);
        Assert.Equal(Path.Combine(temp.Path, "Second"), entry.OutputRoot);
        Assert.Equal(Later, entry.LastUsed);
    }

    [Fact]
    public void Renamed_collections_come_back_under_their_new_names()
    {
        using var temp = new TempDirectory();
        var evidence = temp.Dir(Path.Combine("CaseA", "triagedata"));
        var output = temp.Dir(Path.Combine("CaseA", "triageoutput", "CaseA"));
        var older = Path.Combine(evidence, "WKS01.zip");
        var newer = Path.Combine(evidence, "WKS01-2.zip");
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, evidence, Path.GetDirectoryName(output)!, "CaseA", Earlier,
                            [new(older, "WKS01-Old"), new(newer, "WKS01-New")]);

        var recall = OutputMemory.Recall(entries, evidence);

        Assert.Equal("WKS01-Old", recall.NameFor(older));
        Assert.Equal("WKS01-New", recall.NameFor(newer));
        Assert.Null(recall.NameFor(Path.Combine(evidence, "HOST01.zip")));
    }

    [Fact]
    public void Renames_follow_a_moved_case_folder()
    {
        using var temp = new TempDirectory();
        var entries = new List<RememberedOutput>();
        var oldEvidence = Path.Combine(temp.Path, "Old", "CaseA", "triagedata");
        OutputMemory.Record(entries, oldEvidence, Path.Combine(temp.Path, "Old", "CaseA", "triageoutput"),
                            "CaseA", Earlier, [new(Path.Combine(oldEvidence, "WKS01.zip"), "WKS01-Old")]);

        var newEvidence = temp.Dir(Path.Combine("New", "CaseA", "triagedata"));
        temp.Dir(Path.Combine("New", "CaseA", "triageoutput", "CaseA"));

        var recall = OutputMemory.Recall(entries, newEvidence);

        Assert.Equal("WKS01-Old", recall.NameFor(Path.Combine(newEvidence, "WKS01.zip")));
    }

    [Fact]
    public void A_later_run_keeps_renames_of_collections_it_did_not_include_and_drops_undone_ones()
    {
        using var temp = new TempDirectory();
        var evidence = Path.Combine(temp.Path, "CaseA", "triagedata");
        var output = Path.Combine(temp.Path, "CaseA", "triageoutput");
        var first = Path.Combine(evidence, "WKS01.zip");
        var second = Path.Combine(evidence, "WKS01-2.zip");
        var entries = new List<RememberedOutput>();
        OutputMemory.Record(entries, evidence, output, "CaseA", Earlier,
                            [new(first, "WKS01-Old"), new(second, "WKS01-New")]);

        OutputMemory.Record(entries, evidence, output, "CaseA", Later, [new(second, null)]);

        var names = Assert.Single(entries).CollectionNames;
        Assert.Equal("WKS01-Old", Assert.Single(names).Value);
    }

    [Fact]
    public void Only_the_most_recent_entries_are_kept()
    {
        using var temp = new TempDirectory();
        var entries = new List<RememberedOutput>();
        for (var i = 0; i <= OutputMemory.MaxEntries; i++)
        {
            OutputMemory.Record(entries, Path.Combine(temp.Path, $"Case{i}", "triagedata"),
                                Path.Combine(temp.Path, $"Case{i}", "triageoutput"), $"Case{i}",
                                Earlier.AddHours(i));
        }

        Assert.Equal(OutputMemory.MaxEntries, entries.Count);
        Assert.DoesNotContain(entries, e => e.CaseName == "Case0");
    }
}
