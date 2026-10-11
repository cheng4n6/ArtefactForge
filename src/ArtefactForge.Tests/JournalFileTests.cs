using System.Text;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

public class JournalFileTests
{
    private static string Text(JournalEntry entry, string name) => Encoding.UTF8.GetString(entry.Get(name)!);

    private static List<JournalEntry> Read(string path, out JournalFile file)
    {
        file = JournalFile.Open(path);
        return file.ReadEntries().ToList();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Reads_entries_and_shared_fields_in_both_layouts(bool compact)
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter(compact);
        var host = w.AddData("_HOSTNAME", "web01");
        var m1 = w.AddData("MESSAGE", "first");
        var m2 = w.AddData("MESSAGE", "second");
        w.AddEntry(1, 1_700_000_000_000_000, host, m1);
        w.AddEntry(2, 1_700_000_001_500_000, host, m2);

        var entries = Read(w.WriteTo(Path.Combine(dir.Path, "system.journal")), out var file);
        using (file)
        {
            Assert.Equal(compact, file.Compact);
            Assert.Equal(2, entries.Count);
            Assert.Equal("web01", Text(entries[1], "_HOSTNAME"));
            Assert.Equal("second", Text(entries[1], "MESSAGE"));
            Assert.Equal(new DateTime(2023, 11, 14, 22, 13, 21, 500, DateTimeKind.Utc), entries[1].RealtimeUtc);
            Assert.Equal("abababababababababababababababab", entries[0].BootId);
            Assert.Empty(file.Warnings);
        }
    }

    [Theory]
    [InlineData(TestCompression.Zstd)]
    [InlineData(TestCompression.Lz4)]
    public void Decompresses_fields(TestCompression compression)
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        var long_ = string.Concat(Enumerable.Repeat("compressed payload ", 60));
        w.AddEntry(1, 1, w.AddData("MESSAGE", long_, compression));

        var entries = Read(w.WriteTo(Path.Combine(dir.Path, "c.journal")), out var file);
        using (file) Assert.Equal(long_, Text(Assert.Single(entries), "MESSAGE"));
    }

    [Fact]
    public void Binary_values_survive_untouched()
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        var blob = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        w.AddEntry(1, 1, w.AddData("BLOB", blob));

        var entries = Read(w.WriteTo(Path.Combine(dir.Path, "b.journal")), out var file);
        using (file) Assert.Equal(blob, Assert.Single(entries).Get("BLOB"));
    }

    [Fact]
    public void Entries_beyond_the_header_count_are_recovered()
    {
        // An unclosed file: journald had appended entries the header had not been updated for.
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        var m = w.AddData("MESSAGE", "x");
        w.AddEntry(1, 1, m);
        w.AddEntry(2, 2, m);
        w.AddEntry(3, 3, m);
        var path = Path.Combine(dir.Path, "system.journal~");
        File.WriteAllBytes(path, w.Build(state: 1, entryCount: 1));

        var entries = Read(path, out var file);
        using (file)
        {
            Assert.Equal(1UL, file.HeaderEntryCount);
            Assert.Equal(3, entries.Count);
        }
    }

    [Fact]
    public void A_truncated_file_keeps_what_precedes_the_damage_and_says_so()
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        var m = w.AddData("MESSAGE", "kept");
        w.AddEntry(1, 1, m);
        w.AddEntry(2, 2, m);
        var bytes = w.Build();
        var path = Path.Combine(dir.Path, "cut.journal");
        File.WriteAllBytes(path, bytes[..^20]);

        var entries = Read(path, out var file);
        using (file)
        {
            Assert.Single(entries);
            Assert.Contains(file.Warnings, x => x.Contains("impossible size"));
        }
    }

    [Fact]
    public void An_entry_with_an_unreadable_field_is_kept_and_marked()
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        var good = w.AddData("MESSAGE", "survives");
        w.AddEntry(1, 1, good, 8);   // 8 is inside the header: not a data object

        var entries = Read(w.WriteTo(Path.Combine(dir.Path, "d.journal")), out var file);
        using (file)
        {
            var entry = Assert.Single(entries);
            Assert.Equal("survives", Text(entry, "MESSAGE"));
            Assert.Equal("1", Text(entry, "__AF_UNREADABLE_FIELDS"));
            Assert.Single(file.Warnings);
        }
    }

    [Fact]
    public void Unknown_format_features_are_refused_rather_than_misread()
    {
        using var dir = new TempDirectory();
        var w = new TestJournalWriter();
        var path = w.WriteTo(Path.Combine(dir.Path, "future.journal"), extraIncompatibleFlags: 1u << 10);

        var ex = Assert.Throws<InvalidDataException>(() => JournalFile.Open(path));
        Assert.Contains("0x400", ex.Message);
    }

    [Fact]
    public void Not_a_journal_is_refused()
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "fake.journal");
        File.WriteAllBytes(path, new byte[512]);
        Assert.Throws<InvalidDataException>(() => JournalFile.Open(path));
    }

    [Fact]
    public void Lz4_match_may_overlap_its_own_output()
    {
        // "abc" as literals, then a 9-byte match at offset 3: "abcabcabcabc". The overlap is how
        // LZ4 encodes runs, and a decoder that block-copies gets it wrong.
        byte[] block = [0x35, (byte)'a', (byte)'b', (byte)'c', 3, 0];
        Assert.Equal("abcabcabcabc", Encoding.ASCII.GetString(Lz4Block.Decode(block, 12)));
    }

    [Fact]
    public void Lz4_offset_before_the_start_is_rejected()
    {
        byte[] block = [0x10, (byte)'a', 5, 0];
        Assert.Throws<InvalidDataException>(() => Lz4Block.Decode(block, 5));
    }
}
