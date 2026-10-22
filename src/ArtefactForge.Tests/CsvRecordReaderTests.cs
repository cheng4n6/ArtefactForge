using System.Text;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Tests;

/// <summary>
/// The reader under IP history, the RDP trace and the case report. It scans a buffer at a time and
/// can skip the rest of a record, so cells that span buffers and skipped quoted text are the risks.
/// </summary>
public class CsvRecordReaderTests
{
    private static List<List<string>> ReadAll(string text, int decideAfter = int.MaxValue,
                                              Func<List<string>, bool>? wantRest = null, bool bom = false)
    {
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "x.csv");
        File.WriteAllText(path, text, new UTF8Encoding(bom));
        using var reader = new CsvRecordReader(path);
        var records = new List<List<string>>();
        while (reader.ReadRecord(decideAfter, wantRest) is { } record) records.Add(record);
        return records;
    }

    [Fact]
    public void Quoted_cells_keep_commas_quotes_and_line_breaks()
    {
        var records = ReadAll("a,b,c\r\n1,\"x, \"\"y\"\"\r\nz\",3\r\n", bom: true);

        Assert.Equal(2, records.Count);
        Assert.Equal(new[] { "a", "b", "c" }, records[0]);
        Assert.Equal(new[] { "1", "x, \"y\"\r\nz", "3" }, records[1]);
    }

    [Fact]
    public void Empty_cells_and_a_last_line_without_a_break_are_read()
    {
        var records = ReadAll("a,,c\n,,\nlast,one");

        Assert.Equal(3, records.Count);
        Assert.Equal(new[] { "a", "", "c" }, records[0]);
        Assert.Equal(new[] { "", "", "" }, records[1]);
        Assert.Equal(new[] { "last", "one" }, records[2]);
    }

    [Fact]
    public void Cells_longer_than_the_buffer_come_back_whole()
    {
        var plain = new string('p', 200_000);
        var quoted = string.Concat(Enumerable.Repeat("q\"\"\n", 50_000));
        var records = ReadAll($"{plain},\"{quoted}\",end\nnext,row\n");

        Assert.Equal(2, records.Count);
        Assert.Equal(plain, records[0][0]);
        Assert.Equal(quoted.Replace("\"\"", "\""), records[0][1]);
        Assert.Equal("end", records[0][2]);
        Assert.Equal(new[] { "next", "row" }, records[1]);
    }

    [Fact]
    public void A_record_not_wanted_returns_its_first_cells_and_the_next_record_is_intact()
    {
        // The skipped payload holds a quoted line break, escaped quotes and a comma, and is longer
        // than the buffer, so a skip that lost track of quoting would split the next record.
        var payload = "\"{\"\"a\"\":\"\"x,\ny\"\"}" + new string('z', 100_000) + "\"";
        var text = $"Channel,EventId,Payload\nSystem,7,{payload}\nSecurity,4624,{payload}\nSystem,8,short\n";

        var records = ReadAll(text, decideAfter: 1, wantRest: f => f[0] == "Security" || f[0] == "Channel");

        Assert.Equal(4, records.Count);
        Assert.Equal(new[] { "Channel", "EventId", "Payload" }, records[0]);
        Assert.Equal(new[] { "System", "7" }, records[1]);
        Assert.Equal(3, records[2].Count);
        Assert.StartsWith("{\"a\":\"x,\ny\"}", records[2][2]);
        Assert.Equal(new[] { "System", "8" }, records[3]);
    }

    [Fact]
    public void A_record_shorter_than_the_decision_point_comes_back_whole()
    {
        var records = ReadAll("only\n", decideAfter: 3, wantRest: _ => false);

        Assert.Equal(new[] { "only" }, Assert.Single(records));
    }
}
