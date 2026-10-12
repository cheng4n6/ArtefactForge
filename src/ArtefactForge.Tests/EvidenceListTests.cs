using ArtefactForge.Core;
using ClosedXML.Excel;

namespace ArtefactForge.Tests;

/// <summary>
/// The evidence list is half generated and half typed by the analyst, so the tests are mostly
/// about the second half: what someone typed into the spreadsheet must survive every rebuild.
/// </summary>
public class EvidenceListTests
{
    private static void WriteSummary(TempDirectory dir, string collection, params (string Item, string Value)[] facts)
    {
        var folder = Path.Combine(dir.Path, collection, "SystemInfo");
        Directory.CreateDirectory(folder);

        var lines = new List<string> { "\"Category\",\"Item\",\"Value\",\"Source\"" };
        lines.AddRange(facts.Select(f => $"\"Identity\",\"{f.Item}\",\"{f.Value}\",\"test\""));
        File.WriteAllLines(Path.Combine(folder, "SystemInfo.csv"), lines);
    }

    private static List<Dictionary<string, string>> ReadRows(string path)
    {
        using var workbook = new XLWorkbook(path);
        var sheet = workbook.Worksheet("Evidence list");
        var last = sheet.LastColumnUsed()!.ColumnNumber();
        var headers = Enumerable.Range(1, last).Select(c => sheet.Cell(1, c).GetFormattedString()).ToList();

        var rows = new List<Dictionary<string, string>>();
        for (var r = 2; r <= sheet.LastRowUsed()!.RowNumber(); r++)
            rows.Add(headers.Select((h, i) => (h, v: sheet.Cell(r, i + 1).GetFormattedString()))
                            .ToDictionary(p => p.h, p => p.v));
        return rows;
    }

    /// <summary>Types into a column of the row for a collection, the way an analyst would in Excel.</summary>
    private static void Edit(string path, string collection, string column, string value)
    {
        using var workbook = new XLWorkbook(path);
        var sheet = workbook.Worksheet("Evidence list");
        var headers = sheet.Row(1).CellsUsed().ToDictionary(c => c.GetFormattedString(), c => c.Address.ColumnNumber);
        var collectionColumn = headers["Collection"];
        var row = sheet.RowsUsed().Skip(1).First(r => r.Cell(collectionColumn).GetFormattedString() == collection);
        row.Cell(headers[column]).Value = value;
        workbook.Save();
    }

    [Fact]
    public void Lists_one_row_per_collection_with_what_the_summaries_detected()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01",
            ("Hostname", "HOST01"), ("Domain", "corp.example"), ("IPAddresses", "10.0.0.5"),
            ("ProductName", "Windows 10 Pro"), ("DisplayVersion", "22H2"), ("Build", "19045.4291"),
            ("ComputerRole", "Workstation"));
        WriteSummary(dir, "web01",
            ("Hostname", "web01"), ("PRETTY_NAME", "Ubuntu 22.04.4 LTS"), ("IPAddresses", "192.168.1.10/24"),
            ("LiveIPAddresses", "10.1.2.3"), ("SerialNumber", "SN-12345"));

        var result = EvidenceList.Rebuild(dir.Path);

        Assert.Equal(EvidenceListOutcome.Written, result.Outcome);
        Assert.Equal(2, result.Added);
        var rows = ReadRows(result.Path);
        Assert.Equal(2, rows.Count);

        var windows = rows.Single(r => r["Collection"] == "HOST01");
        Assert.Equal("Windows 10 Pro 22H2 (build 19045.4291)", windows["OS version"]);
        Assert.Equal("Workstation", windows["Role (detected)"]);
        Assert.Equal("corp.example", windows["Domain"]);
        Assert.Equal("Present", windows["Status"]);

        var linux = rows.Single(r => r["Collection"] == "web01");
        Assert.Equal("Ubuntu 22.04.4 LTS", linux["OS version"]);
        Assert.Equal("10.1.2.3", linux["IP addresses"]);   // live response over static config
        Assert.Equal("SN-12345", linux["Serial number (detected)"]);
    }

    [Fact]
    public void Analyst_edits_survive_a_rebuild_and_new_collections_are_added_blank()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        var path = EvidenceList.Rebuild(dir.Path).Path;

        Edit(path, "HOST01", "Evidence reference", "007");
        Edit(path, "HOST01", "Notes", "Imaged by alice");
        WriteSummary(dir, "HOST02", ("Hostname", "HOST02"));

        var result = EvidenceList.Rebuild(dir.Path);

        Assert.Equal(EvidenceListOutcome.Written, result.Outcome);
        Assert.Equal(1, result.Added);
        var rows = ReadRows(path);
        Assert.Equal("007", rows.Single(r => r["Collection"] == "HOST01")["Evidence reference"]);
        Assert.Equal("Imaged by alice", rows.Single(r => r["Collection"] == "HOST01")["Notes"]);
        Assert.Equal("", rows.Single(r => r["Collection"] == "HOST02")["Notes"]);
    }

    [Fact]
    public void A_collection_that_leaves_the_case_keeps_its_row_marked_missing()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        WriteSummary(dir, "HOST02", ("Hostname", "HOST02"));
        var path = EvidenceList.Rebuild(dir.Path).Path;
        Edit(path, "HOST02", "Notes", "returned to client");

        Directory.Delete(Path.Combine(dir.Path, "HOST02"), recursive: true);
        var result = EvidenceList.Rebuild(dir.Path);

        Assert.Equal(1, result.Missing);
        var gone = ReadRows(path).Single(r => r["Collection"] == "HOST02");
        Assert.Equal("Missing", gone["Status"]);
        Assert.Equal("HOST02", gone["Hostname"]);            // last known values are kept
        Assert.Equal("returned to client", gone["Notes"]);
    }

    [Fact]
    public void Columns_and_rows_the_analyst_adds_are_kept()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        var path = EvidenceList.Rebuild(dir.Path).Path;

        using (var workbook = new XLWorkbook(path))
        {
            var sheet = workbook.Worksheet("Evidence list");
            var next = sheet.LastColumnUsed()!.ColumnNumber() + 1;
            sheet.Cell(1, next).Value = "Custodian";
            sheet.Cell(2, next).Value = "bob";
            sheet.Cell(3, 1).Value = "E99";                     // Evidence reference, no collection
            workbook.Save();
        }

        WriteSummary(dir, "HOST02", ("Hostname", "HOST02"));
        EvidenceList.Rebuild(dir.Path);

        var rows = ReadRows(path);
        Assert.Equal("bob", rows.Single(r => r["Collection"] == "HOST01")["Custodian"]);
        Assert.Contains(rows, r => r["Collection"] == "" && r["Evidence reference"] == "E99");
        Assert.Equal(3, rows.Count);
    }

    [Fact]
    public void Edits_are_kept_in_the_side_file_when_the_spreadsheet_is_deleted()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        var path = EvidenceList.Rebuild(dir.Path).Path;
        Edit(path, "HOST01", "Confirmed role", "File server");
        EvidenceList.Rebuild(dir.Path);   // reads the edit back into the side file

        File.Delete(path);
        EvidenceList.Rebuild(dir.Path);

        Assert.Equal("File server", ReadRows(path).Single()["Confirmed role"]);
    }

    [Fact]
    public void An_open_spreadsheet_is_not_overwritten_and_is_reported_out_of_date()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        var path = EvidenceList.Rebuild(dir.Path).Path;
        Edit(path, "HOST01", "Notes", "saved before the run");
        WriteSummary(dir, "HOST02", ("Hostname", "HOST02"));
        var before = File.ReadAllBytes(path);

        EvidenceListResult result;
        // Excel's lock: open for writing, others may read.
        using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
        {
            Assert.True(EvidenceList.IsOpen(dir.Path));
            result = EvidenceList.Rebuild(dir.Path);
        }

        Assert.Equal(EvidenceListOutcome.Locked, result.Outcome);
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.False(File.Exists(Path.Combine(dir.Path, "EvidenceList (2).xlsx")));

        // Closed again, a rebuild adds the new collection and keeps the saved edit.
        Assert.Equal(EvidenceListOutcome.Written, EvidenceList.Rebuild(dir.Path).Outcome);
        var rows = ReadRows(path);
        Assert.Equal("saved before the run", rows.Single(r => r["Collection"] == "HOST01")["Notes"]);
        Assert.Contains(rows, r => r["Collection"] == "HOST02");
    }

    [Fact]
    public void A_rebuild_with_nothing_new_leaves_the_file_alone()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        var path = EvidenceList.Rebuild(dir.Path).Path;
        var written = File.GetLastWriteTimeUtc(path);

        var result = EvidenceList.Rebuild(dir.Path);

        Assert.Equal(EvidenceListOutcome.Unchanged, result.Outcome);
        Assert.Equal(written, File.GetLastWriteTimeUtc(path));
    }

    [Fact]
    public void An_unreadable_spreadsheet_is_reported_and_left_as_it_is()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        var path = EvidenceList.PathFor(dir.Path);
        File.WriteAllText(path, "not a workbook");

        var result = EvidenceList.Rebuild(dir.Path);

        Assert.Equal(EvidenceListOutcome.Failed, result.Outcome);
        Assert.Equal("not a workbook", File.ReadAllText(path));
    }

    [Fact]
    public void Collections_without_a_summary_are_listed_and_placeholder_serials_are_dropped()
    {
        using var dir = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(dir.Path, "HOST03", "Registry"));
        WriteSummary(dir, "web01", ("Hostname", "web01"), ("SerialNumber", "To Be Filled By O.E.M."));
        Directory.CreateDirectory(Path.Combine(dir.Path, "_Logs"));

        var rows = ReadRows(EvidenceList.Rebuild(dir.Path).Path);

        Assert.Equal(2, rows.Count);
        Assert.Equal("No system summary", rows.Single(r => r["Collection"] == "HOST03")["Status"]);
        Assert.Equal("", rows.Single(r => r["Collection"] == "web01")["Serial number (detected)"]);
    }

    [Fact]
    public void An_empty_case_makes_no_list()
    {
        using var dir = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(dir.Path, "_Logs"));

        Assert.Equal(EvidenceListOutcome.NothingToList, EvidenceList.Rebuild(dir.Path).Outcome);
        Assert.False(File.Exists(EvidenceList.PathFor(dir.Path)));
    }

    [Fact]
    public void The_collection_file_comes_from_the_run_manifest()
    {
        using var dir = new TempDirectory();
        WriteSummary(dir, "HOST01", ("Hostname", "HOST01"));
        Directory.CreateDirectory(Path.Combine(dir.Path, "_Logs"));
        File.WriteAllText(Path.Combine(dir.Path, "_Logs", "manifest.json"),
            """{ "Collections": [ { "CollectionName": "HOST01", "Root": "X:\\x", "Archive": "D:\\in\\HOST01.zip" } ] }""");

        var row = ReadRows(EvidenceList.Rebuild(dir.Path).Path).Single();

        Assert.Equal(@"D:\in\HOST01.zip", row["Collection file"]);
    }
}
