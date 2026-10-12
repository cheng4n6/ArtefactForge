using ArtefactForge.Core.Ioc;

namespace ArtefactForge.Tests;

/// <summary>
/// IOCs.csv is the analyst's own data. These pin down that ArtefactForge only ever adds to it or
/// takes from it what it was asked to, keeps what was edited by hand, and never saves over a
/// file it could not read.
/// </summary>
public class IocListTests
{
    [Fact]
    public void A_case_without_a_list_loads_as_empty_and_no_file_is_created()
    {
        using var dir = new TempDirectory();

        Assert.Empty(IocList.Load(dir.Path));
        Assert.False(File.Exists(IocList.PathFor(dir.Path)));
    }

    [Fact]
    public void Adding_writes_the_list_with_its_four_columns()
    {
        using var dir = new TempDirectory();

        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe", "dropper, from email", "DC01")]);

        Assert.Single(added);
        var rows = CsvReader.Read(IocList.PathFor(dir.Path));
        Assert.Equal("File name", rows[0]["Type"]);
        Assert.Equal("ABC.exe", rows[0]["Value"]);
        Assert.Equal("dropper, from email", rows[0]["Note"]);
        Assert.Equal("DC01", rows[0]["Found on"]);
    }

    [Fact]
    public void Adding_an_IOC_already_listed_changes_nothing()
    {
        using var dir = new TempDirectory();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        var before = File.ReadAllText(IocList.PathFor(dir.Path));

        var added = IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, " abc.EXE ")]);

        Assert.Empty(added);
        Assert.Equal(before, File.ReadAllText(IocList.PathFor(dir.Path)));
    }

    [Fact]
    public void Adding_keeps_rows_and_columns_edited_by_hand_since_the_list_was_read()
    {
        using var dir = new TempDirectory();
        var path = IocList.PathFor(dir.Path);
        // As if edited in Excel: an extra column, a type ArtefactForge does not know, odd casing.
        File.WriteAllText(path,
            "Type,Value,Note,Found on,Analyst\r\n"
            + "sha1,0123456789abcdef0123456789abcdef01234567,from VT,WS02,alice\r\n"
            + "Mutex,Global\\evil,not a type AF sweeps,,bob\r\n");

        IocList.Add(dir.Path, [IocEntry.Create(IocType.IP, "10.0.0.5")]);

        var rows = CsvReader.Read(path);
        Assert.Equal(3, rows.Count);
        Assert.Equal("sha1", rows[0]["Type"]);
        Assert.Equal("alice", rows[0]["Analyst"]);
        Assert.Equal("Mutex", rows[1]["Type"]);
        Assert.Equal("Global\\evil", rows[1]["Value"]);
        Assert.Equal("bob", rows[1]["Analyst"]);
        Assert.Equal("10.0.0.5", rows[2]["Value"]);
        Assert.Equal("", rows[2]["Analyst"]);
    }

    [Fact]
    public void Rows_with_a_type_that_is_not_understood_are_kept_but_not_swept()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(IocList.PathFor(dir.Path), "Type,Value\r\nMutex,Global\\evil\r\n");

        var entry = Assert.Single(IocList.Load(dir.Path));

        Assert.Null(entry.Type);
        Assert.False(entry.IsSweepable);
    }

    [Fact]
    public void A_list_without_a_Value_column_is_never_saved_over()
    {
        using var dir = new TempDirectory();
        var path = IocList.PathFor(dir.Path);
        const string content = "Indicator;Comment\r\nABC.exe;semicolons, not commas\r\n";
        File.WriteAllText(path, content);

        Assert.Throws<InvalidDataException>(() => IocList.Add(dir.Path, [IocEntry.Create(IocType.IP, "10.0.0.5")]));
        Assert.Throws<InvalidDataException>(() => IocList.Remove(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]));
        Assert.Equal(content, File.ReadAllText(path));
    }

    [Fact]
    public void A_list_held_open_by_another_program_is_left_whole_and_the_save_reports_it()
    {
        using var dir = new TempDirectory();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        var path = IocList.PathFor(dir.Path);
        var before = File.ReadAllText(path);

        // Excel holds an open workbook's file like this: others may read it but not replace it.
        using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
        {
            var error = Assert.Throws<IOException>(() => IocList.Add(dir.Path, [IocEntry.Create(IocType.IP, "10.0.0.5")]));
            Assert.Contains("not changed", error.Message);
        }

        Assert.Equal(before, File.ReadAllText(path));
        Assert.Empty(Directory.GetFiles(dir.Path, "*.tmp"));
    }

    [Fact]
    public void Removing_takes_off_only_the_IOCs_named()
    {
        using var dir = new TempDirectory();
        IocList.Add(dir.Path,
        [
            IocEntry.Create(IocType.FileName, "ABC.exe"),
            IocEntry.Create(IocType.IP, "10.0.0.5"),
            IocEntry.Create(IocType.Account, "svc_backup")
        ]);

        var removed = IocList.Remove(dir.Path, [IocEntry.Create(IocType.IP, "10.0.0.5")]);

        Assert.Single(removed);
        Assert.Equal(["ABC.exe", "svc_backup"], IocList.Load(dir.Path).Select(e => e.Value));
    }

    [Fact]
    public void Removing_the_last_IOC_keeps_the_file_with_its_header()
    {
        using var dir = new TempDirectory();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);

        IocList.Remove(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);

        Assert.True(File.Exists(IocList.PathFor(dir.Path)));
        Assert.StartsWith("Type,Value,Note,Found on", File.ReadAllText(IocList.PathFor(dir.Path)).TrimStart('\uFEFF'));
    }

    [Fact]
    public void Importing_another_cases_list_adds_only_what_is_new()
    {
        using var dir = new TempDirectory();
        IocList.Add(dir.Path, [IocEntry.Create(IocType.FileName, "ABC.exe")]);
        var source = dir.File(Path.Combine("other", "IOCs.csv"));
        File.WriteAllText(source,
            "Type,Value,Note,Found on\r\nFile name,abc.exe,,\r\nDomain,evil.example,c2,WS02\r\nMutex,x,,\r\n");

        var result = IocList.Import(dir.Path, source);

        Assert.Equal("evil.example", Assert.Single(result.Added).Value);
        Assert.Equal(1, result.AlreadyListed);
        Assert.Single(result.Rejected);
        Assert.Equal(2, IocList.Load(dir.Path).Count);
    }

    [Fact]
    public void Importing_a_plain_list_works_out_each_type()
    {
        using var dir = new TempDirectory();
        var source = dir.File("list.txt");
        File.WriteAllLines(source,
        [
            "# from the incident ticket",
            "ABC.exe",
            "C:\\Users\\Public\\run.ps1",
            "d41d8cd98f00b204e9800998ecf8427e",
            "203.0.113.7",
            "evil.example",
            "CORP\\svc_backup",
            ""
        ]);

        var added = IocList.Import(dir.Path, source).Added;

        Assert.Equal(
            [IocType.FileName, IocType.Path, IocType.Hash, IocType.IP, IocType.Domain, IocType.Account],
            added.Select(e => e.Type!.Value));
    }

    [Theory]
    [InlineData("ABC.exe", IocType.FileName)]
    [InlineData("payload.dll", IocType.FileName)]
    [InlineData("C:\\Windows\\Temp\\x.bat", IocType.Path)]
    [InlineData("\\\\server\\share\\x.exe", IocType.Path)]
    [InlineData("/tmp/.x/kworker", IocType.Path)]
    [InlineData("0123456789abcdef0123456789abcdef01234567", IocType.Hash)]
    [InlineData("10.1.2.3", IocType.IP)]
    [InlineData("2001:db8::1", IocType.IP)]
    [InlineData("evil.com", IocType.Domain)]
    [InlineData("cdn.evil-site.example", IocType.Domain)]
    [InlineData("CORP\\alice", IocType.Account)]
    [InlineData("alice@corp.example", IocType.Account)]
    [InlineData("svc_backup", IocType.Account)]
    public void The_type_is_worked_out_from_the_value(string value, IocType expected) =>
        Assert.Equal(expected, IocList.Infer(value));
}
