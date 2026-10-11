using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>
/// A UAC bodyfile, as written by stat -c "0|%N|%i|%A|%u|%g|%s|%X|%Y|%Z|%W" with UAC's quote
/// stripping, turned into a mactime-style timeline. Paths and users are made up.
/// </summary>
public class BodyfileTests
{
    private static (string Out, string Errors) Run(TempDirectory dir, string bodyfile)
    {
        File.WriteAllText(dir.File(Path.Combine("root", "_UAC", "bodyfile", "bodyfile.txt")), bodyfile);
        File.WriteAllText(dir.File(Path.Combine("root", "etc", "passwd")), "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n");
        var output = Path.Combine(dir.Path, "out");
        using var log = new StringWriter();
        using var errors = new StringWriter();
        Assert.Equal(0, BodyfileExport.Run(Path.Combine(dir.Path, "root"), output, log, errors, CancellationToken.None));
        return (output, errors.ToString());
    }

    [Fact]
    public void Each_distinct_time_is_a_row_with_its_macb_flags_oldest_first()
    {
        using var dir = new TempDirectory();
        var (output, errors) = Run(dir,
            "0|/tmp/.x/kworkerd|131090|-rwxr-xr-x|1000|1000|812345|1760180000|1760176800|1760176800|1760176800\n" +
            "0|/etc/passwd|393|-rw-r--r--|0|0|1820|1760170000|1760100000|1760100000|0\n");

        Assert.Equal("", errors);
        var rows = CsvReader.Read(Path.Combine(output, "LinuxBodyfile_Timeline.csv"));
        Assert.Equal(
        [
            ("2025-10-10 12:40:00", "m.c.", "/etc/passwd"),
            ("2025-10-11 08:06:40", ".a..", "/etc/passwd"),
            ("2025-10-11 10:00:00", "m.cb", "/tmp/.x/kworkerd"),
            ("2025-10-11 10:53:20", ".a..", "/tmp/.x/kworkerd")
        ], rows.Select(r => (r["TimestampUtc"], r["MACB"], r["Path"])));
        Assert.Equal(("alice (1000)", "812345", "-rwxr-xr-x"), (rows[2]["User"], rows[2]["Size"], rows[2]["Mode"]));
    }

    [Fact]
    public void A_symlink_target_is_split_out_and_a_pipe_in_a_name_survives()
    {
        using var dir = new TempDirectory();
        var (output, _) = Run(dir,
            "0|/etc/localtime -> /usr/share/zoneinfo/Europe/London|1200|lrwxrwxrwx|0|0|33|1760100000|1760100000|1760100000|0\n" +
            "0|/home/alice/a|b.txt|5000|-rw-r--r--|1000|1000|1|1760100000|1760100000|1760100000|0\n");

        var rows = CsvReader.Read(Path.Combine(output, "LinuxBodyfile_Timeline.csv"));
        Assert.Equal(("/etc/localtime", "/usr/share/zoneinfo/Europe/London"), (rows[0]["Path"], rows[0]["LinkTarget"]));
        Assert.Equal("/home/alice/a|b.txt", rows[1]["Path"]);
    }

    [Fact]
    public void A_line_that_is_not_a_bodyfile_record_is_reported()
    {
        using var dir = new TempDirectory();
        var (_, errors) = Run(dir, "0|/etc/passwd|393|-rw-r--r--|0|0|1820|1760170000|1760100000|1760100000|0\nstat: cannot stat '/x': No such file\n");

        Assert.Contains("1 line(s) not in the bodyfile format", errors);
    }
}
