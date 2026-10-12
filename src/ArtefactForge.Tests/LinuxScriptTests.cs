using System.Diagnostics;
using System.IO.Compression;
using System.Text;

namespace ArtefactForge.Tests;

/// <summary>
/// The PowerShell parsers in Scripts\linux, run the way their modules run them: Windows PowerShell
/// 5.1 through powershell.exe, against a made-up root. The scripts have no other test harness, and
/// a 5.1 incompatibility only shows when a module runs.
/// </summary>
public class LinuxScriptTests
{
    private static readonly string ScriptsDir = FindScriptsDir();

    private static string FindScriptsDir()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "Scripts", "linux");
            if (Directory.Exists(candidate)) return candidate;
        }
        throw new DirectoryNotFoundException("Scripts\\linux not found above " + AppContext.BaseDirectory);
    }

    private static string PowerShell =>
        Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

    private static (int Exit, string Stdout, string Stderr) Run(string arguments)
    {
        var info = new ProcessStartInfo(PowerShell, "-NoProfile -ExecutionPolicy Bypass " + arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var process = Process.Start(info)!;
        var stderr = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout, stderr.Result);
    }

    private static (int Exit, string Stdout, string Stderr, string Out) RunScript(TempDirectory dir, string script)
    {
        var output = Path.Combine(dir.Path, "out");
        var result = Run($"-File \"{Path.Combine(ScriptsDir, script)}\" -Root \"{Path.Combine(dir.Path, "root")}\" -Out \"{output}\"");
        return (result.Exit, result.Stdout, result.Stderr, output);
    }

    private static List<Dictionary<string, string>> Csv(string path)
    {
        var lines = File.ReadAllLines(path);
        var header = Fields(lines[0].TrimStart('﻿'));
        return lines.Skip(1)
            .Select(l => header.Zip(Fields(l)).ToDictionary(p => p.First, p => p.Second))
            .ToList();
    }

    // Export-Csv quotes every value except a null, which it writes as nothing at all (,,).
    private static List<string> Fields(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted && c == '"' && i + 1 < line.Length && line[i + 1] == '"') { current.Append('"'); i++; }
            else if (c == '"') quoted = !quoted;
            else if (c == ',' && !quoted) { fields.Add(current.ToString()); current.Clear(); }
            else current.Append(c);
        }
        fields.Add(current.ToString());
        return fields;
    }

    private static string AuthLog(TempDirectory dir, string name, string text, DateTime lastWrite)
    {
        var path = dir.File(Path.Combine("root", "var", "log", name));
        File.WriteAllText(path, text.Replace("\r\n", "\n"));
        File.SetLastWriteTime(path, lastWrite);
        return path;
    }

    [Fact]
    public void Every_script_parses_under_windows_powershell_and_is_ascii()
    {
        // Every script in Scripts\, not only the Linux ones: all of them run under powershell.exe.
        foreach (var script in Directory.GetFiles(Path.GetDirectoryName(ScriptsDir)!, "*.ps1",
                                                  SearchOption.AllDirectories))
        {
            var bytes = File.ReadAllBytes(script);
            Assert.True(bytes.All(b => b < 0x80), $"{Path.GetFileName(script)} is not ASCII");

            var check = Run("-Command \"$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('"
                            + script + "', [ref]$null, [ref]$e); $e | ForEach-Object { $_.Message }\"");
            Assert.True(check.Stdout.Trim().Length == 0 && check.Exit == 0,
                $"{Path.GetFileName(script)} does not parse under 5.1: {check.Stdout}{check.Stderr}");
        }
    }

    [Fact]
    public void Rfc3339_auth_lines_keep_their_year_and_fill_the_utc_time()
    {
        using var dir = new TempDirectory();
        AuthLog(dir, "auth.log",
            "2026-10-29T10:23:45.123456+01:00 host01 sshd[812]: Accepted publickey for alice from 192.0.2.10 port 50122 ssh2\n",
            new DateTime(2027, 3, 1));

        var (exit, _, stderr, output) = RunScript(dir, "Parse-LinuxAuth.ps1");

        Assert.Equal(0, exit);
        Assert.Equal("", stderr);
        var row = Assert.Single(Csv(Path.Combine(output, "LinuxAuth_Events.csv")));
        Assert.Equal("2026-10-29 10:23:45.123456", row["Timestamp"]);
        Assert.Equal("2026-10-29 09:23:45.123456", row["TimestampUtc"]);
        Assert.Equal("no", row["YearInferred"]);
        Assert.Equal("LoginSuccess", row["Event"]);
        Assert.Equal("alice", row["User"]);
        Assert.Equal("192.0.2.10", row["SourceIP"]);
    }

    [Fact]
    public void Classic_lines_take_the_year_from_the_file_and_roll_back_across_new_year()
    {
        using var dir = new TempDirectory();
        // A RHEL dateext rotation written early in January still holds December's entries.
        AuthLog(dir, "secure-20270102",
            "Dec 31 23:59:01 host01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\n" +
            "Jan  1 00:00:05 host01 sshd[90]: Failed password for invalid user admin from 198.51.100.7 port 4242 ssh2\n",
            new DateTime(2027, 1, 2, 3, 0, 0));

        var (exit, _, stderr, output) = RunScript(dir, "Parse-LinuxAuth.ps1");

        Assert.Equal(0, exit);
        Assert.Equal("", stderr);
        var rows = Csv(Path.Combine(output, "LinuxAuth_Events.csv"));
        Assert.Equal(["2026-12-31 23:59:01", "2027-01-01 00:00:05"], rows.Select(r => r["Timestamp"]));
        Assert.All(rows, r => Assert.Equal("yes", r["YearInferred"]));
        Assert.All(rows, r => Assert.Equal("", r["TimestampUtc"]));
        Assert.Equal("/usr/bin/id", rows[0]["Command"]);
        Assert.Equal("LoginFailed", rows[1]["Event"]);
        Assert.Equal("admin", rows[1]["User"]);
    }

    [Fact]
    public void A_truncated_rotated_log_is_reported_and_its_readable_lines_kept()
    {
        using var dir = new TempDirectory();
        var text = string.Concat(Enumerable.Range(0, 400).Select(i =>
            $"Oct 10 10:{i / 60 % 60:00}:{i % 60:00} host01 sshd[{i}]: Accepted password for alice from 192.0.2.1 port {i} ssh2\n"));
        using var buffer = new MemoryStream();
        using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, leaveOpen: true))
            gzip.Write(Encoding.UTF8.GetBytes(text));
        var gz = dir.File(Path.Combine("root", "var", "log", "auth.log.2.gz"));
        File.WriteAllBytes(gz, buffer.ToArray()[..(int)(buffer.Length - 8)]);

        var (exit, _, stderr, output) = RunScript(dir, "Parse-LinuxAuth.ps1");

        Assert.Equal(0, exit);
        Assert.Contains("auth.log.2.gz", stderr);
        Assert.Contains("truncated", stderr);
        Assert.True(File.Exists(Path.Combine(output, "LinuxAuth_Events.csv")));
    }

    [Fact]
    public void Other_tools_history_is_read_per_user()
    {
        using var dir = new TempDirectory();
        void Put(string name, string text) => File.WriteAllText(dir.File(Path.Combine("home", "alice", name)), text);
        Put(".viminfo",
            "# This viminfo file was generated by Vim 9.0.\n" +
            "# Command Line History (newest to oldest):\n" +
            ":wq\n" +
            "|2,0,1760176800,,\"wq\"\n" +
            "# Search String History (newest to oldest):\n" +
            "?/password\n" +
            "# History of marks within files (newest to oldest):\n" +
            "\n" +
            "> /etc/shadow\n" +
            "\t\"\t12\t0\n");
        Put(".lesshst", ".less-history-file:\n.search\n\"api_key\n.shell\n\"id\n");
        Put(".mysql_history", "_HiStOrY_V2_\nselect\\040*\\040from\\040users;\n");
        Put(".wget-hsts", "# HSTS 1.0 Known Hosts database for GNU Wget.\nexample.org\t0\t1\t1760176800\t31536000\n");
        Put(".sudo_as_admin_successful", "");
        Put(Path.Combine(".local", "share", "recently-used.xbel"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xbel version=\"1.0\"><bookmark href=\"file:///home/alice/Documents/Q3%20plan.odt\" added=\"2026-10-11T09:00:00Z\" modified=\"2026-10-11T09:00:00Z\" visited=\"2026-10-11T09:30:00Z\"/></xbel>\n");

        var output = Path.Combine(dir.Path, "out");
        var (exit, _, stderr) = Run($"-File \"{Path.Combine(ScriptsDir, "Parse-LinuxUserFiles.ps1")}\" -HomeDir \"{Path.Combine(dir.Path, "home", "alice")}\" -User alice -Out \"{output}\"");

        Assert.Equal(0, exit);
        Assert.Equal("", stderr);
        var rows = Csv(Path.Combine(output, "alice_LinuxUserFiles_OtherHistory.csv"));
        Assert.Contains(rows, r => r["Type"] == "vim command" && r["Entry"] == "wq" && r["TimeUtc"] == "2025-10-11 10:00:00");
        Assert.Contains(rows, r => r["Type"] == "vim search" && r["Entry"] == "password");
        Assert.Contains(rows, r => r["Type"] == "vim file edited" && r["Entry"] == "/etc/shadow");
        Assert.Contains(rows, r => r["Type"] == "less search" && r["Entry"] == "api_key");
        Assert.Contains(rows, r => r["Type"] == "less shell command" && r["Entry"] == "id");
        Assert.Contains(rows, r => r["Type"] == "mysql command" && r["Entry"] == "select * from users;");
        Assert.Contains(rows, r => r["Type"] == "wget HTTPS host" && r["Entry"] == "example.org" && r["TimeUtc"] == "2025-10-11 10:00:00");
        Assert.Contains(rows, r => r["Type"] == "recent file (desktop)" && r["Entry"] == "file:///home/alice/Documents/Q3 plan.odt"
                                   && r["TimeUtc"] == "2026-10-11 09:30:00");
        Assert.Contains(rows, r => r["Source"] == ".sudo_as_admin_successful");
    }

    /// <summary>The list the extractor writes for links it does not create (CollectionExtractor.SymlinkList).</summary>
    private static void Symlinks(TempDirectory dir, params (string Path, string Target)[] links) =>
        File.WriteAllLines(dir.File(Path.Combine("root", "_symlinks.csv")),
            links.Select(l => $"{l.Path},{l.Target},[root]/{l.Path}").Prepend("Path,Target,ArchiveEntry"));

    [Fact]
    public void Systemd_enablement_links_listed_by_the_extractor_are_recorded()
    {
        using var dir = new TempDirectory();
        dir.Dir(Path.Combine("root", "etc", "systemd", "system", "multi-user.target.wants"));
        Symlinks(dir,
            ("etc/systemd/system/multi-user.target.wants/ssh.service", "/lib/systemd/system/ssh.service"),
            ("etc/localtime", "/usr/share/zoneinfo/Europe/London"));

        var (exit, _, stderr, output) = RunScript(dir, "Parse-LinuxSystemd.ps1");

        Assert.Equal(0, exit);
        Assert.Equal("", stderr);
        var row = Assert.Single(Csv(Path.Combine(output, "LinuxSystemd_Enabled.csv")));
        Assert.Equal("ssh.service", row["Unit"]);
        Assert.Equal("multi-user.target", row["WantedBy"]);
        Assert.Equal("/lib/systemd/system/ssh.service", row["LinkTarget"]);
    }

    [Fact]
    public void System_info_follows_listed_links_and_reports_ones_whose_target_was_not_collected()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(Path.Combine("root", "usr", "lib", "os-release")), "PRETTY_NAME=\"Ubuntu 22.04\"\n");
        dir.File(Path.Combine("root", "etc", "passwd"));
        Symlinks(dir,
            ("etc/os-release", "../usr/lib/os-release"),
            ("etc/localtime", "/usr/share/zoneinfo/Europe/London"),
            ("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf"));

        var (exit, _, _, output) = RunScript(dir, "Parse-LinuxSystemInfo.ps1");

        Assert.Equal(0, exit);
        var facts = Csv(Path.Combine(output, "SystemInfo.csv"));
        Assert.Contains(facts, f => f["Item"] == "PRETTY_NAME" && f["Value"] == "Ubuntu 22.04" && f["Source"] == "etc/os-release");
        Assert.Contains(facts, f => f["Item"] == "Timezone" && f["Value"] == "Europe/London");
        Assert.Contains(facts, f => f["Item"] == "UnreadableSymlink" && f["Value"].StartsWith("etc/resolv.conf -> "));
    }

    [Fact]
    public void System_info_takes_live_addresses_and_the_system_serial_from_uac_live_response()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(Path.Combine("root", "etc", "hostname")), "web01\n");
        File.WriteAllText(dir.File(Path.Combine("root", "_UAC", "live_response", "network", "ip_addr_show.txt")),
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n" +
            "    inet 127.0.0.1/8 scope host lo\n" +
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n" +
            "    inet 10.1.2.3/24 brd 10.1.2.255 scope global dynamic eth0\n" +
            "    inet6 fe80::1/64 scope link\n");
        File.WriteAllText(dir.File(Path.Combine("root", "_UAC", "live_response", "hardware", "dmidecode.txt")),
            "Handle 0x0001, DMI type 1, 27 bytes\n" +
            "System Information\n" +
            "\tManufacturer: Example Corp\n" +
            "\tProduct Name: Model 7\n" +
            "\tSerial Number: SN-12345\n" +
            "\n" +
            "Handle 0x0002, DMI type 2, 15 bytes\n" +
            "Base Board Information\n" +
            "\tSerial Number: BOARD-999\n");

        var (exit, _, stderr, output) = RunScript(dir, "Parse-LinuxSystemInfo.ps1");

        Assert.Equal(0, exit);
        Assert.Equal("", stderr);
        var facts = Csv(Path.Combine(output, "SystemInfo.csv"));
        Assert.Contains(facts, f => f["Item"] == "LiveIPAddresses" && f["Value"] == "10.1.2.3");
        Assert.Contains(facts, f => f["Item"] == "SerialNumber" && f["Value"] == "SN-12345");
        Assert.Contains(facts, f => f["Item"] == "Model" && f["Value"] == "Model 7");
    }
}
