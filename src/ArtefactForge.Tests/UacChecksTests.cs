using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>UAC's hash_executables lists and chkrootkit output, with made-up paths and hashes.</summary>
public class UacChecksTests
{
    private static void Put(TempDirectory dir, string relative, string text) =>
        File.WriteAllText(dir.File(Path.Combine(["root", "_UAC", .. relative.Split('/')])), text);

    private delegate int Export(string root, string output, TextWriter log, TextWriter errors, CancellationToken token);

    private static (string Out, string Errors) Run(TempDirectory dir, Export export)
    {
        var output = Path.Combine(dir.Path, "out");
        using var log = new StringWriter();
        using var errors = new StringWriter();
        Assert.Equal(0, export(Path.Combine(dir.Path, "root"), output, log, errors, CancellationToken.None));
        return (output, errors.ToString());
    }

    [Fact]
    public void Hash_lists_are_merged_per_file_and_odd_locations_marked()
    {
        using var dir = new TempDirectory();
        Put(dir, "hash_executables/hash_executables.md5",
            "0123456789abcdef0123456789abcdef  /usr/bin/ls\nfedcba9876543210fedcba9876543210  /dev/shm/.x/miner\n");
        Put(dir, "hash_executables/hash_executables.sha1",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709  /usr/bin/ls\n");

        var (output, errors) = Run(dir, UacChecksExport.Hashes);

        Assert.Equal("", errors);
        var rows = CsvReader.Read(Path.Combine(output, "LinuxExecutableHashes.csv"));
        Assert.Equal(["/dev/shm/.x/miner", "/usr/bin/ls"], rows.Select(r => r["Path"]));
        Assert.Equal(("0123456789abcdef0123456789abcdef", "da39a3ee5e6b4b0d3255bfef95601890afd80709"), (rows[1]["MD5"], rows[1]["SHA1"]));
        Assert.Contains("temporary", rows[0]["Review"]);
        Assert.Equal("", rows[1]["Review"]);
    }

    [Fact]
    public void A_hash_line_in_another_format_is_reported()
    {
        using var dir = new TempDirectory();
        Put(dir, "hash_executables/hash_executables.md5", "0123456789abcdef0123456789abcdef  /usr/bin/ls\nmd5sum: /usr/bin/x: Permission denied\n");

        var (_, errors) = Run(dir, UacChecksExport.Hashes);

        Assert.Contains("1 line(s) not in a hash-and-path format", errors);
    }

    [Fact]
    public void Chkrootkit_checks_become_rows_and_findings_are_marked()
    {
        using var dir = new TempDirectory();
        Put(dir, "chkrootkit/chkrootkit_-n_-r.txt",
            "ROOTDIR is `/'\n" +
            "Checking `amd'...                                           not found\n" +
            "Checking `sshd'...                                          not infected\n" +
            "Searching for suspicious files and dirs, it may take a while... The following suspicious files and directories were found:\n" +
            "/tmp/.ICE-unix/.x /usr/lib/.hidden\n" +
            "Searching for Linux.Xor.DDoS ... INFECTED: Possible Malicious Linux.Xor.DDoS installed\n" +
            "/tmp/abc123\n" +
            "Checking `sniffer'...                                       WARNING\n" +
            "WARNING: Output from ifpromisc:\n" +
            "eth0: PACKET SNIFFER(/usr/sbin/tcpdump[812])\n");

        var (output, _) = Run(dir, UacChecksExport.Chkrootkit);

        var rows = CsvReader.Read(Path.Combine(output, "LinuxChkrootkit.csv"));
        Assert.Equal(["amd", "sshd", "Searching for suspicious files and dirs, it may take a while",
                      "Searching for Linux.Xor.DDoS", "sniffer"], rows.Select(r => r["Check"]));
        Assert.Equal(["", "", "yes", "yes", "yes"], rows.Select(r => r["Review"]));
        Assert.Equal("/tmp/abc123", rows[3]["Detail"]);
        Assert.Equal("WARNING: Output from ifpromisc: | eth0: PACKET SNIFFER(/usr/sbin/tcpdump[812])", rows[4]["Detail"]);
    }
}
