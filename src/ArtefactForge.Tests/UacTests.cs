using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// UAC (Unix-like Artifacts Collector) collections, converted on extraction into a Linux
/// filesystem root. The archives are synthetic but follow UAC's layout: uac.log first, the
/// collected files under [root]/, and the collector's own output beside them.
/// </summary>
public class UacTests
{
    private static LayoutProfile[] Layouts() =>
    [
        new()
        {
            Name = "Linux filesystem root",
            Id = "linux-root",
            Priority = 30,
            Platform = Platform.Linux,
            Detect = new LayoutDetectRules
            {
                RootIsSelection = true,
                Markers = ["etc/passwd", "etc/os-release", "var/log"],
                MatchMode = MarkerMatchMode.Any
            },
            Resolve = new LayoutResolveRules { RootOffset = "." }
        }
    ];

    private const string Log =
        "2026-10-11 10:00:00 +0000 INF Unix-like Artifacts Collector v3.0.0\n"
        + "2026-10-11 10:00:00 +0000 INF Hostname: HOST01\n";

    /// <summary>A tar entry: a file with content, or a link when Link is set.</summary>
    private sealed record Entry(string Name, string? Content = null, string? Link = null,
                                TarEntryType Type = TarEntryType.RegularFile);

    private static Entry[] Basics(string log = Log) =>
    [
        new("uac.log", log),
        new("[root]/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"),
        new("[root]/var/log/auth.log", "Oct 11 10:00:00 host01 sshd[1]: Accepted password for alice\n"),
        new("live_response/process/ps.txt", "PID CMD\n")
    ];

    private static byte[] TarBytes(IEnumerable<Entry> entries)
    {
        using var buffer = new MemoryStream();
        using (var writer = new TarWriter(buffer, TarEntryFormat.Gnu, leaveOpen: true))
        {
            foreach (var e in entries)
            {
                var entry = new GnuTarEntry(e.Type, e.Name) { ModificationTime = new DateTimeOffset(2026, 10, 11, 9, 0, 0, TimeSpan.Zero) };
                if (e.Link is not null) entry.LinkName = e.Link;
                if (e.Content is not null) entry.DataStream = new MemoryStream(Encoding.UTF8.GetBytes(e.Content));
                writer.WriteEntry(entry);
            }
        }
        return buffer.ToArray();
    }

    private static byte[] Gzip(byte[] data)
    {
        using var buffer = new MemoryStream();
        using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(data);
        return buffer.ToArray();
    }

    private static string TarGz(TempDirectory dir, string name, params Entry[] entries)
    {
        var path = Path.Combine(dir.Path, name);
        File.WriteAllBytes(path, Gzip(TarBytes(entries)));
        return path;
    }

    private static async Task<(ExtractionRecord Record, string Root)> Extract(TempDirectory dir, string source)
    {
        var root = Path.Combine(dir.Path, "out", "HOST01");
        var record = await CollectionExtractor.ExtractAsync(source, root, Path.Combine(dir.Path, "extract.csv"), null, CancellationToken.None);
        Assert.Null(record.Error);
        return (record, root);
    }

    [Theory]
    [InlineData("[root]/etc/passwd", "etc/passwd")]
    [InlineData("[root]/", null)]
    [InlineData("uac.log", "_UAC/uac.log")]
    [InlineData("live_response/network/ss.txt", "_UAC/live_response/network/ss.txt")]
    public void Root_becomes_the_filesystem_root_and_the_rest_goes_under_UAC(string entry, string? expected) =>
        Assert.Equal(expected, UacCollection.MapEntry(entry));

    [Fact]
    public void A_uac_tar_gz_is_recognised_and_named_after_the_host_in_its_log()
    {
        using var dir = new TempDirectory();
        var tar = TarGz(dir, "uac-host01-linux-20261011100000.tar.gz", Basics());

        var (targets, reason) = EvidenceDiscovery.InspectArchive(tar, Layouts());

        var target = Assert.Single(targets);
        Assert.Null(reason);
        Assert.Equal("HOST01", target.CollectionName);
        Assert.Equal("linux-root", target.Layout.Id);
        Assert.Equal(tar, target.ArchivePath);
    }

    [Fact]
    public void Without_a_hostname_in_the_log_the_archive_name_gives_the_host()
    {
        using var dir = new TempDirectory();
        var tar = TarGz(dir, "uac-web-01-linux-20261011100000.tar.gz", Basics(log: "nothing useful\n"));

        var (targets, _) = EvidenceDiscovery.InspectArchive(tar, Layouts());

        Assert.Equal("web-01", Assert.Single(targets).CollectionName);
    }

    [Fact]
    public void An_uncompressed_tar_is_read_the_same_way()
    {
        using var dir = new TempDirectory();
        var tar = Path.Combine(dir.Path, "uac-host01-linux-20261011100000.tar");
        File.WriteAllBytes(tar, TarBytes(Basics()));

        var (targets, _) = EvidenceDiscovery.InspectArchive(tar, Layouts());

        Assert.Equal("HOST01", Assert.Single(targets).CollectionName);
    }

    [Fact]
    public async Task Collected_files_land_at_the_root_and_the_collectors_output_under_UAC()
    {
        using var dir = new TempDirectory();
        var (record, root) = await Extract(dir, TarGz(dir, "uac.tar.gz", Basics()));

        Assert.Empty(record.Problems);
        Assert.Equal("root:x:0:0:root:/root:/bin/bash\n", File.ReadAllText(Path.Combine(root, "etc", "passwd")));
        Assert.True(File.Exists(Path.Combine(root, UacCollection.MetadataFolder, "uac.log")));
        Assert.True(File.Exists(Path.Combine(root, UacCollection.MetadataFolder, "live_response", "process", "ps.txt")));
        Assert.False(Directory.Exists(Path.Combine(root, "[root]")));
        Assert.Equal(new DateTime(2026, 10, 11, 9, 0, 0, DateTimeKind.Utc),
                     File.GetLastWriteTimeUtc(Path.Combine(root, "etc", "passwd")));

        var found = Assert.Single(LayoutDetector.Detect(root, Layouts()));
        Assert.Equal("linux-root", found.Layout.Id);
    }

    [Fact]
    public async Task Symbolic_links_are_listed_with_their_targets_rather_than_created()
    {
        using var dir = new TempDirectory();
        var tar = TarGz(dir, "uac.tar.gz",
        [
            .. Basics(),
            new("[root]/etc/localtime", Link: "/usr/share/zoneinfo/Europe/London", Type: TarEntryType.SymbolicLink),
            new("[root]/etc/systemd/system/multi-user.target.wants/ssh.service",
                Link: "/lib/systemd/system/ssh.service", Type: TarEntryType.SymbolicLink)
        ]);

        var (record, root) = await Extract(dir, tar);

        Assert.Empty(record.Problems);
        Assert.False(File.Exists(Path.Combine(root, "etc", "localtime")));
        // The folder the link lived in still exists, so the systemd module finds it.
        Assert.True(Directory.Exists(Path.Combine(root, "etc", "systemd", "system", "multi-user.target.wants")));
        Assert.Equal(
        [
            "Path,Target,ArchiveEntry",
            "etc/localtime,/usr/share/zoneinfo/Europe/London,[root]/etc/localtime",
            "etc/systemd/system/multi-user.target.wants/ssh.service,/lib/systemd/system/ssh.service,"
            + "[root]/etc/systemd/system/multi-user.target.wants/ssh.service"
        ], File.ReadAllLines(Path.Combine(root, CollectionExtractor.SymlinkList)));
        Assert.Contains(record.Notes, n => n.Contains(CollectionExtractor.SymlinkList));
    }

    [Fact]
    public async Task A_hard_link_gets_the_content_of_the_entry_it_repeats()
    {
        using var dir = new TempDirectory();
        var tar = TarGz(dir, "uac.tar.gz",
        [
            .. Basics(),
            new("[root]/usr/bin/vi", "binary"),
            new("[root]/usr/bin/view", Link: "[root]/usr/bin/vi", Type: TarEntryType.HardLink)
        ]);

        var (record, root) = await Extract(dir, tar);

        Assert.Empty(record.Problems);
        Assert.Equal("binary", File.ReadAllText(Path.Combine(root, "usr", "bin", "view")));
    }

    [Fact]
    public async Task Devices_and_pipes_are_left_out_with_a_note()
    {
        using var dir = new TempDirectory();
        var (record, _) = await Extract(dir, TarGz(dir, "uac.tar.gz",
            [.. Basics(), new("[root]/dev/null", Type: TarEntryType.CharacterDevice)]));

        Assert.Empty(record.Problems);
        Assert.Contains(record.Notes, n => n.Contains("devices, pipes and sockets"));
    }

    [Fact]
    public async Task Many_small_entries_in_a_tar_gz_are_all_read()
    {
        // TarReader skips unread entries with one read, and GZipStream can return short reads; the
        // reader then lost its place after a few small files and misread the next header.
        using var dir = new TempDirectory();
        var small = Enumerable.Range(0, 200).Select(i => new Entry($"[root]/etc/conf.d/f{i}", i.ToString())).ToArray();

        var (record, root) = await Extract(dir, TarGz(dir, "uac.tar.gz", [.. Basics(), .. small]));

        Assert.True(record.Problems.Count == 0, string.Join("; ", record.Problems));
        Assert.Equal(200, Directory.GetFiles(Path.Combine(root, "etc", "conf.d")).Length);
        Assert.Equal("199", File.ReadAllText(Path.Combine(root, "etc", "conf.d", "f199")));
    }

    [Fact]
    public async Task A_truncated_archive_is_reported_and_what_came_before_is_kept()
    {
        using var dir = new TempDirectory();
        var large = string.Concat(Enumerable.Range(0, 20_000).Select(i => $"line {i} {Guid.NewGuid()}\n"));
        var whole = Gzip(TarBytes([.. Basics(), new("[root]/var/log/syslog", large)]));
        var tar = Path.Combine(dir.Path, "uac.tar.gz");
        File.WriteAllBytes(tar, whole[..(whole.Length / 2)]);

        var (record, root) = await Extract(dir, tar);

        Assert.Contains(record.Problems, p => p.Contains("truncated"));
        Assert.True(File.Exists(Path.Combine(root, "etc", "passwd")));
        Assert.False(File.Exists(Path.Combine(root, "var", "log", "syslog")));
    }

    [Fact]
    public async Task A_gzip_cut_inside_its_trailer_is_still_caught()
    {
        // .NET decompresses such a file in full and says nothing; only the trailer shows the loss.
        using var dir = new TempDirectory();
        var whole = Gzip(TarBytes(Basics()));
        var tar = Path.Combine(dir.Path, "uac.tar.gz");
        File.WriteAllBytes(tar, whole[..^4]);

        var (record, _) = await Extract(dir, tar);

        Assert.Contains(record.Problems, p => p.Contains("truncated"));
    }

    [Fact]
    public async Task A_uac_zip_lists_its_unix_symlinks_instead_of_writing_them_as_files()
    {
        using var dir = new TempDirectory();
        var zipPath = Path.Combine(dir.Path, "uac-host01-linux-20261011100000.zip");
        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            foreach (var e in Basics())
            {
                using var writer = new StreamWriter(zip.CreateEntry(e.Name).Open());
                writer.Write(e.Content);
            }
            var link = zip.CreateEntry("[root]/etc/localtime");
            link.ExternalAttributes = 0xA1FF << 16;   // S_IFLNK | 0777, as zip(1) records a link on Unix
            using (var writer = new StreamWriter(link.Open())) writer.Write("/usr/share/zoneinfo/UTC");
        }

        var (targets, _) = EvidenceDiscovery.InspectArchive(zipPath, Layouts());
        var (_, root) = await Extract(dir, zipPath);

        Assert.Equal("HOST01", Assert.Single(targets).CollectionName);
        Assert.False(File.Exists(Path.Combine(root, "etc", "localtime")));
        Assert.Contains("etc/localtime,/usr/share/zoneinfo/UTC,[root]/etc/localtime",
                        File.ReadAllLines(Path.Combine(root, CollectionExtractor.SymlinkList)));
    }

    [Fact]
    public async Task An_unpacked_uac_folder_is_converted_and_left_unchanged()
    {
        using var dir = new TempDirectory();
        var source = dir.Dir("uac-host01-linux-20261011100000");
        foreach (var e in Basics())
            File.WriteAllText(dir.File(Path.Combine(source, e.Name.Replace('/', Path.DirectorySeparatorChar))), e.Content);
        var before = Directory.GetFiles(source, "*", SearchOption.AllDirectories).Order().ToList();

        var discovery = EvidenceDiscovery.Discover(source, batch: false, Layouts());
        var (record, root) = await Extract(dir, source);

        Assert.Equal("HOST01", Assert.Single(discovery.Targets).CollectionName);
        Assert.Empty(record.Problems);
        Assert.True(File.Exists(Path.Combine(root, "etc", "passwd")));
        Assert.Equal(before, Directory.GetFiles(source, "*", SearchOption.AllDirectories).Order());
    }

    [Fact]
    public void A_batch_picks_up_tar_archives_and_passes_over_their_unpacked_copies()
    {
        using var dir = new TempDirectory();
        var tar = TarGz(dir, "uac-host01-linux-20261011100000.tar.gz", Basics());
        File.WriteAllText(dir.File(Path.Combine("uac-host01-linux-20261011100000", "[root]", "etc", "passwd")), "root:x:0:0::/root:/bin/sh\n");
        dir.File(Path.Combine("uac-host01-linux-20261011100000", "uac.log"));

        var result = EvidenceDiscovery.Discover(dir.Path, batch: true, Layouts());

        Assert.Equal(tar, Assert.Single(result.Targets).ArchivePath);
        Assert.Contains(result.Unmatched, u => u.Reason.Contains("extracted copy"));
    }

    [Theory]
    [InlineData("uac-a-linux-20261011100000.tar.gz", "uac-a-linux-20261011100000")]
    [InlineData("collection.tgz", "collection")]
    [InlineData("collection.tar", "collection")]
    [InlineData("HOST01.zip", "HOST01")]
    public void An_archive_loses_its_whole_extension(string file, string stem) =>
        Assert.Equal(stem, CollectionExtractor.ArchiveStem(Path.Combine(Path.GetTempPath(), file)));

    [Fact]
    public async Task Linux_names_windows_cannot_hold_are_renamed_and_logged()
    {
        using var dir = new TempDirectory();
        var tar = TarGz(dir, "uac.tar.gz",
        [
            .. Basics(),
            new("[root]/usr/src/aux.c", "a"),
            new("[root]/var/log/nul", "b"),
            new("[root]/etc/odd.", "c"),
            // systemd escapes '-' in unit names; on Unix the '\' is part of the name, not a folder.
            new("[root]/etc/systemd/system/mnt-data\\x2dbackup.mount", "d")
        ]);

        var (record, root) = await Extract(dir, tar);

        Assert.True(record.Problems.Count == 0, string.Join("; ", record.Problems));
        Assert.Equal("a", File.ReadAllText(Path.Combine(root, "usr", "src", "_aux.c")));
        Assert.Equal("b", File.ReadAllText(Path.Combine(root, "var", "log", "_nul")));
        Assert.Equal("c", File.ReadAllText(Path.Combine(root, "etc", "odd_")));
        Assert.Equal("d", File.ReadAllText(Path.Combine(root, "etc", "systemd", "system", "mnt-data_x2dbackup.mount")));
        Assert.Equal(4, File.ReadAllLines(Path.Combine(dir.Path, "extract.csv")).Count(l => l.Contains("renamed")));
    }
}
