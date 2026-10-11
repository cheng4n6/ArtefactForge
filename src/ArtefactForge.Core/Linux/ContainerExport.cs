using System.Globalization;
using System.Text.Json;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxContainers module: Docker containers, what they ran and with what privileges, their
/// logs, and the images present.
///
///   LinuxContainers_Containers.csv  one row per container, from config.v2.json and hostconfig.json
///   LinuxContainers_Logs.csv        stdout and stderr, from the json-file log driver, UTC
///   LinuxContainers_Images.csv      tags and image IDs, from repositories.json and the image database
///
/// Environment variables are listed by NAME only. Container environments routinely hold database
/// passwords and cloud keys, and copying them into a case folder creates a second place for them
/// to leak from - the same reasoning that keeps shadow hashes out of LinuxUsers. The values are
/// still in config.v2.json in the evidence when they are needed.
///
/// Only Docker's default layout is read. Podman, containerd and the 'local' log driver are not.
/// </summary>
public static class ContainerExport
{
    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var docker = Path.Combine(root, "var", "lib", "docker");
        var containersDir = new DirectoryInfo(Path.Combine(docker, "containers"));
        var imageDir = new DirectoryInfo(Path.Combine(docker, "image"));

        if (!containersDir.Exists && !imageDir.Exists)
        {
            log.WriteLine($"No containers or image folder under {docker}");
            return 0;
        }

        Directory.CreateDirectory(outputDirectory);
        using var containers = new CsvFile(Path.Combine(outputDirectory, "LinuxContainers_Containers.csv"),
            "ContainerId", "Name", "Image", "ImageId", "CreatedUtc", "StartedUtc", "FinishedUtc", "Running",
            "ExitCode", "Pid", "User", "Command", "Privileged", "NetworkMode", "PidMode", "CapAdd",
            "Mounts", "Ports", "RestartPolicy", "EnvNames", "SourceFile");
        using var logs = new CsvFile(Path.Combine(outputDirectory, "LinuxContainers_Logs.csv"),
            "TimestampUtc", "ContainerId", "ContainerName", "Stream", "Message", "SourceFile");
        using var images = new CsvFile(Path.Combine(outputDirectory, "LinuxContainers_Images.csv"),
            "Repository", "Tag", "ImageId", "CreatedUtc", "Driver", "SourceFile");

        if (containersDir.Exists)
        {
            foreach (var dir in containersDir.EnumerateDirectories().OrderBy(d => d.Name, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var name = ReadContainer(root, dir, containers, errors);
                ReadLogs(root, dir, name, logs, errors, cancellationToken);
            }
        }

        if (imageDir.Exists) ReadImages(root, imageDir, images, errors);

        foreach (var csv in new[] { containers, logs, images })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-32} {csv.Rows} row(s)");
        if (containers.Rows + logs.Rows + images.Rows == 0) log.WriteLine("Docker folders present but empty");
        return 0;
    }

    private static string ReadContainer(string root, DirectoryInfo dir, CsvFile csv, TextWriter errors)
    {
        var configPath = Path.Combine(dir.FullName, "config.v2.json");
        if (!File.Exists(configPath))
        {
            errors.WriteLine($"{Relative(root, dir.FullName)}: no config.v2.json - container not described, logs still read");
            return "";
        }

        try
        {
            using var config = JsonDocument.Parse(File.ReadAllBytes(configPath));
            var c = config.RootElement;
            JsonDocument? hostDoc = null;
            var hostPath = Path.Combine(dir.FullName, "hostconfig.json");
            if (File.Exists(hostPath)) hostDoc = JsonDocument.Parse(File.ReadAllBytes(hostPath));
            using var _ = hostDoc;
            var h = hostDoc?.RootElement;

            var name = Str(c, "Name").TrimStart('/');
            var cfg = Get(c, "Config");
            var state = Get(c, "State");

            var command = string.Join(" ", Strings(cfg, "Entrypoint").Concat(Strings(cfg, "Cmd")));
            if (command.Length == 0) command = string.Join(" ", new[] { Str(c, "Path") }.Concat(Strings(c, "Args"))).Trim();

            var mounts = new List<string>();
            if (Get(c, "MountPoints") is { ValueKind: JsonValueKind.Object } mp)
                foreach (var m in mp.EnumerateObject())
                {
                    var source = Str(m.Value, "Source");
                    if (source.Length == 0) source = Str(m.Value, "Name");
                    mounts.Add($"{source}:{m.Name}{(Get(m.Value, "RW") is { ValueKind: JsonValueKind.False } ? ":ro" : "")}");
                }
            if (mounts.Count == 0) mounts.AddRange(Strings(h, "Binds"));

            var ports = new List<string>();
            if (h is not null && Get(h, "PortBindings") is { ValueKind: JsonValueKind.Object } pb)
                foreach (var p in pb.EnumerateObject())
                    foreach (var binding in p.Value.ValueKind == JsonValueKind.Array ? p.Value.EnumerateArray() : Enumerable.Empty<JsonElement>())
                        ports.Add($"{Str(binding, "HostIp")}:{Str(binding, "HostPort")}->{p.Name}".TrimStart(':'));

            var envNames = Strings(cfg, "Env").Select(e => e.Split('=', 2)[0]);

            csv.Write(
                Short(Str(c, "ID").Length > 0 ? Str(c, "ID") : dir.Name),
                name,
                Str(cfg, "Image"),
                Short(Str(c, "Image").Replace("sha256:", "")),
                Time(Str(c, "Created")),
                Time(Str(state, "StartedAt")),
                Time(Str(state, "FinishedAt")),
                Raw(state, "Running"),
                Raw(state, "ExitCode"),
                Raw(state, "Pid") == "0" ? "" : Raw(state, "Pid"),
                Str(cfg, "User"),
                command,
                Raw(h, "Privileged"),
                Str(h, "NetworkMode"),
                Str(h, "PidMode"),
                string.Join(";", Strings(h, "CapAdd")),
                string.Join(";", mounts),
                string.Join(";", ports),
                Str(Get(h, "RestartPolicy"), "Name"),
                string.Join(";", envNames),
                Relative(root, configPath));
            return name;
        }
        catch (JsonException ex)
        {
            errors.WriteLine($"{Relative(root, configPath)}: not valid JSON - {ex.Message}");
            return "";
        }
    }

    private static void ReadLogs(string root, DirectoryInfo dir, string name, CsvFile csv, TextWriter errors, CancellationToken cancellationToken)
    {
        // <id>-json.log, rotated to <id>-json.log.1 ... and optionally gzipped.
        var files = RotatedLogs.Order(dir.EnumerateFiles("*-json.log*")).ToList();
        var id = Short(dir.Name);

        foreach (var file in files)
        {
            var relative = Relative(root, file.FullName);
            var bad = 0;
            try
            {
                foreach (var line in RotatedLogs.ReadLines(file))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (line.Length == 0) continue;
                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var e = doc.RootElement;
                        csv.Write(Time(Str(e, "time")), id, name, Str(e, "stream"), Str(e, "log").TrimEnd('\n', '\r'), relative);
                    }
                    catch (JsonException) { bad++; }
                }
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException)
            {
                errors.WriteLine($"{relative}: incomplete - {ex.Message}");
            }
            if (bad > 0) errors.WriteLine($"{relative}: {bad} line(s) were not valid JSON and were skipped");
        }
    }

    private static void ReadImages(string root, DirectoryInfo imageDir, CsvFile csv, TextWriter errors)
    {
        // image/<driver>/repositories.json maps repo -> { "repo:tag": "sha256:id" }.
        foreach (var driver in imageDir.EnumerateDirectories())
        {
            var repositories = Path.Combine(driver.FullName, "repositories.json");
            if (!File.Exists(repositories)) continue;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllBytes(repositories));
                if (Get(doc.RootElement, "Repositories") is not { ValueKind: JsonValueKind.Object } repos) continue;

                foreach (var repo in repos.EnumerateObject())
                foreach (var tag in repo.Value.EnumerateObject())
                {
                    var id = tag.Value.GetString() ?? "";
                    // "nginx:latest" becomes "latest"; a digest reference keeps its '@' so it reads as one.
                    var reference = tag.Name.StartsWith(repo.Name) ? tag.Name[repo.Name.Length..].TrimStart(':') : tag.Name;
                    csv.Write(repo.Name, reference, Short(id.Replace("sha256:", "")),
                        ImageCreated(driver.FullName, id), driver.Name, Relative(root, repositories));
                }
            }
            catch (JsonException ex)
            {
                errors.WriteLine($"{Relative(root, repositories)}: not valid JSON - {ex.Message}");
            }
        }
    }

    private static string ImageCreated(string driverDir, string id)
    {
        var hex = id.Replace("sha256:", "");
        var path = Path.Combine(driverDir, "imagedb", "content", "sha256", hex);
        if (hex.Length == 0 || !File.Exists(path)) return "";
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            return Time(Str(doc.RootElement, "created"));
        }
        catch (JsonException) { return ""; }
    }

    private static string Relative(string root, string path) => Path.GetRelativePath(root, path).Replace('\\', '/');

    private static string Short(string id) => id.Length > 12 ? id[..12] : id;

    /// <summary>Docker writes RFC 3339 with nanoseconds; the zero time means "never".</summary>
    private static string Time(string value)
    {
        if (value.Length == 0 || value.StartsWith("0001-01-01")) return "";
        // .NET parses at most seven fractional digits; Docker writes nine.
        var trimmed = System.Text.RegularExpressions.Regex.Replace(value, @"(\.\d{7})\d+", "$1");
        return DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)
            ? t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.ffffff")
            : value;
    }

    private static JsonElement? Get(JsonElement? e, string name) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(name, out var v) ? v : null;

    private static string Str(JsonElement? e, string name) =>
        Get(e, name) is { ValueKind: JsonValueKind.String } v ? v.GetString() ?? "" : "";

    private static string Raw(JsonElement? e, string name) =>
        Get(e, name) is { } v && v.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)
            ? v.ValueKind switch { JsonValueKind.True => "true", JsonValueKind.False => "false", _ => v.GetRawText() }
            : "";

    private static IEnumerable<string> Strings(JsonElement? e, string name) =>
        Get(e, name) is { ValueKind: JsonValueKind.Array } a
            ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").ToList()
            : [];
}
