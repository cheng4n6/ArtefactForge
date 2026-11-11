using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core;

/// <summary>
/// When a collection was made, and what the collector recorded about the machine's clock at the
/// time: its time zone and when it last booted. Each value names where it came from, and an
/// estimate is marked as one, so the case report can say how far to trust it.
/// </summary>
public sealed record CollectorTimes
{
    public DateTime? CollectedUtc { get; init; }
    /// <summary>Where <see cref="CollectedUtc"/> came from, in words.</summary>
    public string CollectedFrom { get; init; } = "";
    /// <summary>True when <see cref="CollectedUtc"/> is an estimate rather than a recorded time.</summary>
    public bool CollectedApprox { get; init; }

    public DateTime? BootUtc { get; init; }
    public string BootFrom { get; init; } = "";

    /// <summary>The time zone the collector saw, such as "BST (UTC+01:00)". Empty when it recorded none.</summary>
    public string TimeZone { get; init; } = "";
    public string TimeZoneFrom { get; init; } = "";

    [JsonIgnore]
    public bool IsEmpty => CollectedUtc is null && BootUtc is null && TimeZone.Length == 0;
}

/// <summary>
/// Reads <see cref="CollectorTimes"/> from a collection's own files. It runs during the run, when
/// the collection is processed, because an extracted collection (and the collector's files with
/// it) can be deleted once its modules finish.
///
///   Velociraptor  _Velociraptor\client_info.json: ClientStart, BootTime, LocalTZ and its offset
///   UAC           _UAC\uac.log: the time of its first line, with the offset UAC wrote
///   KAPE          yyyy-MM-ddTHHmmss_ConsoleLog.txt beside the drive folder, named in UTC
///   Live system   the start of the run, this machine's uptime and time zone
///   Other zips    the time the zip file was last written, as an estimate
///
/// Nothing is guessed from file times inside a collection: they are the system's, not the
/// collector's, and an image's newest file says when the machine stopped, not when it was taken.
/// </summary>
public static partial class CollectorTimesReader
{
    public static CollectorTimes Read(string root, string? archive, bool isLive, DateTimeOffset runStarted)
    {
        try
        {
            if (isLive) return Live(runStarted);

            // A converted collection keeps the collector's files beside the drive folder
            // (Velociraptor) or inside the root (UAC); a KAPE --tout keeps its logs beside the drive.
            var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(root));
            string[] places = parent is null ? [root] : [root, parent];
            foreach (var place in places)
            {
                if (Velociraptor(Path.Combine(place, VelociraptorCollection.MetadataFolder, "client_info.json")) is { } v)
                    return v;
                if (Uac(Path.Combine(place, UacCollection.MetadataFolder, "uac.log")) is { } u) return u;
                if (Kape(place) is { } k) return k;
            }

            if (archive is not null && File.Exists(archive))
                return new CollectorTimes
                {
                    CollectedUtc = Trim(File.GetLastWriteTimeUtc(archive)),
                    CollectedFrom = $"when {Path.GetFileName(archive)} was last written; the collector recorded no time",
                    CollectedApprox = true
                };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The collection is still processed; the report shows its collection time as not recorded.
        }
        return new CollectorTimes();
    }

    private static CollectorTimes Live(DateTimeOffset runStarted)
    {
        var offset = TimeZoneInfo.Local.GetUtcOffset(runStarted);
        return new CollectorTimes
        {
            CollectedUtc = Trim(runStarted.UtcDateTime),
            CollectedFrom = "processed live: the start of the run",
            BootUtc = Trim(DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64)),
            BootFrom = "this machine's uptime when the run started",
            TimeZone = $"{TimeZoneInfo.Local.Id} ({Offset(offset)})",
            TimeZoneFrom = "this machine's time zone setting"
        };
    }

    /// <summary>client_info.json from a Velociraptor offline collector.</summary>
    internal static CollectorTimes? Velociraptor(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var info = doc.RootElement;
            DateTime? collected = null, boot = null;
            if (Text(info, "ClientStart") is { } start
                && DateTime.TryParse(start, CultureInfo.InvariantCulture,
                                     DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var c))
                collected = Trim(c);
            if (info.TryGetProperty("BootTime", out var bt) && bt.ValueKind == JsonValueKind.Number
                && bt.TryGetInt64(out var seconds) && seconds > 0)
                boot = DateTime.UnixEpoch.AddSeconds(seconds);

            var zone = "";
            if (Text(info, "LocalTZ") is { } tz)
            {
                zone = tz;
                if (info.TryGetProperty("LocalTZOffset", out var o) && o.ValueKind == JsonValueKind.Number
                    && o.TryGetInt32(out var offsetSeconds))
                    zone += $" ({Offset(TimeSpan.FromSeconds(offsetSeconds))})";
            }

            return new CollectorTimes
            {
                CollectedUtc = collected,
                CollectedFrom = collected is null ? "" : "Velociraptor client_info.json (ClientStart)",
                BootUtc = boot,
                BootFrom = boot is null ? "" : "Velociraptor client_info.json (BootTime)",
                TimeZone = zone,
                TimeZoneFrom = zone.Length == 0 ? "" : "Velociraptor client_info.json (LocalTZ)"
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>uac.log: every line starts "yyyy-MM-dd HH:mm:ss +hhmm", the first when UAC started.</summary>
    internal static CollectorTimes? Uac(string path)
    {
        if (!File.Exists(path)) return null;
        using var reader = new StreamReader(path);
        for (var i = 0; i < 20 && reader.ReadLine() is { } line; i++)
        {
            var m = UacLine().Match(line);
            if (!m.Success) continue;
            var local = DateTime.ParseExact(m.Groups[1].Value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            var sign = m.Groups[2].Value == "-" ? -1 : 1;
            var offset = sign * new TimeSpan(int.Parse(m.Groups[3].Value), int.Parse(m.Groups[4].Value), 0);
            return new CollectorTimes
            {
                CollectedUtc = DateTime.SpecifyKind(local - offset, DateTimeKind.Utc),
                CollectedFrom = "uac.log (its first line)"
            };
        }
        return null;
    }

    /// <summary>
    /// A KAPE --tdest folder holds yyyy-MM-ddTHHmmss_ConsoleLog.txt, named in UTC. More than one
    /// means KAPE ran into the folder more than once; the last run is the one that finished it.
    /// </summary>
    internal static CollectorTimes? Kape(string folder)
    {
        if (!Directory.Exists(folder)) return null;
        var runs = Directory.EnumerateFiles(folder, "*_ConsoleLog.txt")
            .Select(f => KapeLog().Match(Path.GetFileName(f)))
            .Where(m => m.Success)
            .Select(m => DateTime.ParseExact(m.Groups[1].Value, "yyyy-MM-dd'T'HHmmss", CultureInfo.InvariantCulture,
                                             DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal))
            .Order()
            .ToList();
        if (runs.Count == 0) return null;
        return new CollectorTimes
        {
            CollectedUtc = runs[^1],
            CollectedFrom = "KAPE console log name" + (runs.Count > 1 ? $" (the last of {runs.Count} KAPE runs into this folder)" : "")
        };
    }

    /// <summary>UTC+01:00, UTC-05:30, UTC+00:00.</summary>
    public static string Offset(TimeSpan offset) =>
        "UTC" + (offset < TimeSpan.Zero ? "-" : "+") + offset.Duration().ToString(@"hh\:mm", CultureInfo.InvariantCulture);

    private static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s.Trim() : null;

    /// <summary>To the second: every time in the summaries is written that way.</summary>
    private static DateTime Trim(DateTime t) =>
        DateTime.SpecifyKind(new DateTime(t.Ticks - t.Ticks % TimeSpan.TicksPerSecond), DateTimeKind.Utc);

    [GeneratedRegex(@"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([+-])(\d{2})(\d{2}) ")]
    private static partial Regex UacLine();

    [GeneratedRegex(@"^(\d{4}-\d{2}-\d{2}T\d{6})_ConsoleLog\.txt$", RegexOptions.IgnoreCase)]
    private static partial Regex KapeLog();
}
