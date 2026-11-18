using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArtefactForge.Lake.Contract;

/// <summary>
/// Writes a time as UTC to the second ("2026-11-18T10:15:02Z") and reads any ISO 8601 time back
/// as UTC. Sub-second digits say nothing about when a file was produced and make diffs noisy; a
/// time without an offset is taken as UTC rather than as the reading machine's local time.
/// </summary>
public sealed class UtcSecondsConverter : JsonConverter<DateTime>
{
    private const string Pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var text = reader.GetString();
        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value))
            throw new JsonException($"'{text}' is not an ISO 8601 time.");
        return value.UtcDateTime;
    }

    public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
    {
        var utc = value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : value;
        writer.WriteStringValue(utc.ToString(Pattern, CultureInfo.InvariantCulture));
    }
}
