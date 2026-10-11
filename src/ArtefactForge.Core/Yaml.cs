using YamlDotNet.Serialization;

namespace ArtefactForge.Core;

internal static class Yaml
{
    /// <summary>
    /// Keys are matched exactly as written, matching KAPE's PascalCase mkape convention.
    /// Unknown keys are ignored so stock mkape files and future fields both load.
    /// </summary>
    internal static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.NullNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    /// <summary>Parse an enum from YAML, case-insensitively, with an error naming the valid values.</summary>
    internal static T ParseEnum<T>(string? value, T fallback, string field) where T : struct, Enum
    {
        if (string.IsNullOrWhiteSpace(value)) return fallback;
        if (Enum.TryParse<T>(value.Replace("-", "").Replace("_", ""), ignoreCase: true, out var parsed))
            return parsed;
        throw new FormatException(
            $"{field}: '{value}' is not valid. Expected one of: {string.Join(", ", Enum.GetNames<T>())}.");
    }
}
