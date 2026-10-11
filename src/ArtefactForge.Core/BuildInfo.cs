using System.Reflection;
using System.Security.Cryptography;

namespace ArtefactForge.Core;

/// <summary>
/// Identifies the build that is running. Recorded in every manifest: the EZ tool versions and
/// hashes answer "what parsed this", and this answers "what drove it" - a question that gets asked
/// about a case long after the tool has moved on several versions.
/// </summary>
public static class BuildInfo
{
    /// <summary>Assembly version, e.g. 1.0.0.</summary>
    public static string Version { get; } =
        typeof(BuildInfo).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>Version plus the source commit where available, e.g. 1.0.0+e93446b.</summary>
    public static string InformationalVersion { get; } =
        typeof(BuildInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? Version;

    /// <summary>The executable actually running - the GUI or the CLI.</summary>
    public static string? Executable { get; } = Environment.ProcessPath;

    private static readonly Lazy<string?> LazyHash = new(() =>
    {
        try
        {
            if (Executable is null || !File.Exists(Executable)) return null;
            using var stream = File.OpenRead(Executable);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch { return null; }
    });

    public static string? Sha256 => LazyHash.Value;

    /// <summary>One-line identity for a log header or a window title.</summary>
    public static string Describe() => $"ArtefactForge {InformationalVersion}";
}
