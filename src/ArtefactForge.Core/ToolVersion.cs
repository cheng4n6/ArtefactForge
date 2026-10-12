using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core;

/// <summary>
/// What version an executable says it is. The version resource is read first. Chainsaw has none,
/// so for a tool <see cref="ToolUpdater.Packages"/> knows how to ask, the tool is run with its
/// version switch and the number read from what it prints.
/// </summary>
public static partial class ToolVersion
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    public static string? Read(string path)
    {
        var version = FromResource(path);
        if (version is not null) return version;

        var spec = ToolUpdater.Packages.FirstOrDefault(p =>
            p.VersionArguments is not null &&
            string.Equals(p.Executable, Path.GetFileName(path), StringComparison.OrdinalIgnoreCase));
        return spec is null ? null : FromOutput(path, spec.VersionArguments!);
    }

    private static string? FromResource(string path)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            return string.IsNullOrWhiteSpace(info.FileVersion) ? null : info.FileVersion;
        }
        catch { return null; }
    }

    /// <summary>Runs the executable with <paramref name="arguments"/> and reads a version from its output.</summary>
    public static string? FromOutput(string path, string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(path, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(path) ?? ""
            });
            if (process is null) return null;

            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(Timeout))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* it is being abandoned anyway */ }
                return null;
            }
            return Parse(output.Result);
        }
        catch { return null; }
    }

    /// <summary>The first version number in a tool's output, e.g. "chainsaw 2.16.5" gives "2.16.5".</summary>
    public static string? Parse(string output)
    {
        var match = VersionNumber().Match(output);
        return match.Success ? match.Groups[1].Value : null;
    }

    [GeneratedRegex(@"\bv?(\d+\.\d+(?:\.\d+){0,2})\b")]
    private static partial Regex VersionNumber();
}
