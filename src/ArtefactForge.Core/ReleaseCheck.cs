using System.Net.Http.Headers;
using System.Text.Json;

namespace ArtefactForge.Core;

/// <summary>A downloadable file attached to a GitHub release, with the SHA-256 GitHub publishes for it.</summary>
public sealed record ReleaseAsset(string Name, string Url, long Size, string? Sha256);

public sealed record ReleaseInfo(string Package, string? LatestVersion, string? Url, string? Error)
{
    public bool Ok => LatestVersion is not null;

    /// <summary>The Windows x64 download for this tool, when the release has one.</summary>
    public ReleaseAsset? Asset { get; init; }
}

/// <summary>
/// Looks up the newest published release of the third-party tools. Deliberately manual: a forensic
/// workstation should not reach out to the internet on its own, and never mid-case.
/// </summary>
public static class ReleaseCheck
{
    /// <summary>Package name as it appears under Tools\, mapped to its GitHub repository.</summary>
    public static readonly IReadOnlyDictionary<string, string> KnownRepositories =
        ToolUpdater.Packages.ToDictionary(p => p.Name, p => p.Repository, StringComparer.OrdinalIgnoreCase);

    public static async Task<ReleaseInfo> LatestAsync(
        string package, string repository, CancellationToken cancellationToken = default)
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("ArtefactForge", "1.0"));
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

            var json = await client.GetStringAsync(
                $"https://api.github.com/repos/{repository}/releases/latest", cancellationToken);

            return Parse(package, json);
        }
        catch (Exception ex)
        {
            // No network on an isolated workstation is the normal case, not an error worth throwing.
            return new ReleaseInfo(package, null, null, ex.Message);
        }
    }

    /// <summary>Reads GitHub's "latest release" response, picking the package's Windows download.</summary>
    public static ReleaseInfo Parse(string package, string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
        var url = root.TryGetProperty("html_url", out var u) ? u.GetString() : null;

        if (tag is null) return new ReleaseInfo(package, null, url, "no tag in the response");

        var spec = ToolUpdater.Find(package);
        ReleaseAsset? asset = null;
        if (spec is not null && root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in assets.EnumerateArray())
            {
                var name = item.TryGetProperty("name", out var n) ? n.GetString() : null;
                var download = item.TryGetProperty("browser_download_url", out var d) ? d.GetString() : null;
                if (name is null || download is null || !spec.AssetPattern.IsMatch(name)) continue;

                var size = item.TryGetProperty("size", out var s) && s.TryGetInt64(out var bytes) ? bytes : 0;
                // GitHub states the digest as "sha256:<hex>"; releases from before it did so have none.
                var digest = item.TryGetProperty("digest", out var g) ? g.GetString() : null;
                var sha256 = digest is not null && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
                    ? digest["sha256:".Length..].ToUpperInvariant()
                    : null;

                asset = new ReleaseAsset(name, download, size, sha256);
                break;
            }
        }

        return new ReleaseInfo(package, tag.TrimStart('v', 'V'), url, null) { Asset = asset };
    }

    /// <summary>
    /// The page to open in the browser for a tool's release. The link a check returned is used
    /// only if it is an https GitHub page, because it is handed to the shell; otherwise, and before
    /// any check, the repository's latest-release page, so the link works without checking first.
    /// </summary>
    public static Uri ReleasePage(string repository, string? checkedUrl)
    {
        if (IsGitHubHttps(checkedUrl, out var uri)) return uri;
        return new Uri($"https://github.com/{repository}/releases/latest");
    }

    internal static bool IsGitHubHttps(string? url, out Uri uri)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out uri!)
            && uri.Scheme == Uri.UriSchemeHttps
            && string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase))
            return true;

        uri = null!;
        return false;
    }

    /// <summary>
    /// Compares two release strings numerically where possible. Returns null when they cannot be
    /// compared, so the caller can say "unknown" rather than assert something false.
    /// </summary>
    public static bool? IsNewer(string? latest, string? installed)
    {
        if (string.IsNullOrWhiteSpace(latest) || string.IsNullOrWhiteSpace(installed)) return null;
        if (string.Equals(latest, installed, StringComparison.OrdinalIgnoreCase)) return false;

        return TryParse(latest, out var l) && TryParse(installed, out var i) ? l > i : null;

        static bool TryParse(string value, out Version version)
        {
            var cleaned = new string(value.TakeWhile(c => char.IsDigit(c) || c == '.').ToArray()).Trim('.');
            return Version.TryParse(cleaned.Contains('.') ? cleaned : cleaned + ".0", out version!);
        }
    }
}
