using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace ArtefactForge.Core.Update;

/// <summary>
/// Where releases are read from: GitHub Releases, or a plain folder for workstations with no
/// internet. Every source serves the same three files, and the updater checks them the same way
/// whichever one they came from.
/// </summary>
public interface IReleaseSource
{
    /// <summary>Shown to the analyst: "GitHub (owner/repo)", or the folder path.</summary>
    string Description { get; }

    Task<byte[]> ReadManifestAsync(CancellationToken cancellationToken);
    Task<byte[]> ReadSignatureAsync(CancellationToken cancellationToken);

    /// <summary>Copies the named package to <paramref name="destination"/>, reporting bytes copied.</summary>
    Task DownloadPackageAsync(string fileName, string destination, IProgress<long>? progress, CancellationToken cancellationToken);
}

public static class ReleaseFiles
{
    public const string Manifest = "artefactforge-latest.json";
    public const string Signature = "artefactforge-latest.json.sig";

    /// <summary>The repository whose releases the application checks.</summary>
    public const string GitHubRepository = "cheng4n6/ArtefactForge";
}

/// <summary>
/// The newest release on GitHub, pre-releases included: the 0.x line is published as GitHub
/// pre-releases (beta), and <c>releases/latest</c> never returns one. So the release list is read
/// from the API once per check, the highest version carrying the manifest is chosen, and the
/// manifest, signature and package all come from that one release, so a release published
/// mid-update cannot mix files from two. Drafts are never visible without a token.
/// </summary>
public sealed class GitHubReleaseSource : IReleaseSource
{
    private readonly Uri _api;
    private Task<GitHubRelease>? _release;

    public GitHubReleaseSource(string repository = ReleaseFiles.GitHubRepository)
    {
        if (repository.Split('/') is not [{ Length: > 0 }, { Length: > 0 }])
            throw new ArgumentException($"Expected owner/repository, not '{repository}'.", nameof(repository));

        Repository = repository;
        _api = new Uri($"https://api.github.com/repos/{repository}/releases?per_page=30");
    }

    public string Repository { get; }

    public string Description => $"GitHub ({Repository})";

    public async Task<byte[]> ReadManifestAsync(CancellationToken cancellationToken)
    {
        // A new check always reads the list again; the signature and package then reuse it.
        _release = FindReleaseAsync(cancellationToken);
        return await GetAssetAsync(ReleaseFiles.Manifest, cancellationToken);
    }

    public Task<byte[]> ReadSignatureAsync(CancellationToken cancellationToken) =>
        GetAssetAsync(ReleaseFiles.Signature, cancellationToken);

    public async Task DownloadPackageAsync(string fileName, string destination, IProgress<long>? progress, CancellationToken cancellationToken)
    {
        var url = await AssetUrlAsync(fileName, cancellationToken);
        using var client = Client(TimeSpan.FromMinutes(10));
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var output = File.Create(destination);
        await Copy(input, output, progress, cancellationToken);
    }

    /// <summary>
    /// Picks the release to offer from the API's release list: the highest version among those
    /// that carry <see cref="ReleaseFiles.Manifest"/>, whether or not it is marked pre-release.
    /// Returns null when none does. Public for tests.
    /// </summary>
    public static GitHubRelease? SelectRelease(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array) return null;

        GitHubRelease? best = null;
        foreach (var release in document.RootElement.EnumerateArray())
        {
            if (release.TryGetProperty("draft", out var draft) && draft.ValueKind == JsonValueKind.True) continue;
            if (!release.TryGetProperty("tag_name", out var tagElement) || tagElement.GetString() is not { } tag) continue;

            var assets = new Dictionary<string, Uri>(StringComparer.Ordinal);
            if (release.TryGetProperty("assets", out var list) && list.ValueKind == JsonValueKind.Array)
                foreach (var asset in list.EnumerateArray())
                    if (asset.TryGetProperty("name", out var name) && name.GetString() is { } n &&
                        asset.TryGetProperty("browser_download_url", out var url) &&
                        Uri.TryCreate(url.GetString(), UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps)
                        assets[n] = uri;

            if (!assets.ContainsKey(ReleaseFiles.Manifest)) continue;

            var candidate = new GitHubRelease(tag, release.TryGetProperty("prerelease", out var pre) && pre.ValueKind == JsonValueKind.True, assets);
            // The list is newest first, so on equal or unreadable versions the first one stands.
            if (best is null || ReleaseCheck.IsNewer(candidate.Tag.TrimStart('v', 'V'), best.Tag.TrimStart('v', 'V')) == true)
                best = candidate;
        }
        return best;
    }

    private async Task<GitHubRelease> FindReleaseAsync(CancellationToken cancellationToken)
    {
        using var client = Client(TimeSpan.FromSeconds(30));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        // No caching anywhere between here and GitHub: a stale list would hide a release.
        using var request = new HttpRequestMessage(HttpMethod.Get, _api);
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        using var response = await client.SendAsync(request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new UpdateException($"{Description} was not found, or is not public.");
        if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            throw new UpdateException($"GitHub refused the request (HTTP {(int)response.StatusCode}) - usually its hourly limit " +
                                      "for unauthenticated checks from this network. Try again later.");
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        try
        {
            return SelectRelease(json)
                   ?? throw new UpdateException($"No ArtefactForge release has been published on {Description} yet.");
        }
        catch (JsonException ex) { throw new UpdateException("GitHub's release list could not be read: " + ex.Message); }
    }

    private async Task<Uri> AssetUrlAsync(string name, CancellationToken cancellationToken)
    {
        var release = await (_release ??= FindReleaseAsync(cancellationToken));
        return release.Assets.TryGetValue(name, out var url)
            ? url
            : throw new UpdateException($"Release {release.Tag} on {Description} has no {name}.");
    }

    private async Task<byte[]> GetAssetAsync(string name, CancellationToken cancellationToken)
    {
        var url = await AssetUrlAsync(name, cancellationToken);
        using var client = Client(TimeSpan.FromSeconds(30));
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        using var response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    private static HttpClient Client(TimeSpan timeout)
    {
        // The default handler uses the system proxy, so a corporate network works unchanged. It
        // follows GitHub's redirect to its download host and refuses any redirect from HTTPS to HTTP.
        var client = new HttpClient { Timeout = timeout };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("ArtefactForge", BuildInfo.Version));
        return client;
    }

    internal static async Task Copy(Stream input, Stream output, IProgress<long>? progress, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
        {
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            total += read;
            progress?.Report(total);
        }
    }
}

/// <summary>One GitHub release: its tag, whether it is a pre-release, and its assets by name.</summary>
public sealed record GitHubRelease(string Tag, bool PreRelease, IReadOnlyDictionary<string, Uri> Assets);

/// <summary>The same three files in a folder - a share or a USB stick - for workstations kept offline.</summary>
public sealed class FolderReleaseSource(string folder) : IReleaseSource
{
    public string Description => folder;

    public Task<byte[]> ReadManifestAsync(CancellationToken cancellationToken) => Read(ReleaseFiles.Manifest, cancellationToken);
    public Task<byte[]> ReadSignatureAsync(CancellationToken cancellationToken) => Read(ReleaseFiles.Signature, cancellationToken);

    public async Task DownloadPackageAsync(string fileName, string destination, IProgress<long>? progress, CancellationToken cancellationToken)
    {
        await using var input = File.OpenRead(Path.Combine(folder, fileName));
        await using var output = File.Create(destination);
        await GitHubReleaseSource.Copy(input, output, progress, cancellationToken);
    }

    private Task<byte[]> Read(string name, CancellationToken cancellationToken)
    {
        var path = Path.Combine(folder, name);
        if (!File.Exists(path)) throw new UpdateException($"{name} was not found in {folder}.");
        return File.ReadAllBytesAsync(path, cancellationToken);
    }
}
