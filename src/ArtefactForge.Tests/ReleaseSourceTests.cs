using ArtefactForge.Core.Update;
using Xunit;

namespace ArtefactForge.Tests;

public class ReleaseSourceTests
{
    private const string Base = "https://github.com/cheng4n6/ArtefactForge/releases/download/";

    private static string Release(string tag, bool prerelease = false, bool draft = false, bool manifest = true) =>
        $$"""
        {"tag_name":"{{tag}}","prerelease":{{(prerelease ? "true" : "false")}},"draft":{{(draft ? "true" : "false")}},"assets":[
          {"name":"artefactforge-{{tag.TrimStart('v')}}-no-tools.zip","browser_download_url":"{{Base}}{{tag}}/artefactforge-{{tag.TrimStart('v')}}-no-tools.zip"}
          {{(manifest ? $",{{\"name\":\"artefactforge-latest.json\",\"browser_download_url\":\"{Base}{tag}/artefactforge-latest.json\"}},{{\"name\":\"artefactforge-latest.json.sig\",\"browser_download_url\":\"{Base}{tag}/artefactforge-latest.json.sig\"}}" : "")}}
        ]}
        """;

    private static string List(params string[] releases) => "[" + string.Join(",", releases) + "]";

    [Fact]
    public void A_beta_pre_release_is_offered()
    {
        var release = GitHubReleaseSource.SelectRelease(List(Release("v0.1.0", prerelease: true)));

        Assert.NotNull(release);
        Assert.Equal("v0.1.0", release!.Tag);
        Assert.True(release.PreRelease);
        Assert.Equal(Base + "v0.1.0/artefactforge-latest.json", release.Assets[ReleaseFiles.Manifest].AbsoluteUri);
    }

    [Fact]
    public void The_highest_version_wins_whatever_order_GitHub_lists_them_in()
    {
        var release = GitHubReleaseSource.SelectRelease(List(
            Release("v0.2.1", prerelease: true), Release("v0.10.0", prerelease: true), Release("v0.9.0")));

        Assert.Equal("v0.10.0", release!.Tag);
    }

    [Fact]
    public void Drafts_and_releases_without_a_manifest_are_ignored()
    {
        var release = GitHubReleaseSource.SelectRelease(List(
            Release("v0.3.0", draft: true), Release("v0.2.0", manifest: false), Release("v0.1.0", prerelease: true)));

        Assert.Equal("v0.1.0", release!.Tag);
    }

    [Fact]
    public void No_published_release_gives_nothing_to_offer()
    {
        Assert.Null(GitHubReleaseSource.SelectRelease("[]"));
        Assert.Null(GitHubReleaseSource.SelectRelease(List(Release("v0.1.0", manifest: false))));
    }

    [Fact]
    public void An_asset_link_that_is_not_https_is_not_used()
    {
        var json = List("""{"tag_name":"v0.1.0","assets":[{"name":"artefactforge-latest.json","browser_download_url":"http://example.com/x.json"}]}""");

        Assert.Null(GitHubReleaseSource.SelectRelease(json));
    }

    [Fact]
    public void The_source_names_this_repository()
    {
        var source = new GitHubReleaseSource();

        Assert.Equal("cheng4n6/ArtefactForge", source.Repository);
        Assert.Equal("GitHub (cheng4n6/ArtefactForge)", source.Description);
    }

    [Theory]
    [InlineData("ArtefactForge")]
    [InlineData("cheng4n6/")]
    [InlineData("a/b/c")]
    public void A_repository_must_be_owner_and_name(string repository) =>
        Assert.Throws<ArgumentException>(() => new GitHubReleaseSource(repository));
}
