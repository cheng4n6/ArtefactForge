using ArtefactForge.Core;
using Xunit;

namespace ArtefactForge.Tests;

public class ReleaseCheckTests
{
    [Fact]
    public void The_release_page_found_by_a_check_is_the_one_opened()
    {
        var page = ReleaseCheck.ReleasePage(
            "Yamato-Security/hayabusa", "https://github.com/Yamato-Security/hayabusa/releases/tag/v4.1.0");

        Assert.Equal("https://github.com/Yamato-Security/hayabusa/releases/tag/v4.1.0", page.AbsoluteUri);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Before_a_check_the_release_page_is_the_latest_release_of_the_repository(string? checkedUrl)
    {
        var page = ReleaseCheck.ReleasePage("WithSecureLabs/chainsaw", checkedUrl);

        Assert.Equal("https://github.com/WithSecureLabs/chainsaw/releases/latest", page.AbsoluteUri);
    }

    [Theory]
    [InlineData("http://github.com/WithSecureLabs/chainsaw/releases/tag/v2.16.5")]
    [InlineData("https://example.com/chainsaw.exe")]
    [InlineData("file:///C:/Windows/System32/calc.exe")]
    [InlineData("C:\\Windows\\System32\\calc.exe")]
    [InlineData("not a url")]
    public void A_link_that_is_not_an_https_GitHub_page_is_not_handed_to_the_shell(string checkedUrl)
    {
        var page = ReleaseCheck.ReleasePage("WithSecureLabs/chainsaw", checkedUrl);

        Assert.Equal("https://github.com/WithSecureLabs/chainsaw/releases/latest", page.AbsoluteUri);
    }
}
