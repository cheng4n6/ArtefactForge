using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ArtefactForge.Core;
using ArtefactForge.Core.Update;
using Xunit;

namespace ArtefactForge.Tests;

public class ToolUpdaterTests
{
    private const string Versions =
        "Tool versions in this folder\r\n" +
        "Recorded 2026-08-19\r\n" +
        "\r\n" +
        "hayabusa.exe   v4.0.0  (hayabusa-4.0.0-win-x64.exe)\r\n" +
        "               SHA256 AAAA\r\n" +
        "chainsaw.exe   v2.16.3 (chainsaw_x86_64-pc-windows-msvc.exe)\r\n" +
        "               SHA256 BBBB\r\n" +
        "eztools\\       Eric Zimmerman tools\r\n";

    [Fact]
    public void The_Windows_download_and_its_published_SHA256_are_read_from_the_release()
    {
        const string json = """
            {
              "tag_name": "v4.1.0",
              "html_url": "https://github.com/Yamato-Security/hayabusa/releases/tag/v4.1.0",
              "assets": [
                { "name": "hayabusa-4.1.0-win-x64-live-response.zip", "size": 7,
                  "browser_download_url": "https://github.com/Yamato-Security/hayabusa/releases/download/v4.1.0/live.zip",
                  "digest": "sha256:1111" },
                { "name": "hayabusa-4.1.0-win-x64.zip", "size": 44765237,
                  "browser_download_url": "https://github.com/Yamato-Security/hayabusa/releases/download/v4.1.0/hayabusa-4.1.0-win-x64.zip",
                  "digest": "sha256:4d304cc5baaa750ed08cc24b7b89c58ea058740c7e344502d7b82554637543a8" }
              ]
            }
            """;

        var release = ReleaseCheck.Parse("hayabusa", json);

        Assert.Equal("4.1.0", release.LatestVersion);
        Assert.Equal("hayabusa-4.1.0-win-x64.zip", release.Asset!.Name);
        Assert.Equal(44765237, release.Asset.Size);
        Assert.Equal("4D304CC5BAAA750ED08CC24B7B89C58EA058740C7E344502D7B82554637543A8", release.Asset.Sha256);
        Assert.Null(ToolUpdater.WhyNotInstallable(release, "4.0.0"));
    }

    [Fact]
    public void A_download_without_a_published_SHA256_is_not_offered()
    {
        var release = Release("chainsaw", "2.16.5", "chainsaw_x86_64-pc-windows-msvc.zip", 1, null);

        Assert.Contains("no SHA-256", ToolUpdater.WhyNotInstallable(release, "2.16.3"));
    }

    [Fact]
    public void A_release_that_is_not_newer_is_not_installed()
    {
        var release = Release("chainsaw", "2.16.5", "chainsaw_x86_64-pc-windows-msvc.zip", 1, "AA");

        Assert.Contains("already the latest", ToolUpdater.WhyNotInstallable(release, "2.16.5"));
    }

    [Fact]
    public void Hayabusa_is_renamed_to_the_name_modules_call_and_its_rules_are_replaced()
    {
        using var temp = new TempDirectory();
        var tools = temp.Dir("Tools");
        Write(tools, @"hayabusa\hayabusa.exe", "old exe");
        Write(tools, @"hayabusa\rules\old.yml", "old rule");
        Write(tools, @"hayabusa\config\old.txt", "old config");
        Write(tools, @"hayabusa\logs\keep.log", "analyst log");
        WriteVersions(tools);

        var zip = Zip(temp, "hayabusa-4.1.0-win-x64.zip",
            ("hayabusa-4.1.0-win-x64.exe", "new exe"),
            ("rules/new.yml", "new rule"),
            ("config/default_profile.yaml", "new config"));

        var outcome = new ToolUpdater(tools).Install(zip, ReleaseFor("hayabusa", "4.1.0", zip), "4.0.0");

        var folder = Path.Combine(tools, "hayabusa");
        Assert.Equal("new exe", File.ReadAllText(Path.Combine(folder, "hayabusa.exe")));
        Assert.False(File.Exists(Path.Combine(folder, "hayabusa-4.1.0-win-x64.exe")));
        Assert.True(File.Exists(Path.Combine(folder, "rules", "new.yml")));
        Assert.False(File.Exists(Path.Combine(folder, "rules", "old.yml")));
        Assert.False(File.Exists(Path.Combine(folder, "config", "old.txt")));
        Assert.Equal("analyst log", File.ReadAllText(Path.Combine(folder, "logs", "keep.log")));
        Assert.False(Directory.Exists(Path.Combine(tools, ToolUpdater.WorkFolder)));

        Assert.Equal("4.1.0", ToolInventory.DeclaredVersion(tools, "hayabusa"));
        Assert.Equal("2.16.3", ToolInventory.DeclaredVersion(tools, "chainsaw"));
        var versions = File.ReadAllText(Path.Combine(tools, ToolUpdater.VersionsFile));
        Assert.Contains("SHA256 " + outcome.ExecutableSha256, versions);
        Assert.Contains("(hayabusa-4.1.0-win-x64.exe)", versions);
        Assert.Contains("eztools\\", versions);
        Assert.DoesNotContain("AAAA", versions);
        Assert.Equal(SelfUpdater.Sha256(Path.Combine(folder, "hayabusa.exe")), outcome.ExecutableSha256);
    }

    [Fact]
    public void Chainsaw_is_unwrapped_from_its_folder_and_its_rules_and_mappings_are_kept()
    {
        using var temp = new TempDirectory();
        var tools = temp.Dir("Tools");
        Write(tools, @"chainsaw\chainsaw.exe", "old exe");
        Write(tools, @"chainsaw\mappings\sigma-event-logs-all.yml", "mapping");
        Write(tools, @"chainsaw\sigma\rules\a.yml", "sigma");
        Write(tools, @"chainsaw\rules\b.yml", "rule");
        WriteVersions(tools);

        var zip = Zip(temp, "chainsaw_x86_64-pc-windows-msvc.zip",
            ("chainsaw/chainsaw.exe", "new exe"),
            ("chainsaw/LICENCE", "licence"),
            ("chainsaw/README.md", "readme"));

        new ToolUpdater(tools).Install(zip, ReleaseFor("chainsaw", "2.16.5", zip), "2.16.3");

        var folder = Path.Combine(tools, "chainsaw");
        Assert.Equal("new exe", File.ReadAllText(Path.Combine(folder, "chainsaw.exe")));
        Assert.False(Directory.Exists(Path.Combine(folder, "chainsaw")));
        Assert.True(File.Exists(Path.Combine(folder, "mappings", "sigma-event-logs-all.yml")));
        Assert.True(File.Exists(Path.Combine(folder, "sigma", "rules", "a.yml")));
        Assert.True(File.Exists(Path.Combine(folder, "rules", "b.yml")));
        Assert.Equal("2.16.5", ToolInventory.DeclaredVersion(tools, "chainsaw"));
        Assert.Equal("4.0.0", ToolInventory.DeclaredVersion(tools, "hayabusa"));
    }

    [Fact]
    public void A_download_whose_SHA256_does_not_match_changes_nothing()
    {
        using var temp = new TempDirectory();
        var tools = temp.Dir("Tools");
        Write(tools, @"chainsaw\chainsaw.exe", "old exe");
        WriteVersions(tools);
        var zip = Zip(temp, "chainsaw_x86_64-pc-windows-msvc.zip", ("chainsaw/chainsaw.exe", "new exe"));
        var release = Release("chainsaw", "2.16.5", "chainsaw_x86_64-pc-windows-msvc.zip",
                              new FileInfo(zip).Length, new string('0', 64));

        var ex = Assert.Throws<UpdateException>(() => new ToolUpdater(tools).Install(zip, release, "2.16.3"));

        Assert.Contains("does not match", ex.Message);
        Assert.Equal("old exe", File.ReadAllText(Path.Combine(tools, "chainsaw", "chainsaw.exe")));
        Assert.Equal(Versions, File.ReadAllText(Path.Combine(tools, ToolUpdater.VersionsFile)));
        Assert.False(Directory.Exists(Path.Combine(tools, ToolUpdater.WorkFolder)));
    }

    [Fact]
    public void A_tool_in_use_is_left_as_it_was()
    {
        using var temp = new TempDirectory();
        var tools = temp.Dir("Tools");
        var exe = Write(tools, @"chainsaw\chainsaw.exe", "old exe");
        WriteVersions(tools);
        var zip = Zip(temp, "chainsaw_x86_64-pc-windows-msvc.zip", ("chainsaw/chainsaw.exe", "new exe"));

        UpdateException ex;
        using (File.Open(exe, FileMode.Open, FileAccess.Read, FileShare.Read))
            ex = Assert.Throws<UpdateException>(() =>
                new ToolUpdater(tools).Install(zip, ReleaseFor("chainsaw", "2.16.5", zip), "2.16.3"));

        Assert.Contains("Nothing was changed", ex.Message);
        Assert.Equal("old exe", File.ReadAllText(exe));
        Assert.Equal("2.16.3", ToolInventory.DeclaredVersion(tools, "chainsaw"));
    }

    [Fact]
    public void A_tool_missing_from_VERSIONS_txt_gets_an_entry_at_the_end()
    {
        var text = ToolUpdater.WithEntry("Tool versions\r\n", "chainsaw.exe", "2.16.5", "chainsaw.exe",
                                         "AB", "chainsaw.zip", "CD", new DateTime(2026, 1, 2));

        Assert.StartsWith("Tool versions\r\n\r\nchainsaw.exe   v2.16.5 (chainsaw.exe)\r\n", text);
        Assert.EndsWith("(SHA256 CD)\r\n", text);
    }

    [Fact]
    public void An_entry_is_replaced_in_a_file_with_mixed_line_endings()
    {
        // The shipped VERSIONS.txt mixes LF and CRLF; splitting on CRLF alone missed every entry,
        // so the new one was appended and the stale one above it was still the one read.
        var text = ToolUpdater.WithEntry(Versions.Replace("\r\n", "\n").Replace("BBBB\n", "BBBB\r\n"),
                                         "chainsaw.exe", "2.16.5", "chainsaw.exe", "AB", "chainsaw.zip", "CD",
                                         new DateTime(2026, 1, 2));

        Assert.DoesNotContain("v2.16.3", text);
        Assert.Single(text.Split('\n'), l => l.StartsWith("chainsaw.exe"));
        Assert.Contains("eztools\\", text);
    }

    private static ReleaseInfo Release(string package, string version, string asset, long size, string? sha256) =>
        new(package, version, $"https://github.com/example/{package}/releases/tag/v{version}", null)
        {
            Asset = new ReleaseAsset(asset, $"https://github.com/example/{package}/releases/download/{asset}", size, sha256)
        };

    private static ReleaseInfo ReleaseFor(string package, string version, string zip) =>
        Release(package, version, Path.GetFileName(zip), new FileInfo(zip).Length,
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(zip))));

    private static string Write(string root, string relative, string content)
    {
        var path = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private static void WriteVersions(string tools) =>
        File.WriteAllText(Path.Combine(tools, ToolUpdater.VersionsFile), Versions, new UTF8Encoding(true));

    private static string Zip(TempDirectory temp, string name, params (string Entry, string Content)[] entries)
    {
        var path = Path.Combine(temp.Dir("downloads"), name);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (entry, content) in entries)
        {
            using var writer = new StreamWriter(zip.CreateEntry(entry).Open());
            writer.Write(content);
        }
        return path;
    }
}
