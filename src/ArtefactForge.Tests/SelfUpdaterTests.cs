using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ArtefactForge.Core.Update;

namespace ArtefactForge.Tests;

/// <summary>
/// The update path end to end against a folder source: an installed package, a signed release,
/// and what must and must not change. Everything here is about not damaging an installation and
/// not installing anything the signature does not vouch for.
/// </summary>
public class SelfUpdaterTests
{
    private const string Password = "test-password";
    private static readonly (string Pem, string Public) Key = ReleaseSigning.GenerateKey(Password);
    private static readonly (string Pem, string Public) OtherKey = ReleaseSigning.GenerateKey(Password);

    // ------------------------------------------------------------------ signing

    [Fact]
    public void A_signature_verifies_and_any_change_breaks_it()
    {
        var data = Encoding.UTF8.GetBytes("{\"version\":\"1.6.0\"}");
        var signature = ReleaseSigning.Sign(data, Key.Pem, Password, out var publicKey);

        Assert.Equal(Key.Public, publicKey);
        Assert.True(ReleaseSigning.Verify(data, signature, [Key.Public]));
        Assert.False(ReleaseSigning.Verify(Encoding.UTF8.GetBytes("{\"version\":\"1.6.1\"}"), signature, [Key.Public]));
        Assert.False(ReleaseSigning.Verify(data, signature, [OtherKey.Public]));
        Assert.False(ReleaseSigning.Verify(data, "not base64!", [Key.Public]));
    }

    [Fact]
    public void A_malformed_trusted_key_does_not_stop_a_good_one_verifying()
    {
        var data = new byte[] { 1, 2, 3 };
        var signature = ReleaseSigning.Sign(data, Key.Pem, Password, out _);
        Assert.True(ReleaseSigning.Verify(data, signature, ["garbage", Key.Public]));
    }

    [Fact]
    public void The_wrong_password_is_reported_plainly()
    {
        var ex = Assert.Throws<UpdateException>(() => ReleaseSigning.Sign([1], Key.Pem, "wrong", out _));
        Assert.Contains("password", ex.Message);
    }

    [Fact]
    public void A_fingerprint_is_eight_groups_of_four()
    {
        var fingerprint = ReleaseSigning.Fingerprint(Key.Public);
        Assert.Equal(8, fingerprint.Split(':').Length);
        Assert.Equal(39, fingerprint.Length);
    }

    // ------------------------------------------------------------------ manifest

    [Fact]
    public void A_release_manifest_may_only_name_a_zip_beside_it()
    {
        foreach (var file in new[] { "../evil.zip", "sub/x.zip", "C:x.zip", "x.exe" })
            Assert.Throws<UpdateException>(() => ReleaseManifest.Parse(Json("1.6.0", file, 1, new string('A', 64))));
    }

    [Fact]
    public void A_manifest_for_another_product_is_refused()
    {
        var json = Encoding.UTF8.GetBytes("{\"product\":\"Other\",\"version\":\"1.6.0\",\"file\":\"a.zip\",\"size\":1,\"sha256\":\"" + new string('A', 64) + "\"}");
        Assert.Throws<UpdateException>(() => ReleaseManifest.Parse(json));
    }

    [Fact]
    public void A_package_manifest_may_not_reach_outside_the_folder_or_into_tools()
    {
        foreach (var path in new[] { @"..\x.exe", @"Tools\eztools\x.exe", @"C:\x.exe", @"_previous\x", "files.txt", @"a\..\b" })
            Assert.Throws<UpdateException>(() => PackageManifest.Parse([new string('A', 64) + " " + path]));
    }

    // ---------------------------------------------------------------- end to end

    [Fact]
    public async Task An_update_replaces_the_package_and_leaves_the_analysts_files_alone()
    {
        using var temp = new TempDirectory();
        var install = Install(temp, "1.5.0", new()
        {
            ["ArtefactForge.exe"] = "gui 1.5",
            ["ArtefactForgeCli.exe"] = "cli 1.5",
            [@"Modules\EZTools\Kept.forge"] = "kept 1.5",
            [@"Modules\EZTools\Edited.forge"] = "edited 1.5",
            [@"Modules\EZTools\Dropped.forge"] = "dropped 1.5",
            [@"Scripts\linux\Parse.ps1"] = "parse 1.5",
            ["Apps.yaml"] = "apps 1.5",
        });
        File.WriteAllText(Path.Combine(install, "Modules", "EZTools", "Edited.forge"), "edited by the analyst");
        File.WriteAllText(Path.Combine(install, "Modules", "EZTools", "Mine.forge"), "the analyst's own module");
        File.WriteAllText(Path.Combine(install, "Tools", "tool.exe"), "a tool");

        var source = Publish(temp, "1.6.0", new()
        {
            ["ArtefactForge.exe"] = "gui 1.6",
            ["ArtefactForgeCli.exe"] = "cli 1.6",
            [@"Modules\EZTools\Kept.forge"] = "kept 1.5",
            [@"Modules\EZTools\Edited.forge"] = "edited 1.6",
            [@"Modules\Linux\New.forge"] = "new 1.6",
            [@"Scripts\linux\Parse.ps1"] = "parse 1.6",
            ["Apps.yaml"] = "apps 1.5",
        });

        var updater = new SelfUpdater(install, "1.5.0", [Key.Public]);
        var check = await updater.CheckAsync(source);
        Assert.Equal(UpdateCheckStatus.Available, check.Status);

        var staged = await updater.DownloadAsync(source, check.Release!);
        var plan = updater.Plan(staged);
        Assert.Equal(ChangeKind.KeepUserCopy, Kind(plan, @"Modules\EZTools\Edited.forge"));
        Assert.Equal(ChangeKind.Remove, Kind(plan, @"Modules\EZTools\Dropped.forge"));
        Assert.Equal(ChangeKind.Unchanged, Kind(plan, @"Modules\EZTools\Kept.forge"));
        Assert.Equal(ChangeKind.Add, Kind(plan, @"Modules\Linux\New.forge"));

        var outcome = updater.Apply(staged, plan);

        Assert.Equal("gui 1.6", Read(install, "ArtefactForge.exe"));
        Assert.Equal("cli 1.6", Read(install, "ArtefactForgeCli.exe"));
        Assert.Equal("parse 1.6", Read(install, @"Scripts\linux\Parse.ps1"));
        Assert.Equal("new 1.6", Read(install, @"Modules\Linux\New.forge"));
        Assert.Equal("edited by the analyst", Read(install, @"Modules\EZTools\Edited.forge"));
        Assert.Equal("edited 1.6", Read(install, @"Modules\EZTools\Edited.forge.new"));
        Assert.Equal("the analyst's own module", Read(install, @"Modules\EZTools\Mine.forge"));
        Assert.Equal("a tool", Read(install, @"Tools\tool.exe"));
        Assert.False(File.Exists(Path.Combine(install, "Modules", "EZTools", "Dropped.forge")));

        // The backup holds what was replaced or removed, so one step back is always possible.
        Assert.Equal("gui 1.5", Read(outcome.BackupDirectory, "ArtefactForge.exe"));
        Assert.Equal("dropped 1.5", Read(outcome.BackupDirectory, @"Modules\EZTools\Dropped.forge"));

        // The folder now describes itself as the new version, and the update is on record.
        Assert.Equal(staged.Manifest.Files.Count, PackageManifest.Load(install)!.Files.Count);
        Assert.Contains("1.5.0 -> 1.6.0", Read(install, SelfUpdater.LogFileName));
        Assert.Contains(@"kept from the earlier package", Read(install, "BUILD.txt"));
        Assert.DoesNotContain("TOOLS ARE NOT INCLUDED", Read(install, "BUILD.txt"));
        Assert.False(Directory.Exists(Path.Combine(install, SelfUpdater.UpdateFolder)));
    }

    [Fact]
    public async Task A_release_signed_by_an_untrusted_key_is_not_read()
    {
        using var temp = new TempDirectory();
        var install = Install(temp, "1.5.0", Minimal("1.5"));
        var source = Publish(temp, "1.6.0", Minimal("1.6"), signWith: OtherKey);

        var check = await new SelfUpdater(install, "1.5.0", [Key.Public]).CheckAsync(source);
        Assert.Equal(UpdateCheckStatus.Failed, check.Status);
        Assert.Null(check.Release);
        Assert.Contains("signature", check.Message);
    }

    [Fact]
    public async Task An_older_or_equal_release_is_not_offered_or_installed()
    {
        using var temp = new TempDirectory();
        var install = Install(temp, "1.6.0", Minimal("1.6"));
        var source = Publish(temp, "1.5.0", Minimal("1.5"));
        var updater = new SelfUpdater(install, "1.6.0", [Key.Public]);

        var check = await updater.CheckAsync(source);
        Assert.Equal(UpdateCheckStatus.UpToDate, check.Status);
        await Assert.ThrowsAsync<UpdateException>(() => updater.DownloadAsync(source, check.Release!));
    }

    [Fact]
    public async Task A_zip_that_does_not_match_the_signed_hash_is_discarded()
    {
        using var temp = new TempDirectory();
        var install = Install(temp, "1.5.0", Minimal("1.5"));
        var source = Publish(temp, "1.6.0", Minimal("1.6"));
        var updater = new SelfUpdater(install, "1.5.0", [Key.Public]);
        var check = await updater.CheckAsync(source);

        // Same size, different bytes: only the hash can catch it.
        var zip = Path.Combine(source.Description, check.Release!.File);
        var bytes = File.ReadAllBytes(zip);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(zip, bytes);

        var ex = await Assert.ThrowsAsync<UpdateException>(() => updater.DownloadAsync(source, check.Release!));
        Assert.Contains("SHA-256", ex.Message);
        Assert.Equal("gui 1.5", Read(install, "ArtefactForge.exe"));
    }

    [Fact]
    public void A_zip_entry_outside_the_folder_is_refused()
    {
        using var temp = new TempDirectory();
        var zip = Path.Combine(temp.Path, "evil.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            using (var writer = new StreamWriter(archive.CreateEntry("ArtefactForge/../../evil.txt").Open()))
                writer.Write("x");

        Assert.Throws<UpdateException>(() => SelfUpdater.Extract(zip, Path.Combine(temp.Path, "out")));
        Assert.False(File.Exists(Path.Combine(temp.Path, "evil.txt")));
    }

    [Fact]
    public async Task A_failure_part_way_puts_every_file_back()
    {
        using var temp = new TempDirectory();
        var install = Install(temp, "1.5.0", Minimal("1.5"));
        var source = Publish(temp, "1.6.0", new(Minimal("1.6")) { [@"Scripts\zz.ps1"] = "late" });

        // A folder where the release wants a file: the last copy fails after the exes are replaced.
        Directory.CreateDirectory(Path.Combine(install, "Scripts", "zz.ps1"));

        var updater = new SelfUpdater(install, "1.5.0", [Key.Public]);
        var check = await updater.CheckAsync(source);
        var staged = await updater.DownloadAsync(source, check.Release!);
        var plan = updater.Plan(staged);

        Assert.Throws<UpdateException>(() => updater.Apply(staged, plan));
        Assert.Equal("gui 1.5", Read(install, "ArtefactForge.exe"));
        Assert.Equal("cli 1.5", Read(install, "ArtefactForgeCli.exe"));
        Assert.Equal(2, PackageManifest.Load(install)!.Files.Count);
        Assert.DoesNotContain("1.6.0", File.Exists(Path.Combine(install, SelfUpdater.LogFileName)) ? Read(install, SelfUpdater.LogFileName) : "");
    }

    [Fact]
    public async Task An_exe_in_use_is_set_aside_and_cleaned_up_on_the_next_start()
    {
        using var temp = new TempDirectory();
        var install = Install(temp, "1.5.0", Minimal("1.5"));
        var source = Publish(temp, "1.6.0", Minimal("1.6"));
        var updater = new SelfUpdater(install, "1.5.0", [Key.Public]);
        var staged = await updater.DownloadAsync(source, (await updater.CheckAsync(source)).Release!);

        var gui = Path.Combine(install, "ArtefactForge.exe");
        using (new FileStream(gui, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            // Windows: open without FileShare.Write refuses an overwrite but allows a rename.
            updater.Apply(staged, updater.Plan(staged));
            Assert.Equal("gui 1.6", Read(install, "ArtefactForge.exe"));
        }

        SelfUpdater.CleanUpAfterUpdate(install);
        Assert.Empty(Directory.GetFiles(install, "*.af-old*"));
    }

    [Fact]
    public void A_source_checkout_or_an_unsigned_build_cannot_update()
    {
        using var temp = new TempDirectory();
        var install = Install(temp, "1.5.0", Minimal("1.5"));

        Assert.Contains("signing key", new SelfUpdater(install, "1.5.0", []).WhyNotUpdatable());
        Directory.CreateDirectory(Path.Combine(install, "src"));
        Assert.Contains("source checkout", new SelfUpdater(install, "1.5.0", [Key.Public]).WhyNotUpdatable());
    }

    // ---------------------------------------------------------------- helpers

    private static Dictionary<string, string> Minimal(string version) => new()
    {
        ["ArtefactForge.exe"] = "gui " + version,
        ["ArtefactForgeCli.exe"] = "cli " + version,
    };

    /// <summary>An installed package: files, files.txt, a no-tools BUILD.txt, and Tools\.</summary>
    private static string Install(TempDirectory temp, string version, Dictionary<string, string> files)
    {
        var root = temp.Dir("install");
        WriteTree(root, files);
        WriteManifest(root, files.Keys);
        File.WriteAllText(Path.Combine(root, "BUILD.txt"),
            $"ArtefactForge {version}\nTools      NOT INCLUDED - see below\n\nTOOLS ARE NOT INCLUDED in this build.\n");
        Directory.CreateDirectory(Path.Combine(root, "Tools"));
        return root;
    }

    /// <summary>A release folder as a release would serve it: zip, manifest, signature.</summary>
    private static FolderReleaseSource Publish(TempDirectory temp, string version, Dictionary<string, string> files,
        (string Pem, string Public)? signWith = null)
    {
        var package = temp.Dir("build-" + version);
        WriteTree(package, files);
        WriteManifest(package, files.Keys);

        var site = temp.Dir("site-" + version);
        var zipName = $"artefactforge-{version}-no-tools.zip";
        var zip = Path.Combine(site, zipName);
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            foreach (var file in Directory.EnumerateFiles(package, "*", SearchOption.AllDirectories))
                archive.CreateEntryFromFile(file, "ArtefactForge/" + Path.GetRelativePath(package, file).Replace('\\', '/'));

        var json = Json(version, zipName, new FileInfo(zip).Length, SelfUpdater.Sha256(zip));
        File.WriteAllBytes(Path.Combine(site, ReleaseFiles.Manifest), json);
        var key = signWith ?? Key;
        File.WriteAllText(Path.Combine(site, ReleaseFiles.Signature), ReleaseSigning.Sign(json, key.Pem, Password, out _));
        return new FolderReleaseSource(site);
    }

    private static byte[] Json(string version, string file, long size, string sha256) => Encoding.UTF8.GetBytes(
        $"{{\"product\":\"ArtefactForge\",\"version\":\"{version}\",\"file\":\"{file}\",\"size\":{size},\"sha256\":\"{sha256}\"}}");

    private static void WriteTree(string root, Dictionary<string, string> files)
    {
        foreach (var (relative, content) in files)
        {
            var path = PackageManifest.Local(root, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content);
        }
    }

    private static void WriteManifest(string root, IEnumerable<string> relatives) =>
        File.WriteAllLines(Path.Combine(root, PackageManifest.FileName),
            relatives.Select(r => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(PackageManifest.Local(root, r)))) + " " + r));

    private static string Read(string root, string relative) => File.ReadAllText(PackageManifest.Local(root, relative));

    private static ChangeKind Kind(UpdatePlan plan, string relative) =>
        plan.Changes.Single(c => c.RelativePath == relative).Kind;
}
