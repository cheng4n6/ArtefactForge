using System.Security.AccessControl;
using System.Security.Principal;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// Detection must survive folders it cannot read. Every drive root carries
/// 'System Volume Information', readable only by SYSTEM, so a batch run pointed at a mounted
/// image walked straight into an UnauthorizedAccessException and killed the GUI.
/// </summary>
public class LayoutDetectorAccessTests
{
    private static LayoutProfile DriveLetterProfile() => new()
    {
        Id = "collection-folder",
        Name = "Collection folder",
        Detect = new LayoutDetectRules
        {
            DriveLetterFolder = true,
            Markers = [@"?\Windows"],
            MatchMode = MarkerMatchMode.All
        },
        Resolve = new LayoutResolveRules { RootOffset = "?" }
    };

    [Fact]
    public void An_unreadable_folder_does_not_match_rather_than_throwing()
    {
        using var dir = new TempDirectory();
        var locked = Path.Combine(dir.Path, "System Volume Information");
        Directory.CreateDirectory(locked);

        DenyListing(locked);
        try
        {
            // The exception came from listing the folder's children, so detection has to be
            // pointed AT the locked folder - which is exactly what batch mode does.
            var result = LayoutDetector.Detect(locked, [DriveLetterProfile()]);
            Assert.Empty(result);
        }
        finally
        {
            AllowListing(locked);
        }
    }

    [Fact]
    public void A_sibling_that_cannot_be_read_does_not_stop_the_others()
    {
        using var dir = new TempDirectory();
        var good = Path.Combine(dir.Path, "HOST01");
        Directory.CreateDirectory(Path.Combine(good, "C", "Windows"));

        var locked = Path.Combine(dir.Path, "System Volume Information");
        Directory.CreateDirectory(locked);
        DenyListing(locked);

        try
        {
            // Batch: walk every subfolder, exactly as the CLI and GUI do.
            var detected = Directory.EnumerateDirectories(dir.Path)
                .SelectMany(sub => LayoutDetector.Detect(sub, [DriveLetterProfile()]))
                .ToList();

            Assert.Equal("HOST01", Assert.Single(detected).CollectionName);
        }
        finally
        {
            AllowListing(locked);
        }
    }

    private static void DenyListing(string path)
    {
        var info = new DirectoryInfo(path);
        var security = info.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!, FileSystemRights.ListDirectory,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));
        info.SetAccessControl(security);
    }

    private static void AllowListing(string path)
    {
        var info = new DirectoryInfo(path);
        var security = info.GetAccessControl();
        security.RemoveAccessRuleAll(new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!, FileSystemRights.ListDirectory,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));
        info.SetAccessControl(security);
    }
}
