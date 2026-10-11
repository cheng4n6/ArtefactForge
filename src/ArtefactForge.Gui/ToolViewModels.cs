using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using ArtefactForge.Core;

namespace ArtefactForge.Gui;

/// <summary>A row in the Tools grid.</summary>
public sealed class ToolRow
{
    public required ToolUsage Usage { get; init; }

    public string Package => Usage.Package;
    public string Executable => Usage.Executable;
    public string Version => Usage.Version ?? "-";
    public int ModuleCount => Usage.ModuleCount;
    public string ModuleList => string.Join(", ", Usage.Modules);

    public string StatusText => Usage.Found ? (Usage.IsSystem ? "system" : "found") : "MISSING";

    /// <summary>Enough hash to compare against a manifest by eye, without filling the column.</summary>
    public string ShortHash => string.IsNullOrEmpty(Usage.Sha256) ? "-" : Usage.Sha256[..16].ToLowerInvariant();
}

public sealed class UpdateRow : Observable
{
    private string _statusText = "not checked";
    private string _latestText = "latest: ?";
    private string? _url;
    private ReleaseInfo? _release;
    private bool _busy;

    public required string Package { get; init; }
    public required string Repository { get; init; }
    public string? Installed { get; init; }

    public string InstalledText => Installed is null ? "installed: unknown" : $"installed: {Installed}";

    public string LatestText
    {
        get => _latestText;
        set => Set(ref _latestText, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => Set(ref _statusText, value);
    }

    public string? Url
    {
        get => _url;
        set => Set(ref _url, value);
    }

    /// <summary>The release the last check found; what the Update button installs.</summary>
    public ReleaseInfo? Release
    {
        get => _release;
        private set
        {
            Set(ref _release, value);
            RaiseInstallState();
        }
    }

    public bool IsBusy
    {
        get => _busy;
        set
        {
            Set(ref _busy, value);
            RaiseInstallState();
        }
    }

    /// <summary>Why the Update button is disabled, shown as its tooltip; null when it is enabled.</summary>
    public string? InstallBlockedReason => _release is null
        ? "Check for updates first."
        : ToolUpdater.WhyNotInstallable(_release, Installed);

    public bool CanInstall => !_busy && InstallBlockedReason is null;

    public string InstallText => _release?.Ok == true ? $"Update to {_release.LatestVersion}" : "Update";

    private void RaiseInstallState()
    {
        Raise(nameof(InstallBlockedReason));
        Raise(nameof(CanInstall));
        Raise(nameof(InstallText));
    }

    public void Apply(ReleaseInfo release)
    {
        Url = release.Url;
        Release = release;

        if (!release.Ok)
        {
            LatestText = "latest: ?";
            // Offline is the expected state on an isolated workstation, so say so plainly.
            StatusText = "could not reach GitHub - " + (release.Error ?? "unknown error");
            return;
        }

        LatestText = "latest: " + release.LatestVersion;
        StatusText = ReleaseCheck.IsNewer(release.LatestVersion, Installed) switch
        {
            true => "update available",
            false => "up to date",
            null => "compare manually - installed version unknown"
        };
    }
}

/// <summary>A row in the Apps card on the Tools tab.</summary>
public sealed class AppRow(AppEntry entry)
{
    public AppEntry Entry { get; } = entry;

    public string Name => Entry.Name;
    public bool Found => Entry.Found;

    /// <summary>The description, or - for a program that is missing - where it was looked for.</summary>
    public string Detail => Entry.Found || Entry.Executable.Length == 0
        ? Entry.Description
        : "not found: " + Entry.LookedFor;

    public string ToolTip => Entry.ResolvedPath ?? Entry.LookedFor;

    /// <summary>Greyed rather than hidden, so a typo in Apps.yaml is visible.</summary>
    public double RowOpacity => Entry.Found ? 1.0 : 0.55;

    public ImageSource? Icon { get; } = entry.ResolvedPath is null ? null : ExeIcon.Load(entry.ResolvedPath);
}

/// <summary>
/// An executable's own icon, through the shell's ExtractIconEx rather than System.Drawing, which a
/// WPF-only project does not reference. Returns null on any failure: the row then shows no icon,
/// which is not worth an error.
/// </summary>
internal static class ExeIcon
{
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconEx(string file, int index, IntPtr[]? large, IntPtr[]? small, uint count);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    public static ImageSource? Load(string path)
    {
        var large = new IntPtr[1];
        try
        {
            if (ExtractIconEx(path, 0, large, null, 1) == 0 || large[0] == IntPtr.Zero) return null;
            var image = Imaging.CreateBitmapSourceFromHIcon(large[0], Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            image.Freeze();
            return image;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (large[0] != IntPtr.Zero) DestroyIcon(large[0]);
        }
    }
}
