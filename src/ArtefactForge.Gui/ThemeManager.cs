using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace ArtefactForge.Gui;

/// <summary>
/// Light or dark. The palette is the first merged dictionary in App.xaml; swapping it updates every
/// DynamicResource in every open window at once. The choice is saved with the other per-user
/// preferences (<see cref="Preferences"/>).
/// </summary>
public static class ThemeManager
{
    public static bool IsDark { get; private set; }

    /// <summary>Applies the saved theme, and dark title bars to every window as it opens.</summary>
    public static void Initialise()
    {
        EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent,
            new RoutedEventHandler((sender, _) => ApplyTitleBar((Window)sender)));
        Apply(string.Equals(Preferences.Current.Theme, "Dark", StringComparison.OrdinalIgnoreCase), save: false);
    }

    public static void Apply(bool dark, bool save = true)
    {
        IsDark = dark;
        var palette = new ResourceDictionary
        {
            Source = new Uri(dark ? "Themes/Dark.xaml" : "Themes/Light.xaml", UriKind.Relative)
        };
        var merged = Application.Current.Resources.MergedDictionaries;
        merged[0] = palette;

        foreach (Window window in Application.Current.Windows) ApplyTitleBar(window);
        if (!save) return;
        Preferences.Current.Theme = dark ? "Dark" : "Light";
        Preferences.Save();
    }

    // The title bar belongs to Windows, not WPF. DWM draws it dark on request (Windows 10 2004
    // and later; attribute 19 on the 1809-1909 builds). Older versions ignore it, which is fine.
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private static void ApplyTitleBar(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero) return;

        var value = IsDark ? 1 : 0;
        if (DwmSetWindowAttribute(handle, 20, ref value, sizeof(int)) != 0)
            DwmSetWindowAttribute(handle, 19, ref value, sizeof(int));
    }
}
