using System.Windows;
using System.Windows.Threading;
using ArtefactForge.Core.Update;

namespace ArtefactForge.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Leftovers from an in-place update: the old exe, renamed aside while it was running.
        SelfUpdater.CleanUpAfterUpdate(
            System.IO.Path.GetDirectoryName(System.Environment.ProcessPath) ?? System.AppContext.BaseDirectory);

        ThemeManager.Initialise();

        // A processing run can be long and unattended. Vanishing without a word is the worst
        // outcome: the analyst returns to no window, no message, and no idea whether the output
        // is complete. Show what happened and keep running where the failure allows it.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            Report(args.ExceptionObject as Exception, fatal: true);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Report(e.Exception, fatal: false);
        e.Handled = true;
    }

    private static void Report(Exception? exception, bool fatal)
    {
        var detail = exception?.ToString() ?? "Unknown error.";
        var heading = fatal
            ? "ArtefactForge has to close."
            : "Something went wrong, but the application is still running.";

        MessageBox.Show(
            heading + "\n\n" + detail,
            "ArtefactForge", MessageBoxButton.OK,
            fatal ? MessageBoxImage.Error : MessageBoxImage.Warning);
    }
}
