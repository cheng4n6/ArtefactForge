using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;
using ArtefactForge.Core;
using ArtefactForge.Core.Update;
using Microsoft.Win32;

namespace ArtefactForge.Gui;

public partial class MainWindow : Window
{
    private readonly string _repoRoot;
    private readonly List<LayoutProfile> _layouts = [];
    private readonly ObservableCollection<PlatformGroup> _platforms = [];
    private readonly ObservableCollection<CategoryGroup> _railCategories = [];
    private readonly ListCollectionView _railView;
    // Categories the analyst has opened in the list view, as "Platform/Category". Everything
    // starts collapsed; this keeps what was opened across a filter or platform change.
    private readonly HashSet<string> _expanded = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ModuleItem> _allItems = [];
    private readonly ObservableCollection<CollectionItem> _collections = [];
    private readonly ObservableCollection<CollectionProgress> _progress = [];
    private readonly ObservableCollection<UpdateRow> _updates = [];
    private readonly ObservableCollection<AppRow> _apps = [];
    private readonly List<WorkResult> _results = [];
    private readonly StringBuilder _log = new();
    private readonly DispatcherTimer _elapsedTimer = new() { Interval = TimeSpan.FromSeconds(1) };

    private CancellationTokenSource? _cancellation;
    private IReleaseSource? _offerSource;
    private ReleaseManifest? _offerRelease;
    private DateTimeOffset _runStarted;
    private string? _lastCaseDirectory;
    private Platform? _platformFilter;

    // Never default inside the application folder. A deployment package may sit on a USB stick, a
    // read-only share, or be replaced wholesale on the next update - none of which are somewhere
    // case output should live.
    private static readonly string DefaultOutput = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ArtefactForge");

    // The evidence path the output and case name were last recalled for, so re-detecting the same
    // evidence (Batch toggled, focus lost) does not overwrite what the analyst has since changed.
    private string? _recalledFor;
    private OutputRecall? _recall;
    private bool _applyingRecall;
    private bool _outputTyped;
    private bool _caseTyped;
    private bool _outputConfirmed;

    public MainWindow()
    {
        _railView = new ListCollectionView(_railCategories);
        InitializeComponent();

        _repoRoot = FindRepoRoot(AppContext.BaseDirectory) ?? Directory.GetCurrentDirectory();
        // The commit belongs in the manifest and BUILD.txt, where it traces output to source.
        // In the title bar it is just noise.
        Title = $"ArtefactForge v{BuildInfo.Version}";
        CategoryList.ItemsSource = _platforms;
        RailList.ItemsSource = _railView;
        CollectionList.ItemsSource = _collections;
        ProgressList.ItemsSource = _progress;

        _elapsedTimer.Tick += (_, _) =>
            StatElapsed.Text = (DateTimeOffset.Now - _runStarted).ToString(@"mm\:ss");

        UpdateList.ItemsSource = _updates;
        AppList.ItemsSource = _apps;

        LoadLayouts();
        LoadModules();
        LoadProfiles();
        LoadTools();
        ShowAbout();
        DarkModeSwitch.IsChecked = ThemeManager.IsDark;
        (Preferences.Current.ModuleView == ModuleView.Rail ? ModuleViewRail : ModuleViewList).IsChecked = true;
        ShowModuleView(Preferences.Current.ModuleView);
        LoadRunOptions();
        InitIocTab();
        InitRdpTab();

        OutputPath.Text = DefaultOutput;
        EvidencePath.LostFocus += (_, _) => Detect();
        OutputPath.TextChanged += (_, _) => { OnOutputTyped(); RefreshCollections(); };
        CaseName.TextChanged += (_, _) => { if (!_applyingRecall) _caseTyped = true; RefreshCollections(); };
        RefreshCollections();
    }

    // ---------------------------------------------------------------- loading

    private void LoadLayouts()
    {
        var loaded = LayoutLoader.LoadDirectory(Path.Combine(_repoRoot, "Layouts"));
        _layouts.AddRange(loaded.Items);
        foreach (var error in loaded.Errors) Append($"layout error: {error.Path}: {error.Message}");
    }

    private void LoadModules()
    {
        var loaded = ModuleLoader.LoadDirectory(Path.Combine(_repoRoot, "Modules"));
        foreach (var error in loaded.Errors) Append($"module error: {Path.GetFileName(error.Path)}: {error.Message}");

        foreach (var module in loaded.Items)
        {
            var item = new ModuleItem { Definition = module, IsSelected = module.DefaultEnabled };
            // Every way a tick changes - the module's own box or switch, its category, Default,
            // All, None, a profile - goes through IsSelected, so the counts follow from here.
            item.PropertyChanged += (_, args) =>
            {
                if (args.PropertyName == nameof(ModuleItem.IsSelected)) UpdateModuleCount();
            };
            _allItems.Add(item);
        }

        BuildCategories("");

        if (loaded.Errors.Count > 0)
            MessageBox.Show(this,
                $"{loaded.Errors.Count} module file(s) failed to load. See the run log for details.",
                "ArtefactForge", MessageBoxButton.OK, MessageBoxImage.Warning);

        UpdateModuleCount();
    }

    private void LoadProfiles()
    {
        ProfileBox.Items.Clear();
        ProfileBox.Items.Add("(current selection)");
        ProfileBox.SelectedIndex = 0;

        var dir = ProfileFile.Directory(_repoRoot);
        if (!Directory.Exists(dir)) return;

        foreach (var file in Directory.EnumerateFiles(dir, "*.json").OrderBy(f => f))
            ProfileBox.Items.Add(Path.GetFileNameWithoutExtension(file));
    }

    // ------------------------------------------------------------------ tools

    private List<string> ToolRoots() => ToolInventory.Roots(_repoRoot);

    private void LoadTools()
    {
        var roots = ToolRoots();
        ToolRootsText.Text = string.Join(Environment.NewLine,
            roots.Select(r => (Directory.Exists(r) ? "" : "(missing) ") + r));

        var inventory = ToolInventory.Scan(_allItems.Select(m => m.Definition), roots);
        ToolsGrid.ItemsSource = inventory.Select(u => new ToolRow { Usage = u }).ToList();

        var missing = inventory.Count(u => !u.Found);
        ToolSummary.Text = missing == 0
            ? $"{inventory.Count} executable(s) referenced, all found."
            : $"{inventory.Count} executable(s) referenced, {missing} MISSING - modules using them will report ToolMissing.";
        ToolSummary.SetResourceReference(TextBlock.ForegroundProperty, missing == 0 ? "TextBrush" : "ErrorBrush");

        LoadApps(roots);

        _updates.Clear();
        var toolsDir = roots[0];
        foreach (var (package, repository) in ReleaseCheck.KnownRepositories)
        {
            if (!Directory.Exists(Path.Combine(toolsDir, package))) continue;
            _updates.Add(new UpdateRow
            {
                Package = package,
                Repository = repository,
                Installed = ToolInventory.InstalledVersion(toolsDir, package)
            });
        }
    }

    private void OnRefreshTools(object sender, RoutedEventArgs e) => LoadTools();

    // ------------------------------------------------------------------- apps

    private string AppsPath => Path.Combine(_repoRoot, AppCatalog.FileName);

    /// <summary>Reloaded with the tools, so the tab's existing Refresh picks up an edited Apps.yaml.</summary>
    private void LoadApps(List<string> roots)
    {
        _apps.Clear();
        var catalog = AppCatalog.Load(AppsPath, roots);
        foreach (var app in catalog.Apps) _apps.Add(new AppRow(app));

        string? message = null;
        if (catalog.FileMissing)
            message = $"No {AppCatalog.FileName} beside the application. Edit list creates one.";
        else if (catalog.Error is not null)
            message = catalog.Error;
        else if (catalog.Apps.Count == 0)
            message = $"{AppCatalog.FileName} lists no apps yet. Edit list to add some.";

        AppsMessage.Text = message ?? "";
        AppsMessage.Visibility = message is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnOpenApp(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button { Tag: AppRow row } || row.Entry.ResolvedPath is null) return;
        try
        {
            // Detached: the app outlives ArtefactForge, several copies can run, and nothing goes in
            // any manifest - opening a viewer is not processing evidence.
            Process.Start(new ProcessStartInfo(row.Entry.ResolvedPath)
            {
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(row.Entry.ResolvedPath) ?? ""
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not start {row.Name}:\n{ex.Message}", "ArtefactForge",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnEditApps(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!File.Exists(AppsPath)) File.WriteAllText(AppsPath, AppCatalog.Template + Environment.NewLine);
            // Notepad rather than the shell: .yaml often has no association, and a failed
            // "open with" prompt is a worse experience than a plain editor.
            Process.Start(new ProcessStartInfo("notepad.exe", $"\"{AppsPath}\"") { UseShellExecute = false });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not open {AppsPath}:\n{ex.Message}", "ArtefactForge",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // ---------------------------------------------------------------- options

    private void OnEditOptions(object sender, RoutedEventArgs e) => EditOptions(_allItems);

    /// <summary>The Options button on a module's row: the same dialog, showing only that module.</summary>
    private void OnModuleOptions(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button { Tag: ModuleItem item }) EditOptions([item]);
    }

    private void EditOptions(IEnumerable<ModuleItem> modules)
    {
        var dialog = new OptionsWindow(modules) { Owner = this };
        if (dialog.ShowDialog() != true) return;

        foreach (var item in _allItems)
        {
            if (!dialog.Values.TryGetValue(item.Definition.Name, out var values)) continue;
            item.OptionValues.Clear();
            foreach (var (option, value) in values) item.OptionValues[option] = value;
            item.RefreshOptions();
        }

        var tuned = _allItems.Count(m => m.IsTuned);
        SetupStatus.Text = tuned == 0 ? "Module options are at their defaults."
                                      : $"{tuned} module(s) tuned away from defaults.";
    }

    /// <summary>Only options moved off their default are sent, so a run stays minimal and readable.</summary>
    private Dictionary<string, IReadOnlyDictionary<string, string>> CollectOptionOverrides()
    {
        var overrides = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in _allItems.Where(m => m.IsSelected && m.OptionValues.Count > 0))
        {
            var defaults = ModuleOptions.Effective(item.Definition);
            var changed = item.OptionValues
                .Where(pair => defaults.TryGetValue(pair.Key, out var d)
                               && !string.Equals(d, pair.Value, StringComparison.OrdinalIgnoreCase))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);

            if (changed.Count > 0) overrides[item.Definition.Name] = changed;
        }
        return overrides;
    }

    private async void OnCheckUpdates(object sender, RoutedEventArgs e)
    {
        if (_updates.Count == 0) { UpdateStatus.Text = "No updatable tools found in the Tools folder."; return; }

        CheckUpdatesButton.IsEnabled = false;
        UpdateStatus.Text = "Checking GitHub...";
        try
        {
            foreach (var row in _updates)
                row.Apply(await ReleaseCheck.LatestAsync(row.Package, row.Repository));

            UpdateStatus.Text = "Checked " + DateTime.Now.ToString("HH:mm:ss")
                                + ". Nothing was downloaded - press Update on a tool to install its release.";
        }
        finally
        {
            CheckUpdatesButton.IsEnabled = true;
        }
    }

    private async void OnInstallTool(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: UpdateRow { Release: { Asset: { } asset } release } row })
            return;

        if (!RunButton.IsEnabled)
        {
            MessageBox.Show(this, "Wait for the current run or update to finish first.", "ArtefactForge");
            return;
        }

        var spec = ToolUpdater.Find(row.Package)!;
        var question =
            $"Download {asset.Name} ({asset.Size / 1048576.0:N1} MB) from GitHub, check its SHA-256, and replace " +
            $"Tools\\{row.Package} ({row.Installed ?? "version unknown"}) with {release.LatestVersion}?\n\n" +
            $"The program is installed as {spec.Executable}, so modules find it as before, and VERSIONS.txt " +
            "records the new version and hash." +
            (spec.KeptNote is null ? "" : "\n\n" + spec.KeptNote);
        if (MessageBox.Show(this, question, "Update " + row.Package, MessageBoxButton.OKCancel,
                            MessageBoxImage.Question) != MessageBoxResult.OK)
            return;

        row.IsBusy = true;
        CheckUpdatesButton.IsEnabled = false;
        RunButton.IsEnabled = false;
        var total = asset.Size / 1048576.0;
        var progress = new Progress<long>(bytes =>
            row.StatusText = $"downloading {bytes / 1048576.0:N1} of {total:N1} MB");
        try
        {
            var outcome = await new ToolUpdater(ToolRoots()[0]).UpdateAsync(release, row.Installed, progress);
            LoadTools();
            UpdateStatus.Text =
                $"{outcome.Package} updated from {outcome.FromVersion ?? "an unknown version"} to {outcome.ToVersion}" +
                $" at {DateTime.Now:HH:mm:ss}. VERSIONS.txt records SHA256 {outcome.ExecutableSha256}.";
        }
        catch (Exception ex) when (ex is UpdateException or HttpRequestException or IOException
                                       or UnauthorizedAccessException or TaskCanceledException)
        {
            row.StatusText = "update failed - see the message";
            MessageBox.Show(this, ex.Message, $"Update {row.Package} failed", MessageBoxButton.OK,
                            MessageBoxImage.Warning);
        }
        finally
        {
            row.IsBusy = false;
            CheckUpdatesButton.IsEnabled = true;
            RunButton.IsEnabled = true;
        }
    }

    private void OnOpenRelease(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: UpdateRow row }) return;

        // Open() only accepts local paths and returned silently for a URL, so the button did nothing.
        var page = ReleaseCheck.ReleasePage(row.Repository, row.Url);
        try
        {
            Process.Start(new ProcessStartInfo(page.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            MessageBox.Show(this, $"Could not open the browser: {ex.Message}\n\n{page.AbsoluteUri}",
                            "ArtefactForge");
        }
    }

    // --------------------------------------------------------------- settings

    private void OnDarkModeToggled(object sender, RoutedEventArgs e)
    {
        var dark = DarkModeSwitch.IsChecked == true;
        if (dark != ThemeManager.IsDark) ThemeManager.Apply(dark);
    }

    private void OnModuleViewChanged(object sender, RoutedEventArgs e)
    {
        var view = ModuleViewRail.IsChecked == true ? ModuleView.Rail : ModuleView.List;
        ShowModuleView(view);
        if (view == Preferences.Current.ModuleView) return;
        Preferences.Current.ModuleView = view;
        Preferences.Save();
    }

    private void ShowModuleView(ModuleView view)
    {
        // Fires once while the window is still being built, before both views exist.
        if (ModuleRailView is null || ExpandButtons is null) return;
        var rail = view == ModuleView.Rail;
        ModuleListView.Visibility = rail ? Visibility.Collapsed : Visibility.Visible;
        ExpandButtons.Visibility = rail ? Visibility.Collapsed : Visibility.Visible;
        ModuleRailView.Visibility = rail ? Visibility.Visible : Visibility.Collapsed;
    }

    // ------------------------------------------------------- application update

    private void ShowAbout()
    {
        var updater = SelfUpdater.ForRunningApplication();
        AboutVersion.Text = BuildInfo.Describe();
        AboutFolder.Text = "Installed in " + updater.InstallDirectory;

        var reason = updater.WhyNotUpdatable();
        if (reason is null) return;
        AppUpdateStatus.Text = reason;
        CheckAppUpdateButton.IsEnabled = false;
        UpdateFromFolderButton.IsEnabled = false;
    }

    private async void OnCheckAppUpdate(object sender, RoutedEventArgs e) =>
        await CheckAppUpdate(new GitHubReleaseSource());

    private async void OnUpdateFromFolder(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select the folder holding " + ReleaseFiles.Manifest };
        if (dialog.ShowDialog(this) == true) await CheckAppUpdate(new FolderReleaseSource(dialog.FolderName));
    }

    private async Task CheckAppUpdate(IReleaseSource source)
    {
        _offerSource = null;
        _offerRelease = null;
        InstallUpdateButton.Visibility = Visibility.Collapsed;
        AppUpdateNotes.Visibility = Visibility.Collapsed;
        SetAppUpdateBusy(true);
        AppUpdateStatus.Text = $"Checking {source.Description} ...";
        try
        {
            var check = await SelfUpdater.ForRunningApplication().CheckAsync(source);
            AppUpdateStatus.Text = check.Message;
            if (check.Status != UpdateCheckStatus.Available) return;

            _offerSource = source;
            _offerRelease = check.Release!;
            if (!string.IsNullOrWhiteSpace(_offerRelease.Notes))
            {
                AppUpdateNotes.Text = _offerRelease.Notes;
                AppUpdateNotes.Visibility = Visibility.Visible;
            }
            InstallUpdateButton.Content = $"Download and install {_offerRelease.Version}";
            InstallUpdateButton.Visibility = Visibility.Visible;
        }
        finally
        {
            SetAppUpdateBusy(false);
        }
    }

    private async void OnInstallAppUpdate(object sender, RoutedEventArgs e)
    {
        if (_offerSource is not { } source || _offerRelease is not { } release) return;

        // Output provenance records the ArtefactForge version; it must not change under a run.
        if (StopButton.IsEnabled)
        {
            MessageBox.Show(this, "A run is in progress. Update once it has finished.", "Update ArtefactForge",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(this,
            $"Download ArtefactForge {release.Version} ({release.Size / 1024.0 / 1024.0:N1} MB) and replace this installation?\n\n" +
            "Modules, layouts and profiles you have edited are kept, and Tools\\ is not touched. " +
            "The current version is kept in _previous\\ so it can be put back.",
            "Update ArtefactForge", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        SetAppUpdateBusy(true);
        RunButton.IsEnabled = false;
        try
        {
            var updater = SelfUpdater.ForRunningApplication();
            var progress = new Progress<long>(bytes =>
                AppUpdateStatus.Text = $"Downloading ... {bytes * 100 / Math.Max(1, release.Size)}%");

            var staged = await Task.Run(() => updater.DownloadAsync(source, release, progress));
            AppUpdateStatus.Text = "Signature, size and SHA-256 verified. Installing ...";

            var (plan, outcome) = await Task.Run(() =>
            {
                var planned = updater.Plan(staged);
                return (planned, updater.Apply(staged, planned));
            });

            InstallUpdateButton.Visibility = Visibility.Collapsed;
            AppUpdateStatus.Text = $"Updated to {outcome.ToVersion}: {plan.Summary()}. Restart to use it.";
            Append($"ArtefactForge updated {outcome.FromVersion} -> {outcome.ToVersion}: {plan.Summary()}");

            var kept = plan.Paths(ChangeKind.KeepUserCopy).ToList();
            var message = $"ArtefactForge {outcome.ToVersion} is installed: {plan.Summary()}." +
                          (kept.Count == 0 ? "" :
                              "\n\nYou had edited these, so yours were kept and the new versions saved beside them as .new:\n  " +
                              string.Join("\n  ", kept)) +
                          "\n\nRestart now?";

            if (MessageBox.Show(this, message, "Update installed", MessageBoxButton.YesNo, MessageBoxImage.Information)
                == MessageBoxResult.Yes)
            {
                Process.Start(new ProcessStartInfo(Path.Combine(updater.InstallDirectory, "ArtefactForge.exe"))
                {
                    UseShellExecute = true,
                    WorkingDirectory = updater.InstallDirectory
                });
                Application.Current.Shutdown();
            }
        }
        catch (Exception ex)
        {
            // UpdateException messages are written for the analyst; anything else is a network or
            // disk failure, reported as it is. Either way nothing outside _update\ was changed,
            // or it was rolled back.
            AppUpdateStatus.Text = ex.Message;
            MessageBox.Show(this, ex.Message, "Update not installed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            SetAppUpdateBusy(false);
            RunButton.IsEnabled = true;
        }
    }

    private void SetAppUpdateBusy(bool busy)
    {
        CheckAppUpdateButton.IsEnabled = !busy;
        UpdateFromFolderButton.IsEnabled = !busy;
        InstallUpdateButton.IsEnabled = !busy;
    }

    // -------------------------------------------------------------- selection

    private IEnumerable<ModuleItem> AllModules => _allItems;

    /// <summary>
    /// Rebuilds the categories from the master list, for both module views. Selection lives on
    /// the ModuleItem, so filtering never loses a tick - the same instances are re-grouped, not
    /// recreated. Which categories are open is kept by name, so it survives the rebuild.
    /// </summary>
    private void BuildCategories(string filter)
    {
        var railSelection = RailList.SelectedItem as CategoryGroup;
        _platforms.Clear();
        _railCategories.Clear();
        var matches = _allItems.Where(m => Matches(m, filter)).ToList();
        var filtering = !string.IsNullOrWhiteSpace(filter);

        // Windows first, then Linux, then anything platform-agnostic. Fixed order rather than
        // alphabetical: the point is that the two families stay in predictable places.
        foreach (var platform in new[] { Platform.Windows, Platform.Linux, Platform.Any })
        {
            if (platform != Platform.Any && _platformFilter is { } only && only != platform) continue;
            var forPlatform = matches.Where(m => m.Definition.Platform == platform).ToList();
            if (forPlatform.Count == 0) continue;

            var group = new PlatformGroup
            {
                Platform = platform,
                Name = platform == Platform.Any ? "Any platform" : platform.ToString()
            };

            foreach (var byCategory in forPlatform.GroupBy(m => m.Definition.Category).OrderBy(g => g.Key))
            {
                var category = new CategoryGroup { Name = byCategory.Key, Platform = platform };
                foreach (var module in byCategory.OrderBy(m => m.Definition.Priority)) category.Modules.Add(module);

                // A filter opens every category it matched, or the matches would be hidden in
                // collapsed rows; clearing it returns to what the analyst had opened.
                category.IsExpanded = filtering || _expanded.Contains(ExpandKey(category));
                category.PropertyChanged += (_, args) =>
                {
                    if (args.PropertyName != nameof(CategoryGroup.IsExpanded)
                        || !string.IsNullOrWhiteSpace(ModuleFilter.Text)) return;
                    if (category.IsExpanded) _expanded.Add(ExpandKey(category));
                    else _expanded.Remove(ExpandKey(category));
                };
                category.SelectionChanged += UpdateModuleCount;
                category.RefreshSummary();
                group.Categories.Add(category);
                _railCategories.Add(category);
            }

            group.RefreshSummary();
            _platforms.Add(group);
        }

        var several = _platforms.Count > 1;
        foreach (var group in _platforms) group.ShowHeading = several;
        _railView.GroupDescriptions.Clear();
        if (several) _railView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(CategoryGroup.PlatformName)));

        RailList.SelectedItem = _railCategories.FirstOrDefault(c => railSelection is not null
                                                                    && c.Platform == railSelection.Platform
                                                                    && c.Name == railSelection.Name)
                                ?? _railCategories.FirstOrDefault();
        UpdateApplies();
    }

    private static string ExpandKey(CategoryGroup category) => $"{category.Platform}/{category.Name}";

    /// <summary>
    /// "applies to 1 of 3 collections" on each platform group, from the selected collections'
    /// detected platform, and each module dimmed when no selected collection is a target it can
    /// run against. The planner already leaves out what does not apply; this shows it before the
    /// run rather than as skips after it.
    /// </summary>
    private void UpdateApplies()
    {
        var selected = _collections.Where(c => c.IsSelected).ToList();
        foreach (var module in _allItems)
            module.WillRun = selected.Count == 0 || selected.Any(c => RunPlanner.Applies(module.Definition, c.Target));

        foreach (var group in _platforms)
        {
            group.RefreshSummary();
            if (selected.Count == 0) { group.AppliesText = ""; group.HeaderOpacity = 1.0; continue; }

            var applies = selected.Count(c => group.Platform == Platform.Any
                                              || c.Target.Layout.Platform == Platform.Any
                                              || c.Target.Layout.Platform == group.Platform);
            group.AppliesText = $"applies to {applies} of {selected.Count} collection{(selected.Count == 1 ? "" : "s")}";
            group.HeaderOpacity = applies == 0 ? 0.5 : 1.0;
        }
        RefreshCollections();
    }

    /// <summary>
    /// The Collections tab's detail for each collection: how many ticked modules apply to it and
    /// the folder its output will go to. Follows the module ticks, Output, Case name and renames.
    /// </summary>
    private void RefreshCollections()
    {
        var modules = _allItems.Where(m => m.IsSelected).Select(m => m.Definition).ToList();
        var selected = _collections.Where(c => c.IsSelected).ToList();
        // As BuildConfiguration does: a blank case is named after the first collection in the run.
        var caseName = !string.IsNullOrWhiteSpace(CaseName.Text) ? CaseName.Text.Trim()
                       : selected.FirstOrDefault()?.EffectiveTarget.CollectionName ?? "";
        var outputRoot = OutputPath.Text.Trim();

        foreach (var collection in _collections)
        {
            var applies = modules.Count(m => RunPlanner.Applies(m, collection.Target));
            collection.ModuleCount = applies;
            collection.ModulesTooltip =
                $"{applies} of the {modules.Count} ticked modules apply to {collection.Kind} evidence."
                + Environment.NewLine
                + (collection.Target.IsArchive
                    ? "Each checks its artefacts are present once the zip is extracted; any that are not are skipped with a reason."
                    : "Each still checks its artefacts are present; Preview plan lists any that will be skipped.");
            collection.OutputFolder = outputRoot.Length == 0
                ? "(choose an output folder)"
                : Path.Combine(outputRoot, caseName, collection.EffectiveTarget.CollectionName);
        }

        CollectionsTab.Header = _collections.Count == 0 ? "Collections"
                                : selected.Count == _collections.Count ? $"Collections ({_collections.Count})"
                                : $"Collections ({selected.Count} of {_collections.Count})";
        CollectionCount.Text = _collections.Count == 0 ? ""
                               : $"{selected.Count} of {_collections.Count} ticked for this run";
        NoCollections.Visibility = _collections.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnSelectAllCollections(object sender, RoutedEventArgs e)
    {
        foreach (var collection in _collections) collection.IsSelected = true;
    }

    private void OnSelectNoCollections(object sender, RoutedEventArgs e)
    {
        foreach (var collection in _collections) collection.IsSelected = false;
    }

    private void OnSideScrolled(object sender, ScrollChangedEventArgs e) =>
        MoreBelow.Visibility = SideScroller.VerticalOffset < SideScroller.ScrollableHeight - 1
            ? Visibility.Visible
            : Visibility.Collapsed;

    private void OnShowMoreBelow(object sender, RoutedEventArgs e) => SideScroller.ScrollToEnd();

    private static bool Matches(ModuleItem item, string filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return true;
        var needle = filter.Trim();
        return item.Name.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || item.Definition.Category.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || item.Description.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void OnFilterModules(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded && _allItems.Count == 0) return;
        BuildCategories(ModuleFilter.Text);
        UpdateModuleCount();
    }

    /// <summary>
    /// After detection, shows the platform the evidence is: Windows collections bring up the
    /// Windows modules. Mixed or undetected evidence shows them all. The analyst can still switch.
    /// </summary>
    private void ShowPlatformOfEvidence()
    {
        var platforms = _collections.Where(c => c.IsSelected)
                                    .Select(c => c.Target.Layout.Platform)
                                    .Distinct().ToList();
        var radio = platforms is [Platform.Windows] ? PlatformWindows
                    : platforms is [Platform.Linux] ? PlatformLinux
                    : PlatformAll;
        radio.IsChecked = true;
    }

    private void OnPlatformChanged(object sender, RoutedEventArgs e)
    {
        // Fires once while the window is still being built, before the module list exists.
        if (ModuleFilter is null) return;
        _platformFilter = PlatformWindows.IsChecked == true ? Platform.Windows
                          : PlatformLinux.IsChecked == true ? Platform.Linux
                          : null;
        BuildCategories(ModuleFilter.Text);
        UpdateModuleCount();
    }

    private void OnExpandCategories(object sender, RoutedEventArgs e)
    {
        foreach (var category in _railCategories) category.IsExpanded = true;
    }

    private void OnCollapseCategories(object sender, RoutedEventArgs e)
    {
        foreach (var category in _railCategories) category.IsExpanded = false;
    }

    private void UpdateModuleCount()
    {
        // Only the text filter counts as hiding: the other platform is a switch away, not hidden.
        var hidden = _allItems.Count(m => !Matches(m, ModuleFilter.Text));
        var isDefault = _allItems.All(m => m.IsSelected == m.Definition.DefaultEnabled);
        ModuleCount.Text = $"{AllModules.Count(m => m.IsSelected)} of {_allItems.Count} selected"
                           + (isDefault ? " (default)" : "")
                           + (hidden > 0 ? $" · {hidden} hidden" : "");
        foreach (var platform in _platforms) platform.RefreshSummary();

        PlatformWindows.Content = PlatformLabel(Platform.Windows);
        PlatformLinux.Content = PlatformLabel(Platform.Linux);
        RefreshCollections();
    }

    /// <summary>"Windows 27/29" on the platform switch, counted over every module whatever is shown.</summary>
    private string PlatformLabel(Platform platform)
    {
        var modules = _allItems.Where(m => m.Definition.Platform == platform).ToList();
        return $"{platform} {modules.Count(m => m.IsSelected)}/{modules.Count}";
    }

    /// <summary>
    /// Modules currently shown, by the filter and the platform switch. All and None act on these
    /// rather than on every module: filtering to "Linux" and pressing All should select the Linux
    /// modules, not all of them. With no filter and All platforms this is the whole set.
    /// </summary>
    private IEnumerable<ModuleItem> VisibleModules => _railCategories.SelectMany(c => c.Modules);

    /// <summary>
    /// The usual run: every module not marked opt-in, regardless of the filter. There is no need
    /// to pick Windows or Linux - the planner gives each collection only what applies to it, so a
    /// mixed batch needs no per-collection selection. This is also the start-up state.
    /// </summary>
    private void OnSelectDefault(object sender, RoutedEventArgs e)
    {
        foreach (var module in _allItems) module.IsSelected = module.Definition.DefaultEnabled;
        ProfileBox.SelectedIndex = 0;
        UpdateModuleCount();
        SetupStatus.Text = "Default selection: each collection runs what applies to it.";
    }

    private void OnSelectAll(object sender, RoutedEventArgs e)
    {
        // Opt-in modules such as SQLECmd stay unticked: they are excluded deliberately, not by oversight.
        foreach (var module in VisibleModules.Where(m => m.Definition.DefaultEnabled)) module.IsSelected = true;
        UpdateModuleCount();
    }

    private void OnSelectNone(object sender, RoutedEventArgs e)
    {
        // Deselecting only what is shown leaves a selection made under a different filter intact.
        foreach (var module in VisibleModules) module.IsSelected = false;
        UpdateModuleCount();
    }

    private void OnProfileSelected(object sender, SelectionChangedEventArgs e)
    {
        if (ProfileBox.SelectedIndex <= 0 || ProfileBox.SelectedItem is not string name) return;

        var path = Path.Combine(ProfileFile.Directory(_repoRoot), name + ".json");
        if (!File.Exists(path)) return;

        try
        {
            var profile = JsonSerializer.Deserialize<ProfileFile>(File.ReadAllText(path));
            if (profile is null) return;

            var wanted = profile.Modules.ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var module in AllModules) module.IsSelected = wanted.Contains(module.Name);

            // A profile carries how each module was tuned, not just which ones were ticked.
            // Anything the profile does not mention returns to its declared default.
            foreach (var module in AllModules)
            {
                module.OptionValues.Clear();
                if (profile.Options.TryGetValue(module.Name, out var saved))
                    foreach (var (option, value) in saved)
                        if (ModuleOptions.TryValidate(module.Definition, option, value, out _))
                            module.OptionValues[option] = value;
                module.RefreshOptions();
            }
            UpdateModuleCount();
            SetupStatus.Text = $"Loaded profile '{name}'";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Could not load profile");
        }
    }

    private void OnSaveProfile(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save module profile",
            Filter = "Profile (*.json)|*.json",
            InitialDirectory = ProfileFile.Directory(_repoRoot),
            FileName = "profile.json"
        };
        if (dialog.ShowDialog(this) != true) return;

        Directory.CreateDirectory(ProfileFile.Directory(_repoRoot));
        var profile = new ProfileFile
        {
            Name = Path.GetFileNameWithoutExtension(dialog.FileName),
            Modules = AllModules.Where(m => m.IsSelected).Select(m => m.Name).ToList(),
            Options = CollectOptionOverrides()
                .ToDictionary(pair => pair.Key,
                              pair => pair.Value.ToDictionary(o => o.Key, o => o.Value, StringComparer.OrdinalIgnoreCase),
                              StringComparer.OrdinalIgnoreCase)
        };
        File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true }));
        LoadProfiles();
        SetupStatus.Text = $"Saved profile '{profile.Name}'";
    }

    // --------------------------------------------------------------- evidence

    private void OnBrowseEvidence(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select evidence folder or drive" };
        if (dialog.ShowDialog(this) != true) return;
        EvidencePath.Text = dialog.FolderName;
        Detect();
    }

    private void OnBrowseZip(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select a collection archive",
            Filter = "Collection archives (*.zip, *.tar.gz, *.tgz, *.tar)|*.zip;*.tar.gz;*.tgz;*.tar"
        };
        if (dialog.ShowDialog(this) != true) return;
        BatchMode.IsChecked = false;
        EvidencePath.Text = dialog.FileName;
        Detect();
    }

    private void OnBrowseOutput(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select output folder" };
        if (dialog.ShowDialog(this) == true) OutputPath.Text = dialog.FolderName;
    }

    private void OnDetect(object sender, RoutedEventArgs e) => Detect();

    private void Detect()
    {
        _collections.Clear();
        UpdateApplies();
        var path = EvidencePath.Text.Trim();
        if (string.IsNullOrWhiteSpace(path) || !(Directory.Exists(path) || File.Exists(path)))
        {
            DetectionSummary.Text = "Choose an evidence folder or zip to detect its layout.";
            _recalledFor = null;
            _recall = null;
            RecallLine.Visibility = Visibility.Collapsed;
            return;
        }

        RecallOutput(path);

        var discovery = EvidenceDiscovery.Discover(path, BatchMode.IsChecked == true, _layouts);
        var found = discovery.Targets;
        var unmatched = discovery.Unmatched.Count;

        // A single zip that is not a collection says why: encrypted, Velociraptor, not a zip.
        if (found.Count == 0 && File.Exists(path) && discovery.Unmatched.Count > 0)
        {
            DetectionSummary.Text = discovery.Unmatched[0].Reason;
            return;
        }

        var restored = 0;
        foreach (var target in found)
        {
            var item = new CollectionItem { Target = target };
            if (_recall?.NameFor(SourceOf(target)) is { } remembered)
            {
                item.Name = remembered;
                restored++;
            }
            item.PropertyChanged += (_, args) =>
            {
                if (args.PropertyName == nameof(CollectionItem.IsSelected)) UpdateApplies();
                // The output folder shown is named after it, and a blank case is named after the first.
                else if (args.PropertyName == nameof(CollectionItem.Name)) RefreshCollections();
            };
            _collections.Add(item);
        }
        UpdateApplies();
        if (found.Count > 0) ShowPlatformOfEvidence();

        // Batch treats each SUBFOLDER as a collection, so ticking it on a mounted image or a
        // single collection folder finds nothing - the evidence is the folder itself. Say so,
        // rather than leaving 'no layout matched' to be interpreted as unsupported evidence.
        if (found.Count == 0 && BatchMode.IsChecked == true
            && LayoutDetector.Detect(path, _layouts).Count > 0)
        {
            DetectionSummary.Text = "This folder is itself a collection, not a folder of them. "
                                    + "Untick Batch to process it as one host.";
            return;
        }

        // A folder of collections does not itself look like a collection. If this one does, batch
        // would process the drive folder inside it and name the collection after that, e.g. 'C'.
        var batchOnACollection = BatchMode.IsChecked == true && discovery.SelectionIsCollection;

        DetectionSummary.Text = found.Count == 0
            ? "No layout matched. Check the folder, or add a layout profile."
            : $"{found.Count} collection(s) detected · "
              + string.Join(", ", found.GroupBy(t => t.Kind).Select(g => found.Count == 1 ? g.Key : $"{g.Count()} {g.Key}"))
              + (unmatched > 0 ? $" · {unmatched} folder(s) or zip(s) skipped (hover for why)" : "")
              + (restored > 0 ? $" · {restored} name(s) from the last run" : "")
              + (batchOnACollection ? " · this folder looks like a collection itself - untick Batch?" : "");
        // The summary line has room for a count; the hover says which ones and why.
        DetectionSummary.ToolTip = unmatched == 0
            ? null
            : string.Join(Environment.NewLine, discovery.Unmatched.Select(u => Path.GetFileName(u.Path) + ": " + u.Reason));

        if (string.IsNullOrWhiteSpace(CaseName.Text) && found.Count > 0)
        {
            _applyingRecall = true;
            CaseName.Text = found[0].CollectionName;
            _applyingRecall = false;
        }
    }

    // ------------------------------------------------------- remembered output

    /// <summary>
    /// Fills the output folder and case name from this evidence's last run, keeping anything the
    /// analyst typed since the previous evidence was chosen.
    /// </summary>
    private void RecallOutput(string evidencePath)
    {
        var key = Path.TrimEndingDirectorySeparator(Path.GetFullPath(evidencePath));
        if (StringComparer.OrdinalIgnoreCase.Equals(key, _recalledFor)) return;
        _recalledFor = key;
        _recall = OutputMemory.Recall(Preferences.Current.Outputs, key);

        _applyingRecall = true;
        if (!_outputTyped) OutputPath.Text = _recall.OutputRoot ?? DefaultOutput;
        // Cleared rather than kept when nothing is known, so the previous case's name is not
        // carried over to new evidence; detection then fills in the collection's name.
        if (!_caseTyped) CaseName.Text = _recall.CaseName ?? "";
        _applyingRecall = false;

        _outputConfirmed = _outputTyped || _recall.Certainty == RecallCertainty.Remembered;
        _outputTyped = false;
        _caseTyped = false;
        ShowRecall();
    }

    private void OnOutputTyped()
    {
        if (_applyingRecall) return;
        _outputTyped = true;
        if (_recall is null) return;
        // Choosing the folder by hand is a decision about where the output goes.
        _outputConfirmed = true;
        ShowRecall();
    }

    private void OnRecallConfirmed(object sender, RoutedEventArgs e)
    {
        _outputConfirmed = true;
        ShowRecall();
    }

    private void ShowRecall()
    {
        if (_recall is null)
        {
            RecallLine.Visibility = Visibility.Collapsed;
            return;
        }

        var remembered = _recall.Certainty == RecallCertainty.Remembered;
        RecallLine.Visibility = Visibility.Visible;
        RecallMarker.SetResourceReference(System.Windows.Shapes.Shape.FillProperty,
                                          _outputConfirmed ? "SuccessBrush" : "WarningBrush");
        RecallText.Text = _outputConfirmed && !remembered ? "Output location confirmed." : _recall.Message;
        RecallConfirm.Visibility = _outputConfirmed ? Visibility.Collapsed : Visibility.Visible;
        RecallConfirm.IsChecked = false;
    }

    /// <summary>
    /// Asks before a run whose output location was not remembered or chosen by the analyst. Output
    /// in the wrong case folder is hard to untangle, so a guess is never taken silently.
    /// </summary>
    private bool ConfirmOutput(RunConfiguration config)
    {
        if (_outputConfirmed) return true;

        var message = $"Output will be written to:{Environment.NewLine}"
                      + Path.Combine(config.OutputRoot, config.CaseName) + Environment.NewLine + Environment.NewLine
                      + (_recall?.Message ?? "This output location has not been confirmed.") + Environment.NewLine
                      + Environment.NewLine + "Write the output here?";
        var answer = MessageBox.Show(this, message, "Confirm output location",
                                     MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return false;

        _outputConfirmed = true;
        ShowRecall();
        return true;
    }

    private void RememberOutput(RunConfiguration config)
    {
        // Every collection shown, ticked or not, so a rename is kept for the run that includes it.
        var names = _collections
            .Select(c => new CollectionNameChoice(
                SourceOf(c.Target),
                c.EffectiveTarget.CollectionName == c.Target.CollectionName ? null : c.EffectiveTarget.CollectionName))
            .ToList();
        OutputMemory.Record(Preferences.Current.Outputs, EvidencePath.Text, config.OutputRoot,
                            config.CaseName, DateTimeOffset.Now, names);
        SaveRunOptions();
    }

    // ------------------------------------------------------------ run options

    private void LoadRunOptions()
    {
        var saved = Preferences.Current.RunOptions.Clamped();
        Workers.Text = saved.Workers.ToString();
        HeavyWorkers.Text = saved.HeavyWorkers.ToString();
        ZipsAtOnce.Text = saved.ZipsAtOnce.ToString();
        UseVss.IsChecked = saved.Vss;
        SkipCompleted.IsChecked = saved.SkipCompleted;
        CleanupExtracted.IsChecked = saved.CleanupExtracted;
    }

    /// <summary>
    /// Saved at Run and on close. A box left with something that is not a number keeps the value
    /// saved before it, rather than saving a default the analyst never chose.
    /// </summary>
    private void SaveRunOptions()
    {
        var previous = Preferences.Current.RunOptions;
        Preferences.Current.RunOptions = new SavedRunOptions
        {
            Workers = int.TryParse(Workers.Text, out var w) ? w : previous.Workers,
            HeavyWorkers = int.TryParse(HeavyWorkers.Text, out var h) ? h : previous.HeavyWorkers,
            ZipsAtOnce = int.TryParse(ZipsAtOnce.Text, out var z) ? z : previous.ZipsAtOnce,
            Vss = UseVss.IsChecked == true,
            SkipCompleted = SkipCompleted.IsChecked == true,
            CleanupExtracted = CleanupExtracted.IsChecked == true
        }.Clamped();
        Preferences.Save();
    }

    /// <summary>The folder or zip a collection was found as, which is what a rename is remembered by.</summary>
    private static string SourceOf(ResolvedTarget target) => target.ArchivePath ?? target.SelectionPath;

    // -------------------------------------------------------------------- run

    private RunConfiguration? BuildConfiguration()
    {
        // The case name is the top-level output folder, so it needs the same check as the
        // collection names beneath it.
        if (!string.IsNullOrWhiteSpace(CaseName.Text)
            && !CollectionNaming.TryValidate(CaseName.Text, out _, out var caseError))
        {
            MessageBox.Show(this, $"Case name '{CaseName.Text}' cannot be a folder name: {caseError}.",
                            "ArtefactForge", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }

        // Refuse rather than silently falling back to the detected name: a run whose output
        // folder is not what the analyst typed is worse than one that does not start.
        var badName = _collections.FirstOrDefault(c => c.IsSelected && c.HasNameError);
        if (badName is not null)
        {
            MessageBox.Show(this, $"'{badName.Name}' cannot be a folder name: {badName.NameError}.",
                            "ArtefactForge", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }

        var duplicate = _collections.Where(c => c.IsSelected)
                                    .GroupBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
                                    .FirstOrDefault(g => g.Count() > 1);
        if (duplicate is not null)
        {
            // Two collections sharing a name would write into the same folder and interleave output.
            MessageBox.Show(this, $"More than one collection is named '{duplicate.Key}'. Names must be unique.",
                            "ArtefactForge", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }

        var targets = _collections.Where(c => c.IsSelected).Select(c => c.EffectiveTarget).ToList();
        if (targets.Count == 0)
        {
            MessageBox.Show(this, "No collections selected. Choose an evidence folder first.", "ArtefactForge");
            return null;
        }

        var modules = AllModules.Where(m => m.IsSelected).Select(m => m.Definition).ToList();
        if (modules.Count == 0)
        {
            MessageBox.Show(this, "No modules selected.", "ArtefactForge");
            return null;
        }

        if (string.IsNullOrWhiteSpace(OutputPath.Text))
        {
            MessageBox.Show(this, "Choose an output folder.", "ArtefactForge");
            return null;
        }

        var toolRoots = ToolRoots();

        return new RunConfiguration
        {
            CaseName = string.IsNullOrWhiteSpace(CaseName.Text) ? targets[0].CollectionName : CaseName.Text.Trim(),
            OutputRoot = OutputPath.Text.Trim(),
            ToolRoots = toolRoots,
            ScriptsDirectory = Path.Combine(_repoRoot, "Scripts"),
            Targets = targets,
            Modules = modules,
            MaxWorkers = int.TryParse(Workers.Text, out var w) ? w : Environment.ProcessorCount,
            MaxHeavyWorkers = int.TryParse(HeavyWorkers.Text, out var h) ? h : 2,
            Vss = UseVss.IsChecked == true,
            SkipCompleted = SkipCompleted.IsChecked == true,
            Layouts = _layouts,
            CleanupExtracted = CleanupExtracted.IsChecked == true,
            ArchivesAtOnce = int.TryParse(ZipsAtOnce.Text, out var z) && z > 0 ? z : 2
        };
    }

    private void OnPreviewPlan(object sender, RoutedEventArgs e)
    {
        var config = BuildConfiguration();
        if (config is null) return;

        var plan = RunPlanner.Build(config);
        var message = new StringBuilder();
        message.AppendLine($"{plan.Items.Count} work item(s) will run.");
        message.AppendLine();

        foreach (var skip in plan.Skipped.OrderBy(s => s.Module).Take(20))
            message.AppendLine($"skipped  {skip.Module}: {skip.Reason}");

        if (plan.Skipped.Count > 20) message.AppendLine($"... and {plan.Skipped.Count - 20} more");

        MessageBox.Show(this, message.ToString(), "Plan preview");
    }

    private async void OnRun(object sender, RoutedEventArgs e)
    {
        var config = BuildConfiguration();
        if (config is null) return;
        if (!ConfirmOutput(config)) return;
        if (!ConfirmEvidenceListClosed(Path.Combine(config.OutputRoot, config.CaseName))) return;
        RememberOutput(config);

        var plan = RunPlanner.Build(config);
        _progress.Clear();
        _results.Clear();
        _log.Clear();
        LogText.Text = "";

        // Seed the tree from the plan so every module is visible as pending before anything starts.
        var lookup = new Dictionary<string, RunItem>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in plan.Items.GroupBy(i => i.Target.CollectionName))
        {
            var collection = new CollectionProgress { Name = group.Key, PlanIndex = _progress.Count };
            foreach (var item in group.OrderBy(i => i.Module.Priority))
            {
                var runItem = new RunItem { Module = item.Module.Name, Iteration = item.IterationKey };
                collection.Items.Add(runItem);
                lookup[item.Key] = runItem;
            }
            collection.PlaceAll();
            collection.Refresh();
            collection.ApplyAutoExpand();
            _progress.Add(collection);
        }

        // A zip's modules are only known once it is extracted, so it starts with one row for the
        // extraction and gains its modules when the engine reports what it found.
        var extractRows = new Dictionary<string, RunItem>(StringComparer.OrdinalIgnoreCase);
        foreach (var archive in config.Targets.Where(t => t.IsArchive))
        {
            var collection = new CollectionProgress { Name = archive.CollectionName, PlanIndex = _progress.Count };
            var row = new RunItem { Module = "Extract " + Path.GetFileName(archive.ArchivePath) };
            collection.Items.Add(row);
            extractRows[archive.CollectionName] = row;
            collection.PlaceAll();
            collection.Refresh();
            _progress.Add(collection);
        }

        Tabs.SelectedIndex = 1;
        RunButton.IsEnabled = false;
        StopButton.IsEnabled = true;
        _cancellation = new CancellationTokenSource();
        _runStarted = DateTimeOffset.Now;
        _elapsedTimer.Start();
        StatCollections.Text = $"0 / {_progress.Count}";

        var engine = new RunEngine();
        engine.Extraction += evt => Dispatcher.Invoke(() =>
        {
            foreach (var target in evt.Collections)
            {
                if (!extractRows.TryGetValue(target.CollectionName, out var row)) continue;
                var collection = _progress.FirstOrDefault(c => c.Name == target.CollectionName);

                switch (evt.Stage)
                {
                    case ExtractionStage.Extracting:
                        row.Status = WorkStatus.Running;
                        row.Detail = evt.BytesTotal == 0
                            ? "checking the zip"
                            : $"{evt.BytesDone / (1024 * 1024):N0} of {evt.BytesTotal / (1024 * 1024):N0} MB";
                        break;
                    case ExtractionStage.Extracted:
                        row.Status = WorkStatus.Completed;
                        row.Detail = "";
                        foreach (var item in (evt.Planned ?? []).Where(i => i.Target.CollectionName == target.CollectionName)
                                                                 .OrderBy(i => i.Module.Priority))
                        {
                            var runItem = new RunItem { Module = item.Module.Name, Iteration = item.IterationKey };
                            collection?.Items.Add(runItem);
                            lookup[item.Key] = runItem;
                        }
                        break;
                    case ExtractionStage.Failed:
                        row.Status = WorkStatus.Failed;
                        row.Detail = evt.Message ?? "";
                        break;
                    case ExtractionStage.Skipped:
                        row.Status = WorkStatus.Skipped;
                        row.Detail = evt.Message ?? "";
                        break;
                }

                if (collection is null) continue;
                collection.PlaceAll();
                collection.Refresh();
                collection.ApplyAutoExpand();
                Reorder(collection);
            }

            if (evt.Stage == ExtractionStage.Failed)
                Append($"[Failed] extracting {Path.GetFileName(evt.ArchivePath)}: {evt.Message}");
            else if (evt.Stage == ExtractionStage.CleanedUp)
                Append($"[Cleanup] {evt.Message}");
            else if (evt.Stage == ExtractionStage.Extracted)
                Append($"[Extracted] {Path.GetFileName(evt.ArchivePath)}");
            else if (evt.Stage == ExtractionStage.Skipped)
                Append($"[Skipped] {Path.GetFileName(evt.ArchivePath)}: {evt.Message}");
            UpdateRunStats();
        });
        engine.Progress += evt => Dispatcher.Invoke(() =>
        {
            if (!lookup.TryGetValue(evt.Item.Key, out var runItem)) return;

            runItem.Status = evt.Status;
            runItem.Detail = evt.Message ?? "";

            var collection = _progress.FirstOrDefault(c => c.Name == evt.Item.Target.CollectionName);
            if (collection is not null)
            {
                collection.Place(runItem);
                collection.Refresh();
                collection.ApplyAutoExpand();
                Reorder(collection);
            }

            if (evt.Status != WorkStatus.Running) Append($"[{evt.Status}] {evt.Item.Label}");
            UpdateRunStats();
        });

        try
        {
            var report = await engine.RunAsync(config, _cancellation.Token);
            _results.AddRange(report.Results);
            _lastCaseDirectory = report.CaseDirectory;
            ShowResults();
            ShowEvidenceList(report.EvidenceList);
            Append($"Finished in {report.DurationSeconds:F1}s. {report.NeedsReview} item(s) need review.");
            if (report.EvidenceList is { } list) Append(list.Describe());
        }
        catch (Exception ex)
        {
            Append("Run failed: " + ex.Message);
            MessageBox.Show(this, ex.Message, "Run failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _elapsedTimer.Stop();
            RunButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            UpdateRunStats();
            RefreshIocs();
            RefreshRdp();
        }
    }

    /// <summary>
    /// Keeps running collections at the top, then those needing attention or not started, then
    /// finished clean. Plan order within a band, and only a collection whose band changed moves.
    /// </summary>
    private void Reorder(CollectionProgress collection)
    {
        var from = _progress.IndexOf(collection);
        var to = _progress.Count(c => c != collection &&
                                      (c.Band < collection.Band ||
                                       (c.Band == collection.Band && c.PlanIndex < collection.PlanIndex)));
        if (from >= 0 && from != to) _progress.Move(from, to);
    }

    private void OnProgressActiveOnly(object sender, RoutedEventArgs e)
    {
        foreach (var collection in _progress) collection.ResetView();
    }

    private void OnProgressExpandAll(object sender, RoutedEventArgs e)
    {
        foreach (var collection in _progress) collection.ExpandAll(true);
    }

    private void OnProgressCollapseAll(object sender, RoutedEventArgs e)
    {
        foreach (var collection in _progress) collection.ExpandAll(false);
    }

    private void UpdateRunStats()
    {
        var items = _progress.SelectMany(c => c.Items).ToList();
        StatCompleted.Text = items.Count(i => i.Status == WorkStatus.Completed).ToString();
        StatReview.Text = items.Count(i => i.IsProblem).ToString();
        StatCollections.Text = $"{_progress.Count(c => c.IsFinished)} / {_progress.Count}";
    }

    private void OnStop(object sender, RoutedEventArgs e)
    {
        _cancellation?.Cancel();
        Append("Cancelling - running tools are being killed.");
        StopButton.IsEnabled = false;
    }

    private void Append(string line)
    {
        _log.AppendLine($"{DateTime.Now:HH:mm:ss}  {line}");
        LogText.Text = _log.ToString();
        LogScroller.ScrollToEnd();
    }

    // ---------------------------------------------------------------- results

    private void ShowResults()
    {
        var rows = _results.AsEnumerable();
        if (OnlyProblems.IsChecked == true)
            rows = rows.Where(r => r.Status is WorkStatus.Failed or WorkStatus.NoOutput or WorkStatus.CheckLog
                                            or WorkStatus.ToolMissing or WorkStatus.TimedOut);

        var list = rows.OrderBy(r => r.Collection).ThenBy(r => r.Category).ThenBy(r => r.Module).ToList();
        ResultsGrid.ItemsSource = list;
        ResultsSummary.Text = $"{list.Count} of {_results.Count} shown";
    }

    private void OnFilterResults(object sender, RoutedEventArgs e) => ShowResults();

    private void OnOpenOutput(object sender, RoutedEventArgs e) => Open(_lastCaseDirectory ?? OutputPath.Text);

    private void OnOpenManifest(object sender, RoutedEventArgs e)
    {
        if (_lastCaseDirectory is null) return;
        Open(Path.Combine(_lastCaseDirectory, "_Logs", "manifest.csv"));
    }

    private void OnOpenLogs(object sender, RoutedEventArgs e)
    {
        if (_lastCaseDirectory is null) return;
        Open(Path.Combine(_lastCaseDirectory, "_Logs"));
    }

    // ---------------------------------------------------------------- evidence list

    /// <summary>
    /// Warns when the case's evidence list is open, as Excel locks it and the run cannot add the
    /// new collections to it. Carrying on is allowed: the list is marked out of date and can be
    /// rebuilt from the results page once it is closed.
    /// </summary>
    private bool ConfirmEvidenceListClosed(string caseDirectory)
    {
        if (!EvidenceList.IsOpen(caseDirectory)) return true;

        var message = $"{EvidenceList.FileName} is open in another program, probably Excel."
                      + Environment.NewLine + Environment.NewLine
                      + "Save and close it so this run can add new collections to it. Only saved "
                      + "changes are kept; edits not yet saved in Excel are not seen."
                      + Environment.NewLine + Environment.NewLine
                      + "Run anyway? The evidence list will be left out of date until you rebuild it.";
        var answer = MessageBox.Show(this, message, "Evidence list is open",
                                     MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        return answer == MessageBoxResult.Yes;
    }

    /// <summary>The case the results page acts on: the last run's, else the one set up to run.</summary>
    private string? ResultsCaseDirectory()
    {
        if (_lastCaseDirectory is not null) return _lastCaseDirectory;
        if (string.IsNullOrWhiteSpace(OutputPath.Text) || string.IsNullOrWhiteSpace(CaseName.Text)) return null;
        return Path.Combine(OutputPath.Text.Trim(), CaseName.Text.Trim());
    }

    private void ShowEvidenceList(EvidenceListResult? result)
    {
        EvidenceListStatus.Text = result?.Describe() ?? "";
        var brush = result?.Outcome switch
        {
            EvidenceListOutcome.Locked => "WarningBrush",
            EvidenceListOutcome.Failed => "ErrorBrush",
            _ => null
        };
        if (brush is null) EvidenceListStatus.ClearValue(TextBlock.ForegroundProperty);
        else EvidenceListStatus.SetResourceReference(TextBlock.ForegroundProperty, brush);
    }

    private void OnOpenEvidenceList(object sender, RoutedEventArgs e)
    {
        if (ResultsCaseDirectory() is not { } caseDirectory) return;
        var path = EvidenceList.PathFor(caseDirectory);
        if (!File.Exists(path))
        {
            MessageBox.Show(this, $"There is no evidence list in {caseDirectory} yet. Run the case, or "
                                  + "press Rebuild evidence list to make one from what is already processed.",
                            "No evidence list");
            return;
        }
        Open(path);
    }

    private async void OnRebuildEvidenceList(object sender, RoutedEventArgs e)
    {
        if (ResultsCaseDirectory() is not { } caseDirectory || !Directory.Exists(caseDirectory))
        {
            MessageBox.Show(this, "Choose the output folder and case name on the Setup page, or run the "
                                  + "case first, so there is a case folder to list.", "No case folder");
            return;
        }

        RebuildEvidenceListButton.IsEnabled = false;
        try
        {
            var result = await Task.Run(() => EvidenceList.Rebuild(caseDirectory));
            ShowEvidenceList(result);
        }
        finally
        {
            RebuildEvidenceListButton.IsEnabled = true;
        }
    }

    private void OnRerunFailed(object sender, RoutedEventArgs e)
    {
        // Failed work is never written to the state file, so a normal run with skip-completed on
        // retries exactly the failures and leaves finished work alone.
        SkipCompleted.IsChecked = true;
        Tabs.SelectedIndex = 0;
        SetupStatus.Text = "Press Run to retry the items that did not complete.";
    }

    private static void Open(string path)
    {
        try
        {
            if (!File.Exists(path) && !Directory.Exists(path)) return;
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Could not open");
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        _cancellation?.Cancel();
        SaveRunOptions();
        base.OnClosing(e);
    }

    private static string? FindRepoRoot(string start)
    {
        for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "Layouts")) &&
                Directory.Exists(Path.Combine(dir.FullName, "Modules")))
                return dir.FullName;
        }
        return null;
    }
}
