using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using ArtefactForge.Core;

namespace ArtefactForge.Gui;

public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return;
        field = value;
        Raise(name);
    }

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class ModuleItem : Observable
{
    private bool _isSelected;
    private bool _willRun = true;

    public required ModuleDefinition Definition { get; init; }
    public string Name => Definition.Name;
    public string Description => Definition.Description;

    /// <summary>Overrides for this module's declared options. Empty means "use the defaults".</summary>
    public Dictionary<string, string> OptionValues { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool HasOptions => Definition.Options.Count > 0;

    /// <summary>
    /// Marked when the analyst has moved an option off its default, so a tuned module is obvious
    /// in the list rather than hidden behind a dialog nobody opens.
    /// </summary>
    public bool IsTuned =>
        ModuleOptions.Expand(Definition, OptionValues) != ModuleOptions.Expand(Definition);

    public string OptionsTooltip => Definition.Options.Count == 0
        ? ""
        : "Flags: " + (ModuleOptions.Expand(Definition, OptionValues) is { Length: > 0 } f ? f : "(none)");

    public bool HasNoOptions => Definition.Options.Count == 0;

    private IReadOnlyList<OptionItem>? _optionItems;

    /// <summary>The declared options as editors, for the full screen rail's module cards.</summary>
    public IReadOnlyList<OptionItem> OptionItems =>
        _optionItems ??= Definition.Options.Select(o => new OptionItem(this, o)).ToList();

    public int ChangedOptionCount => OptionItems.Count(o => o.IsChanged);
    public bool HasChangedOptions => ChangedOptionCount > 0;
    public string ChangedText => $"{ChangedOptionCount} changed";

    /// <summary>After OptionValues was replaced from outside: the dialog, a profile, Reset all.</summary>
    public void RefreshOptions()
    {
        foreach (var option in OptionItems) option.Refresh();
        OptionsEdited();
    }

    /// <summary>After one option was edited in place; the editor's own value is already current.</summary>
    internal void OptionsEdited()
    {
        Raise(nameof(IsTuned));
        Raise(nameof(OptionsTooltip));
        Raise(nameof(ChangedOptionCount));
        Raise(nameof(HasChangedOptions));
        Raise(nameof(ChangedText));
    }

    /// <summary>Disk-bound or memory-hungry: the run limits how many of these go at once.</summary>
    public bool IsHeavy =>
        Definition.IoWeight == IoWeight.Heavy || Definition.MemoryWeight == MemoryWeight.Heavy;

    public string HeavyTooltip => Definition.MemoryWeight == MemoryWeight.Heavy
        ? "Heavy: can use GBs of memory, so these run side by side only as far as the memory free when the run starts allows"
        : "Heavy: disk-bound, so only as many run at once as Heavy IO allows";

    /// <summary>Opt-in modules are left out of Default and All; the row says so.</summary>
    public bool IsOptIn => !Definition.DefaultEnabled;

    /// <summary>Which kind of target the module runs against, in the words of the column.</summary>
    public string RunsOn => Definition.Scope switch
    {
        TargetScope.LiveOnly => "Live only",
        TargetScope.OfflineOnly => "Collected",
        _ => "Both"
    };

    public string RunsOnTooltip => Definition.Scope switch
    {
        TargetScope.LiveOnly => "Runs only against a live system",
        TargetScope.OfflineOnly => "Runs only against a collection or mounted image",
        _ => "Runs against live systems and collections"
    };

    /// <summary>
    /// False when none of the selected collections is a target this module can run against, so
    /// the row is dimmed before the run instead of the module appearing only as a skip after it.
    /// True while nothing is detected: with no evidence there is nothing to rule out.
    /// </summary>
    public bool WillRun
    {
        get => _willRun;
        set
        {
            Set(ref _willRun, value);
            Raise(nameof(RowOpacity));
            Raise(nameof(RowTooltip));
        }
    }

    public double RowOpacity => _willRun ? 1.0 : 0.45;

    public string RowTooltip => _willRun
        ? Description
        : Description + Environment.NewLine + "Will not run: none of the selected collections is a target it applies to.";

    public bool IsSelected
    {
        get => _isSelected;
        set => Set(ref _isSelected, value);
    }
}

/// <summary>
/// One declared option of a module, edited in place on the full screen rail. The value lives in the
/// module's OptionValues, as the Module options dialog keeps it, so either way of editing sees the
/// other's changes and a profile saves both.
/// </summary>
public sealed class OptionItem(ModuleItem module, ModuleOption option) : Observable
{
    private const string NotSet = "(not set)";

    public ModuleOption Option { get; } = option;
    public string Name => Option.Name;
    public string Help => Option.Description ?? "";
    public bool IsFlag => Option.Kind == OptionKind.Flag;
    public bool IsChoice => Option.Kind == OptionKind.Choice;
    public bool IsText => Option.Kind == OptionKind.Text;

    // An empty choice is how an option is switched off; label it so it is pickable.
    public IReadOnlyList<string> Choices => Option.Choices.Select(Display).ToList();

    public string Value
    {
        get => module.OptionValues.TryGetValue(Option.Name, out var value) ? value : Option.Default;
        set
        {
            if (value == Value) return;
            module.OptionValues[Option.Name] = value;
            Edited();
        }
    }

    public bool IsOn
    {
        get => IsTrue(Value);
        set => Value = value ? "true" : "false";
    }

    public string Choice
    {
        get => Display(Option.Choices.FirstOrDefault(
                   c => string.Equals(c, Value, StringComparison.OrdinalIgnoreCase)) ?? Value);
        set => Value = value is null or NotSet ? "" : value;
    }

    /// <summary>The same test the run uses to decide which overrides to send.</summary>
    public bool IsChanged => IsFlag
        ? IsTrue(Value) != IsTrue(Option.Default)
        : !string.Equals(Value, Option.Default, StringComparison.OrdinalIgnoreCase);

    public string DefaultText => "Default: " + (IsFlag ? (IsTrue(Option.Default) ? "on" : "off")
                                                : Option.Default.Length == 0 ? NotSet
                                                : Option.Default) + ".";

    public void Reset()
    {
        module.OptionValues.Remove(Option.Name);
        Refresh();
        module.OptionsEdited();
    }

    public void Refresh()
    {
        Raise(nameof(Value));
        Raise(nameof(IsOn));
        Raise(nameof(Choice));
        Raise(nameof(IsChanged));
    }

    private void Edited()
    {
        Refresh();
        module.OptionsEdited();
    }

    private static string Display(string choice) => choice.Length == 0 ? NotSet : choice;

    private static bool IsTrue(string value) =>
        value.Equals("true", StringComparison.OrdinalIgnoreCase)
        || value.Equals("yes", StringComparison.OrdinalIgnoreCase)
        || value == "1";
}

/// <summary>How much of a category is selected, for the count pill in the rail view.</summary>
public enum SelectionState { None, Some, All }

public sealed class CategoryGroup : Observable
{
    private bool _isExpanded;

    public required string Name { get; init; }
    public required Platform Platform { get; init; }
    public string PlatformName => Platform == Platform.Any ? "Any platform" : Platform.ToString();
    public ObservableCollection<ModuleItem> Modules { get; } = [];

    /// <summary>Raised when the category tick changes every module in it.</summary>
    public event Action? SelectionChanged;

    private int SelectedCount => Modules.Count(m => m.IsSelected);

    public string Summary => $"{SelectedCount} of {Modules.Count}";
    public string ShortSummary => $"{SelectedCount}/{Modules.Count}";

    public SelectionState State =>
        SelectedCount == 0 ? SelectionState.None
        : SelectedCount == Modules.Count ? SelectionState.All
        : SelectionState.Some;

    /// <summary>
    /// The category tick: true when every module is selected, false when none is, null (shown as
    /// a dash) for some. Ticking it selects every module in the category, opt-in ones included:
    /// unlike All, it is a deliberate choice about this category.
    /// </summary>
    public bool? IsChecked
    {
        get => State switch { SelectionState.All => true, SelectionState.None => false, _ => null };
        set
        {
            // A two-state CheckBox clicked on its dash asks for false. Fill the category instead,
            // as Windows does, so the order is some -> all -> none rather than some -> none.
            var on = value == true || State == SelectionState.Some;
            foreach (var module in Modules) module.IsSelected = on;
            RefreshSummary();
            SelectionChanged?.Invoke();
        }
    }

    /// <summary>The rail view's switch: on selects the whole category, off clears it.</summary>
    public bool IsAllSelected
    {
        get => State == SelectionState.All;
        set => IsChecked = value;
    }

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            Set(ref _isExpanded, value);
            Raise(nameof(ShowNote));
            Raise(nameof(ShowRunsOn));
            Raise(nameof(ShowHeavy));
        }
    }

    /// <summary>The full screen list's Runs on for a collapsed row: the shared value, or Mixed.</summary>
    public string RunsOnSummary => Modules.Select(m => m.RunsOn).Distinct().ToList() is [var only] ? only : "Mixed";

    public bool ShowRunsOn => !_isExpanded;

    /// <summary>A collapsed row is Heavy if any module in it is; opened, each module says so itself.</summary>
    public bool ShowHeavy => !_isExpanded && Modules.Any(m => m.IsHeavy);

    /// <summary>The blue dot on the full screen rail: a module here has options off their defaults.</summary>
    public bool HasChangedOptions => Modules.Any(m => m.HasChangedOptions);

    public void RefreshOptions() => Raise(nameof(HasChangedOptions));

    /// <summary>
    /// What a collapsed row would otherwise hide: modules switched off, and selected modules that
    /// will not run on the chosen evidence. Empty for a category that is simply all on.
    /// </summary>
    public string Note
    {
        get
        {
            var parts = new List<string>();
            var off = Modules.Where(m => !m.IsSelected).ToList();
            if (off.Count > 0 && off.Count < Modules.Count)
                parts.Add(off.Count <= 2 ? string.Join(", ", off.Select(m => m.Name)) + " off" : $"{off.Count} off");

            var idle = Modules.Count(m => m.IsSelected && !m.WillRun);
            if (idle > 0) parts.Add($"{idle} will not run on this evidence");
            return string.Join(" · ", parts);
        }
    }

    public bool ShowNote => !_isExpanded && Note.Length > 0;

    public void RefreshSummary()
    {
        Raise(nameof(Summary));
        Raise(nameof(ShortSummary));
        Raise(nameof(State));
        Raise(nameof(IsChecked));
        Raise(nameof(IsAllSelected));
        Raise(nameof(Note));
        Raise(nameof(ShowNote));
    }
}

/// <summary>
/// Categories grouped by the operating system they parse. Sorted alphabetically the Linux
/// categories fall between JumpLists and LNKFiles, which is how a module gets missed - the outer
/// group, and the platform switch above the list, keep the two families apart.
/// </summary>
public sealed class PlatformGroup : Observable
{
    private string _applies = "";
    private double _headerOpacity = 1.0;

    public required string Name { get; init; }
    public Platform Platform { get; init; }

    /// <summary>Whether the list view shows this group's heading: only when more than one platform is shown.</summary>
    public bool ShowHeading { get; set; }

    /// <summary>"applies to 1 of 3 collections" - empty until evidence has been detected.</summary>
    public string AppliesText
    {
        get => _applies;
        set => Set(ref _applies, value);
    }

    /// <summary>
    /// Dimmed only when the group applies to none of the selected collections - the single-OS case.
    /// With mixed evidence nothing dims, because every group applies to something.
    /// </summary>
    public double HeaderOpacity
    {
        get => _headerOpacity;
        set => Set(ref _headerOpacity, value);
    }
    public ObservableCollection<CategoryGroup> Categories { get; } = [];

    public int Total => Categories.Sum(c => c.Modules.Count);
    public int Selected => Categories.Sum(c => c.Modules.Count(m => m.IsSelected));
    public string Summary => $"{Selected} of {Total}";

    public void RefreshSummary()
    {
        foreach (var category in Categories) category.RefreshSummary();
        Raise(nameof(Summary));
    }
}

public sealed class CollectionItem : Observable
{
    private bool _isSelected = true;
    private string? _name;
    private string? _nameError;
    private int _moduleCount;
    private string _modulesTooltip = "";
    private string _outputFolder = "";

    public required ResolvedTarget Target { get; init; }

    /// <summary>
    /// Editable. A mounted image is named after whichever drive letter was free at mount time,
    /// which says nothing about the host; the analyst usually knows it. Editable per collection
    /// rather than as one setting, so a batch of images can each be named.
    /// </summary>
    public string Name
    {
        get => _name ??= Target.CollectionName;
        set
        {
            Set(ref _name, value);
            NameError = CollectionNaming.TryValidate(value, out _, out var error) ? null : error;
        }
    }

    /// <summary>Why the current name cannot be a folder, or null when it is fine.</summary>
    public string? NameError
    {
        get => _nameError;
        private set { Set(ref _nameError, value); Raise(nameof(HasNameError)); }
    }

    public bool HasNameError => _nameError is not null;

    /// <summary>The target under whatever name is currently entered.</summary>
    public ResolvedTarget EffectiveTarget =>
        CollectionNaming.TryValidate(Name, out var name, out _) && name != Target.CollectionName
            ? Target.Renamed(name)
            : Target;
    public string Root => Target.Root;
    /// <summary>What was detected, then how: "Windows, collected - Collection folder (drive-letter root)".</summary>
    public string Layout => Target.Kind + " - " + LayoutName;

    public string Kind => Target.Kind;
    public string LayoutName => Target.Layout.Name + (Target.Layout.Provisional ? " (provisional)" : "");
    public string LayoutTooltip => Target.Layout.Provisional
        ? LayoutName + ": written from documentation, not yet checked against a real collection"
        : LayoutName;

    private string SourcePath => Target.ArchivePath ?? Target.SelectionPath;

    /// <summary>A zip's size, as extracting it needs that much again; empty for a folder.</summary>
    private string SizeSuffix =>
        File.Exists(SourcePath) ? $" ({FormatSize(new FileInfo(SourcePath).Length)})" : "";

    /// <summary>
    /// The folder or zip it was found as, from its parent down. Trimmed at the end, a full path
    /// loses the one part that tells collections apart; the whole path is in the tooltip.
    /// </summary>
    public string SourceText => ShortPath(SourcePath) + SizeSuffix;

    public string SourceTooltip => Target.IsArchive
        ? SourcePath + SizeSuffix
        : SourcePath + Environment.NewLine + "Root: " + Target.Root;

    /// <summary>The case and collection folders; the output root is the Output box above.</summary>
    public string OutputText => ShortPath(_outputFolder);

    private static string ShortPath(string path)
    {
        var parts = path.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length <= 2 ? path : "…" + Path.DirectorySeparatorChar + Path.Combine(parts[^2], parts[^1]);
    }

    private static string FormatSize(long bytes) =>
        bytes >= 1L << 30 ? $"{bytes / (double)(1L << 30):F1} GB"
        : bytes >= 1L << 20 ? $"{bytes / (double)(1L << 20):F0} MB"
        : $"{Math.Max(1, bytes / 1024)} KB";

    /// <summary>How many of the ticked modules apply to this kind of evidence. Set by the window.</summary>
    public int ModuleCount
    {
        get => _moduleCount;
        set { Set(ref _moduleCount, value); Raise(nameof(ModulesText)); }
    }

    public string ModulesText => _moduleCount == 0 ? "none" : _moduleCount.ToString();

    public string ModulesTooltip
    {
        get => _modulesTooltip;
        set => Set(ref _modulesTooltip, value);
    }

    /// <summary>Output root, case and collection name, as the run will write them. Set by the window.</summary>
    public string OutputFolder
    {
        get => _outputFolder;
        set { Set(ref _outputFolder, value); Raise(nameof(OutputText)); }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set { Set(ref _isSelected, value); Raise(nameof(RowOpacity)); }
    }

    public double RowOpacity => _isSelected ? 1.0 : 0.5;
}

/// <summary>One module run, as shown under its collection in the run view.</summary>
public sealed class RunItem : Observable
{
    private WorkStatus _status = WorkStatus.Pending;
    private string _detail = "";

    public required string Module { get; init; }
    public string? Iteration { get; init; }
    public string Label => Iteration is null ? Module : $"{Module} [{Iteration}]";

    public WorkStatus Status
    {
        get => _status;
        set { Set(ref _status, value); Raise(nameof(StatusText)); Raise(nameof(IsProblem)); }
    }

    public string Detail
    {
        get => _detail;
        set => Set(ref _detail, value);
    }

    public string StatusText => Status switch
    {
        WorkStatus.Running => "running",
        WorkStatus.Completed => "done",
        WorkStatus.NoOutput => "no output",
        WorkStatus.CheckLog => "check log",
        WorkStatus.ToolMissing => "tool missing",
        WorkStatus.TimedOut => "timed out",
        WorkStatus.Failed => "failed",
        WorkStatus.Skipped => "skipped",
        WorkStatus.Cancelled => "cancelled",
        _ => "waiting"
    };

    /// <summary>Statuses that mean the output cannot be trusted without a look.</summary>
    public bool IsProblem => Status is WorkStatus.Failed or WorkStatus.NoOutput or WorkStatus.CheckLog
                                     or WorkStatus.ToolMissing or WorkStatus.TimedOut;

    /// <summary>Which status group the run view shows this under.</summary>
    public StatusBucket Bucket => Status switch
    {
        WorkStatus.Pending => StatusBucket.Waiting,
        WorkStatus.Running => StatusBucket.Processing,
        _ when IsProblem => StatusBucket.NeedsReview,
        _ => StatusBucket.Completed      // Completed, Skipped, Cancelled
    };
}

/// <summary>The groups under each collection in the run view, in display order.</summary>
public enum StatusBucket { Processing, NeedsReview, Waiting, Completed }

/// <summary>
/// Shared by collections and status groups: expanded state that follows the run automatically
/// until the analyst clicks it, after which it stays where they put it.
/// </summary>
public abstract class AutoExpandable : Observable
{
    private bool _isExpanded;
    private bool _applying;

    /// <summary>Bound two-way to the Expander. A change that did not come from AutoExpand is a click.</summary>
    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (_isExpanded == value) return;
            _isExpanded = value;
            Raise();
            if (!_applying) UserTouched = true;
        }
    }

    /// <summary>Set once the analyst has expanded or collapsed this by hand.</summary>
    public bool UserTouched { get; set; }

    /// <summary>Sets the state on the analyst's behalf, unless they have already chosen one.</summary>
    public void AutoExpand(bool expanded)
    {
        if (UserTouched) return;
        _applying = true;
        try { IsExpanded = expanded; }
        finally { _applying = false; }
    }

    /// <summary>Expand all / Collapse all: a deliberate choice, so it sticks like a click.</summary>
    public void Choose(bool expanded)
    {
        _applying = true;
        try { IsExpanded = expanded; }
        finally { _applying = false; }
        UserTouched = true;
    }
}

public sealed class StatusGroup(StatusBucket bucket) : AutoExpandable
{
    public StatusBucket Bucket { get; } = bucket;
    public ObservableCollection<RunItem> Items { get; } = [];

    public string Title => Bucket switch
    {
        StatusBucket.Processing => "Processing",
        StatusBucket.NeedsReview => "Needs review",
        StatusBucket.Waiting => "Waiting",
        _ => "Completed"
    };

    public int Count => Items.Count;
    public bool HasItems => Items.Count > 0;
    public string Header => $"{Title} ({Items.Count})";

    /// <summary>Open by default: only what is running now. Needs review shows its count in amber, closed.</summary>
    public bool OpenByDefault => Bucket is StatusBucket.Processing;

    public void Changed()
    {
        Raise(nameof(Count));
        Raise(nameof(HasItems));
        Raise(nameof(Header));
    }
}

public sealed class CollectionProgress : AutoExpandable
{
    public required string Name { get; init; }

    /// <summary>Position in the plan, so collections in the same band keep a stable order.</summary>
    public int PlanIndex { get; init; }

    /// <summary>Every module run, in plan order. Totals and the stat cards read this, not the groups.</summary>
    public ObservableCollection<RunItem> Items { get; } = [];

    /// <summary>The same runs, split by status: Processing, Needs review, Waiting, Completed.</summary>
    public IReadOnlyList<StatusGroup> Groups { get; } =
        Enum.GetValues<StatusBucket>().Select(b => new StatusGroup(b)).ToList();

    private StatusGroup Group(StatusBucket bucket) => Groups[(int)bucket];

    /// <summary>
    /// Puts an item in the group its status belongs to, keeping plan order within the group so
    /// rows do not jump about as their neighbours change state.
    /// </summary>
    public void Place(RunItem item)
    {
        var target = Group(item.Bucket);
        foreach (var group in Groups)
            if (group != target && group.Items.Remove(item)) group.Changed();

        if (target.Items.Contains(item)) return;

        var planIndex = Items.IndexOf(item);
        var at = 0;
        while (at < target.Items.Count && Items.IndexOf(target.Items[at]) < planIndex) at++;
        target.Items.Insert(at, item);
        target.Changed();
    }

    public void PlaceAll()
    {
        foreach (var item in Items) Place(item);
    }

    /// <summary>
    /// Default view: a collection is open only while something in it is running, and within it only
    /// Processing is open. Anything clicked by hand is left alone.
    /// </summary>
    public void ApplyAutoExpand()
    {
        foreach (var group in Groups) group.AutoExpand(group.OpenByDefault);
        AutoExpand(Group(StatusBucket.Processing).HasItems);
    }

    /// <summary>Active only: forget every click and go back to the default view.</summary>
    public void ResetView()
    {
        UserTouched = false;
        foreach (var group in Groups) group.UserTouched = false;
        ApplyAutoExpand();
    }

    public void ExpandAll(bool expanded)
    {
        Choose(expanded);
        // Empty groups are left to the default, so a group that fills later follows the default view.
        foreach (var group in Groups.Where(g => g.HasItems)) group.Choose(expanded);
    }

    /// <summary>Sort band: running first, then needing attention or not yet started, finished clean last.</summary>
    public int Band =>
        Group(StatusBucket.Processing).HasItems ? 0
        : IsFinished && Problems == 0 ? 2
        : 1;

    /// <summary>'Processing 2 · Waiting 41 · Completed 12' - where a collapsed collection has got to.</summary>
    public string GroupSummary => string.Join(" \u00B7 ",
        Groups.Where(g => g.HasItems).Select(g => $"{g.Title} {g.Count}"));

    public int Done => Items.Count(i => i.Status is not (WorkStatus.Pending or WorkStatus.Running));
    public int Total => Items.Count;
    public int Problems => Items.Count(i => i.IsProblem);

    public string Summary => Problems > 0
        ? $"{Done} of {Total} · {Problems} need review"
        : $"{Done} of {Total}";

    /// <summary>True once nothing is left running, so the analyst knows it is safe to open.</summary>
    public bool IsFinished => Total > 0 && Done == Total;

    public string State => IsFinished ? (Problems > 0 ? "finished, review" : "finished") : "working";

    public void Refresh()
    {
        Raise(nameof(Done));
        Raise(nameof(Summary));
        Raise(nameof(IsFinished));
        Raise(nameof(State));
        Raise(nameof(Problems));
        Raise(nameof(GroupSummary));
        Raise(nameof(Band));
    }
}
