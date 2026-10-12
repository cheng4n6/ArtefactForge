using ArtefactForge.Core;
using ArtefactForge.Core.Update;

// ArtefactForge command line. The GUI drives the same engine; this is the headless face of it.
var repoRoot = FindRepoRoot(AppContext.BaseDirectory) ?? Directory.GetCurrentDirectory();

// Leftovers from an in-place update (the old exe renamed aside while it was running).
SelfUpdater.CleanUpAfterUpdate(Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory);
var options = CommandLine.Parse(args);
var verb = args.Length > 0 ? args[0].ToLowerInvariant() : "help";

switch (verb)
{
    case "detect": return Detect(options.Positional.ElementAtOrDefault(0));
    case "modules": return ListModules();
    case "profiles": return ListProfiles();
    case "tools": return ListTools(options);
    case "options": return ListOptions(options.Positional.ElementAtOrDefault(0));
    case "version": case "--version": Console.WriteLine(BuildInfo.Describe()); return 0;
    case "plan": return Plan(options);
    case "run": return await Run(options);
    case "evidence-list": return RebuildEvidenceList(options.Positional.ElementAtOrDefault(0));
    case "update": return await Update(options);
    case "release": return Release(options);
    default:
        Console.WriteLine(BuildInfo.Describe() + " - forensic artefact processing");
        Console.WriteLine();
        Console.WriteLine("  detect <path>                     resolve an evidence path to a drive root");
        Console.WriteLine("  modules                           list module definitions");
        Console.WriteLine("  profiles                          list saved module profiles");
        Console.WriteLine("  tools                             show which tools the modules need, and whether they are present");
        Console.WriteLine("  options [module]                  show the switches a module exposes, and their defaults");
        Console.WriteLine("  version                           print the build version");
        Console.WriteLine("  plan <evidence> [options]         show what would run, and why anything is skipped");
        Console.WriteLine("  run <evidence> <output> [options] process evidence: a folder, a drive, or a collection .zip or .tar.gz");
        Console.WriteLine("  evidence-list <case folder>       rebuild the case's EvidenceList.xlsx without running modules");
        Console.WriteLine("  update [--check] [--yes]          check for, download and install a newer ArtefactForge");
        Console.WriteLine("         [--source <folder>]        ...from a folder (share, USB) instead of GitHub");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --config <file>      load the whole run from JSON; flags below override it");
        Console.WriteLine("  --save-config <file> write the effective settings to JSON and exit");
        Console.WriteLine("  --case <name>        case name (default: derived from the collection)");
        Console.WriteLine("  --host <name>        name this collection, e.g. the host a mounted image belongs to");
        Console.WriteLine("  --profile <name>     use a saved module profile from \\Profiles");
        Console.WriteLine("  --modules <a,b>      only these modules");
        Console.WriteLine("  --categories <a,b>   only these categories");
        Console.WriteLine("  --tools <path>       extra tool root, repeatable");
        Console.WriteLine("  --workers <n>        worker pool size (default: logical cores)");
        Console.WriteLine("  --heavy <n>          concurrent heavy-IO modules (default: 2)");
        Console.WriteLine("  --batch              treat each subfolder, .zip and .tar.gz in <evidence> as a collection");
        Console.WriteLine("  --extract-to <path>  where archived collections are extracted (default: <case>\\_Extracted)");
        Console.WriteLine("  --cleanup-extracted  delete each zip's extracted data once its modules have finished");
        Console.WriteLine("  --zips-at-once <n>   zips extracted and parsed at the same time (default: 2)");
        Console.WriteLine("  --vss                process Volume Shadow Copies where supported");
        Console.WriteLine("  --rerun-all          ignore saved state and re-run completed work");
        Console.WriteLine("  --set M.Option=value set a module option, repeatable (see: options <module>)");
        Console.WriteLine();
        Console.WriteLine("Module selection precedence: --modules, then --categories, then --profile,");
        Console.WriteLine("then every module not marked DefaultEnabled: false.");
        Console.WriteLine();
        Console.WriteLine("Publishing (maintainer only):");
        Console.WriteLine("  release keygen --out <file>       create the release signing key - once, kept offline");
        Console.WriteLine("  release sign <file> --key <file>  sign a release manifest, writing <file>.sig");
        Console.WriteLine("  release fingerprint               show the keys this build trusts");
        return 0;
}

int Detect(string? path)
{
    if (string.IsNullOrWhiteSpace(path)) { Console.Error.WriteLine("detect requires a path."); return 2; }

    var layouts = LoadLayouts();
    var discovery = EvidenceDiscovery.Discover(path, batch: false, layouts);
    var targets = discovery.Targets;
    if (targets.Count == 0)
    {
        foreach (var unmatched in discovery.Unmatched) Console.WriteLine($"'{unmatched.Path}': {unmatched.Reason}.");
        return 1;
    }

    foreach (var t in targets)
    {
        Console.WriteLine();
        Console.WriteLine($"  Collection : {t.CollectionName}");
        Console.WriteLine($"  Detected   : {t.Kind}");
        Console.WriteLine($"  Layout     : {t.Layout.Name} [{t.Layout.Id}]{(t.Layout.Provisional ? "  (PROVISIONAL)" : "")}");
        Console.WriteLine(t.IsArchive ? $"  Source     : {t.ArchivePath} (extracted when the run starts)" : $"  Root       : {t.Root}");
        Console.WriteLine($"  Drive      : {t.DriveLetter ?? "-"}   Live: {t.IsLive}");
    }
    return 0;
}

int ListModules()
{
    var result = ModuleLoader.LoadDirectory(Path.Combine(repoRoot, "Modules"));
    foreach (var error in result.Errors) Console.Error.WriteLine($"  ERROR {Path.GetFileName(error.Path)}: {error.Message}");

    Console.WriteLine($"Loaded {result.Items.Count} module(s), {result.Errors.Count} error(s)");
    foreach (var group in result.Items.GroupBy(m => m.Category).OrderBy(g => g.Key))
    {
        Console.WriteLine($"\n{group.Key}");
        foreach (var m in group.OrderBy(m => m.Priority))
        {
            var flags = (m.DefaultEnabled ? "" : " [opt-in]") + (m.Scope == TargetScope.Any ? "" : $" [{m.Scope}]");
            Console.WriteLine($"  [{m.Priority,3}] {m.Name,-30} iterate={m.Iterate,-11} io={m.IoWeight,-5} procs={m.Processors.Count}{flags}");
        }
    }
    return result.Errors.Count > 0 ? 1 : 0;
}

int ListProfiles()
{
    var dir = ProfileFile.Directory(repoRoot);
    if (!Directory.Exists(dir)) { Console.WriteLine("No profiles saved yet."); return 0; }

    var files = Directory.EnumerateFiles(dir, "*.json").OrderBy(f => f).ToList();
    if (files.Count == 0) { Console.WriteLine("No profiles saved yet."); return 0; }

    foreach (var file in files)
    {
        var name = Path.GetFileNameWithoutExtension(file);
        var profile = ProfileFile.Load(repoRoot, name);
        Console.WriteLine($"  {name,-28} {profile?.Modules.Count ?? 0} module(s)");
    }
    return 0;
}

int ListTools(CommandLine options)
{
    var loaded = ModuleLoader.LoadDirectory(Path.Combine(repoRoot, "Modules"));
    // The same roots a run would search: those in --config, then every --tools.
    var extra = new List<string>();
    if (options.Value("config") is { } configPath)
    {
        try { extra.AddRange(RunRequest.Load(configPath).ToolRoots); }
        catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
    }
    extra.AddRange(options.List("tools"));
    var roots = ToolInventory.Roots(repoRoot, extra);

    Console.WriteLine("Tool roots:");
    foreach (var root in roots) Console.WriteLine($"  {(Directory.Exists(root) ? " " : "!")} {root}");

    var inventory = ToolInventory.Scan(loaded.Items, roots);
    Console.WriteLine();
    foreach (var tool in inventory)
        Console.WriteLine($"  {(tool.Found ? tool.IsSystem ? "system " : "found  " : "MISSING")} {tool.Executable,-40} {tool.ModuleCount,2} module(s)  {tool.Version ?? ""}");

    var missing = inventory.Count(t => !t.Found);
    Console.WriteLine();
    Console.WriteLine(missing == 0
        ? $"{inventory.Count} executable(s) referenced, all found."
        : $"{inventory.Count} executable(s) referenced, {missing} missing - those modules will report ToolMissing.");
    return missing > 0 ? 1 : 0;
}

int ListOptions(string? moduleName)
{
    var loaded = ModuleLoader.LoadDirectory(Path.Combine(repoRoot, "Modules"));
    var modules = loaded.Items.Where(m => m.Options.Count > 0);
    if (moduleName is not null)
        modules = modules.Where(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase));

    var any = false;
    foreach (var module in modules.OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase))
    {
        any = true;
        Console.WriteLine();
        Console.WriteLine(module.Name);
        foreach (var option in module.Options)
        {
            var values = option.Kind switch
            {
                OptionKind.Flag => "true|false",
                OptionKind.Choice => string.Join("|", option.Choices),
                _ => "<text>"
            };
            Console.WriteLine($"  {option.Name,-16} {values}");
            Console.WriteLine($"  {"",-16} default: {(option.Default.Length == 0 ? "(off)" : option.Default)}"
                              + (option.Description is null ? "" : "  - " + option.Description));
        }
        Console.WriteLine($"  effective now: {ModuleOptions.Expand(module)}");
    }

    if (!any)
        Console.WriteLine(moduleName is null
            ? "No module declares any options."
            : $"'{moduleName}' declares no options, or does not exist.");
    return 0;
}

int Plan(CommandLine options)
{
    var config = BuildConfig(options, outputRequired: false);
    if (config is null) return 2;

    var plan = RunPlanner.Build(config);
    Console.WriteLine($"{config.Targets.Count} collection(s), {plan.Items.Count} work item(s), {plan.Skipped.Count} skipped");

    foreach (var group in plan.Items.GroupBy(i => i.Target))
    {
        Console.WriteLine($"\n{group.Key.CollectionName} ({group.Key.Kind}) - will run:");
        foreach (var item in group.OrderBy(i => i.Module.Priority))
            Console.WriteLine($"  {item.Module.Category,-14} {item.Module.Name}{(item.IterationKey is null ? "" : $" [{item.IterationKey}]")}");
    }

    // What a zip holds is only known once it is extracted, so its modules are planned then.
    foreach (var archive in config.Targets.Where(t => t.IsArchive))
        Console.WriteLine($"\n{archive.CollectionName} ({archive.Kind}) - {archive.ArchivePath} is extracted when the run starts; "
                          + "its modules are planned then");

    if (plan.Skipped.Count > 0)
    {
        Console.WriteLine("\nSkipped:");
        foreach (var skip in plan.Skipped.OrderBy(s => s.Collection).ThenBy(s => s.Module))
            Console.WriteLine($"  {skip.Collection,-16} {skip.Module,-30} {skip.Reason}");
    }
    return 0;
}

async Task<int> Run(CommandLine options)
{
    var config = BuildConfig(options, outputRequired: true);
    if (config is null) return 2;
    if (options.Value("save-config") is not null) return 0;

    Console.WriteLine($"Case '{config.CaseName}': {config.Targets.Count} collection(s), " +
                      $"{config.Modules.Count} module(s), {config.MaxWorkers} workers ({config.MaxHeavyWorkers} heavy)");

    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        Console.WriteLine("\nCancelling - killing running tools...");
        cancellation.Cancel();
    };

    var engine = new RunEngine();
    engine.Progress += e =>
    {
        if (e.Status == WorkStatus.Running) Console.WriteLine($"  ... {e.Item.Label}");
        else Console.WriteLine($"  {Tag(e.Status)} {e.Item.Label}{(e.Message is null ? "" : " - " + e.Message)}");
    };
    // Per zip, since more than one extracts at once.
    var lastPercent = new System.Collections.Concurrent.ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    engine.Extraction += e =>
    {
        var zip = Path.GetFileName(e.ArchivePath);
        switch (e.Stage)
        {
            case ExtractionStage.Extracting when e.BytesTotal == 0:
                lastPercent[zip] = -10;
                Console.WriteLine($"  ... extracting {zip}");
                break;
            case ExtractionStage.Extracting:
                // Every 10% on the console; the GUI shows the finer steps.
                var percent = (int)(e.BytesDone * 100 / e.BytesTotal);
                if (percent < lastPercent.GetValueOrDefault(zip, -10) + 10) break;
                lastPercent[zip] = percent;
                Console.WriteLine($"      {zip}: {percent}% of {e.BytesTotal / (1024 * 1024):N0} MB");
                break;
            case ExtractionStage.Extracted:
                Console.WriteLine($"  OK       extracted {zip}: {e.Planned?.Count ?? 0} work item(s) found");
                break;
            case ExtractionStage.Failed:
                Console.WriteLine($"  FAILED   {zip} - {e.Message}");
                break;
            case ExtractionStage.CleanedUp:
                Console.WriteLine($"  cleanup  {e.Message}");
                break;
            case ExtractionStage.Skipped:
                Console.WriteLine($"  skip     {zip} - {e.Message}");
                break;
        }
    };

    var report = await engine.RunAsync(config, cancellation.Token);

    Console.WriteLine();
    Console.WriteLine($"Done in {report.DurationSeconds:F1}s{(report.Cancelled ? " (cancelled)" : "")}");
    foreach (var status in Enum.GetValues<WorkStatus>())
    {
        var count = report.Count(status);
        if (count > 0) Console.WriteLine($"  {status,-12} {count}");
    }
    Console.WriteLine($"\nOutput   : {report.CaseDirectory}");
    Console.WriteLine($"Manifest : {Path.Combine(report.LogDirectory, "manifest.csv")}");
    foreach (var extraction in report.Extractions.Where(x => !x.CleanedUp && x.Error is null))
        Console.WriteLine($"Extracted: {extraction.ExtractedTo}");
    if (report.InventoryPath is not null) Console.WriteLine($"Inventory: {report.InventoryPath}");
    if (report.EvidenceList is { } list) Console.WriteLine(list.Describe());
    if (report.NeedsReview > 0)
        Console.WriteLine($"\n{report.NeedsReview} item(s) need review - check the manifest before relying on this output.");

    return report.NeedsReview > 0 ? 1 : 0;
}

int RebuildEvidenceList(string? caseDirectory)
{
    if (string.IsNullOrWhiteSpace(caseDirectory) || !Directory.Exists(caseDirectory))
    {
        Console.Error.WriteLine("Usage: evidence-list <case folder>  (the folder holding the collections and _Logs)");
        return 2;
    }

    var result = EvidenceList.Rebuild(Path.GetFullPath(caseDirectory));
    Console.WriteLine(result.Describe());
    if (result.Outcome is EvidenceListOutcome.Written or EvidenceListOutcome.Unchanged)
        Console.WriteLine($"Evidence list: {result.Path}");
    return result.Outcome is EvidenceListOutcome.Locked or EvidenceListOutcome.Failed ? 1 : 0;
}

async Task<int> Update(CommandLine options)
{
    var updater = SelfUpdater.ForRunningApplication();
    IReleaseSource source = options.Value("source") is { } folder
        ? new FolderReleaseSource(folder)
        : new GitHubReleaseSource();

    Console.WriteLine($"Checking {source.Description} ...");
    var check = await updater.CheckAsync(source);
    Console.WriteLine(check.Message);
    if (check.Status != UpdateCheckStatus.Available) return check.Status == UpdateCheckStatus.UpToDate ? 0 : 1;

    var release = check.Release!;
    if (!string.IsNullOrWhiteSpace(release.Notes))
    {
        Console.WriteLine();
        Console.WriteLine(release.Notes);
        Console.WriteLine();
    }
    if (options.Has("check")) return 0;

    if (!options.Has("yes"))
    {
        Console.Write($"Download and install {release.Version} ({release.Size / 1024.0 / 1024.0:N1} MB)? [y/N] ");
        if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Nothing was changed.");
            return 0;
        }
    }

    try
    {
        var reported = -1L;
        var progress = new Progress<long>(bytes =>
        {
            var tenth = bytes * 10 / Math.Max(1, release.Size);
            if (tenth == reported) return;
            reported = tenth;
            Console.WriteLine($"  downloaded {tenth * 10}%");
        });

        var staged = await updater.DownloadAsync(source, release, progress);
        Console.WriteLine("  signature, size and SHA-256 verified");

        var plan = updater.Plan(staged);
        var outcome = updater.Apply(staged, plan);

        Console.WriteLine();
        Console.WriteLine($"Updated {outcome.FromVersion} -> {outcome.ToVersion}: {plan.Summary()}.");
        foreach (var path in plan.Paths(ChangeKind.KeepUserCopy))
            Console.WriteLine($"  kept your edited {path}; the new version is beside it as {path}.new");
        foreach (var path in plan.Paths(ChangeKind.LeaveEdited))
            Console.WriteLine($"  {path} is no longer shipped, but you had edited it, so it was left in place");
        Console.WriteLine($"The previous version is in {outcome.BackupDirectory}.");
        Console.WriteLine("Restart ArtefactForge (GUI and CLI) to use the new version.");
        return 0;
    }
    catch (UpdateException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

int Release(CommandLine options)
{
    var action = options.Positional.ElementAtOrDefault(0)?.ToLowerInvariant();
    try
    {
        switch (action)
        {
            case "keygen":
            {
                var output = options.Value("out");
                if (string.IsNullOrWhiteSpace(output)) { Console.Error.WriteLine("release keygen requires --out <file>."); return 2; }
                if (File.Exists(output)) { Console.Error.WriteLine($"{output} already exists - refusing to overwrite a signing key."); return 2; }

                // Create the folder before asking for a password, so a bad path fails first, not last.
                var folder = Path.GetDirectoryName(Path.GetFullPath(output));
                try { if (folder is not null) Directory.CreateDirectory(folder); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Console.Error.WriteLine($"Cannot create {folder}: {ex.Message}");
                    return 2;
                }

                var password = ReadPassword("Password for the new key: ");
                if (password.Length < 12) { Console.Error.WriteLine("Use a password of at least 12 characters."); return 2; }
                if (ReadPassword("Again: ") != password) { Console.Error.WriteLine("The passwords differ."); return 2; }

                var (pem, publicKey) = ReleaseSigning.GenerateKey(password);
                File.WriteAllText(output, pem);

                Console.WriteLine();
                Console.WriteLine($"Private key written to {output}.");
                Console.WriteLine("Keep it and its password out of every release and out of the repository, with an offline copy.");
                Console.WriteLine();
                Console.WriteLine("Public key - add to src\\ArtefactForge.Core\\Update\\TrustedKeys.cs and rebuild:");
                Console.WriteLine("  " + publicKey);
                Console.WriteLine("Fingerprint - publish it with the releases:");
                Console.WriteLine("  " + ReleaseSigning.Fingerprint(publicKey));
                return 0;
            }

            case "sign":
            {
                var file = options.Positional.ElementAtOrDefault(1);
                var keyFile = options.Value("key");
                if (file is null || keyFile is null) { Console.Error.WriteLine("release sign <file> --key <keyfile>"); return 2; }

                var data = File.ReadAllBytes(file);
                var password = Environment.GetEnvironmentVariable("AF_SIGNING_PASSWORD") ?? ReadPassword("Signing key password: ");
                var signature = ReleaseSigning.Sign(data, File.ReadAllText(keyFile), password, out var publicKey);

                // Signing with a key this build does not trust would publish a release no
                // installation can accept. Stop here rather than find out from the field.
                if (!ReleaseSigning.Verify(data, signature, TrustedKeys.All))
                {
                    Console.Error.WriteLine($"That key ({ReleaseSigning.Fingerprint(publicKey)}) is not in TrustedKeys.cs for this build. Nothing was written.");
                    return 1;
                }

                File.WriteAllText(file + ".sig", signature);
                Console.WriteLine($"Signed {Path.GetFileName(file)} with key {ReleaseSigning.Fingerprint(publicKey)} -> {Path.GetFileName(file)}.sig");
                return 0;
            }

            case "fingerprint":
                if (TrustedKeys.All.Count == 0) { Console.WriteLine("This build trusts no release signing key; updates are turned off."); return 1; }
                foreach (var key in TrustedKeys.All) Console.WriteLine(ReleaseSigning.Fingerprint(key));
                return 0;

            default:
                Console.Error.WriteLine("release keygen | sign | fingerprint - see 'help'.");
                return 2;
        }
    }
    catch (UpdateException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static string ReadPassword(string prompt)
{
    Console.Write(prompt);
    if (Console.IsInputRedirected) return Console.ReadLine() ?? "";

    var buffer = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace) { if (buffer.Length > 0) buffer.Length--; continue; }
        if (!char.IsControl(key.KeyChar)) buffer.Append(key.KeyChar);
    }
    Console.WriteLine();
    return buffer.ToString();
}

static string Tag(WorkStatus status) => status switch
{
    WorkStatus.Completed => "OK      ",
    WorkStatus.Skipped => "skip    ",
    WorkStatus.NoOutput => "NOOUTPUT",
    WorkStatus.CheckLog => "CHECKLOG",
    WorkStatus.Failed => "FAILED  ",
    WorkStatus.ToolMissing => "MISSING ",
    WorkStatus.TimedOut => "TIMEOUT ",
    WorkStatus.Cancelled => "cancel  ",
    _ => status.ToString()
};

IReadOnlyList<LayoutProfile> LoadLayouts()
{
    var layouts = LayoutLoader.LoadDirectory(Path.Combine(repoRoot, "Layouts"));
    foreach (var error in layouts.Errors) Console.Error.WriteLine($"  layout error: {error.Path}: {error.Message}");
    return layouts.Items;
}

RunConfiguration? BuildConfig(CommandLine options, bool outputRequired)
{
    var request = new RunRequest();
    if (options.Value("config") is { } configPath)
    {
        try { request = RunRequest.Load(configPath); }
        catch (Exception ex) { Console.Error.WriteLine(ex.Message); return null; }
    }

    // Flags win over the file, so one config can be reused with a different evidence path.
    request.Evidence = options.Positional.ElementAtOrDefault(0) ?? request.Evidence;
    request.Output = options.Positional.ElementAtOrDefault(1) ?? request.Output;
    request.CaseName = options.Value("case") ?? request.CaseName;
    request.Profile = options.Value("profile") ?? request.Profile;
    if (options.Has("batch")) request.Batch = true;
    foreach (var pair in options.Repeated("set"))
    {
        var split = pair.IndexOf('=');
        if (split <= 0)
        {
            Console.Error.WriteLine($"--set expects Module.Option=value, got '{pair}'.");
            return null;
        }
        request.Set[pair[..split].Trim()] = pair[(split + 1)..].Trim();
    }
    request.Host = options.Value("host") ?? request.Host;
    if (options.Has("vss")) request.Vss = true;
    if (options.Has("rerun-all")) request.SkipCompleted = false;
    if (options.Has("cleanup-extracted")) request.CleanupExtracted = true;
    request.ExtractTo = options.Value("extract-to") ?? request.ExtractTo;
    if (int.TryParse(options.Value("zips-at-once"), out var zipsAtOnce)) request.ZipsAtOnce = zipsAtOnce;
    if (options.List("modules").Count > 0) request.Modules = options.List("modules");
    if (options.List("categories").Count > 0) request.Categories = options.List("categories");
    if (options.List("tools").Count > 0) request.ToolRoots.AddRange(options.List("tools"));
    if (int.TryParse(options.Value("workers"), out var workers)) request.Workers = workers;
    if (int.TryParse(options.Value("heavy"), out var heavy)) request.HeavyWorkers = heavy;

    if (options.Value("save-config") is { } savePath)
    {
        request.Save(savePath);
        Console.WriteLine($"Wrote {savePath}");
    }

    if (string.IsNullOrWhiteSpace(request.Evidence)) { Console.Error.WriteLine("An evidence path is required."); return null; }
    if (outputRequired && string.IsNullOrWhiteSpace(request.Output)) { Console.Error.WriteLine("An output path is required."); return null; }

    var layouts = LoadLayouts();
    var discovery = EvidenceDiscovery.Discover(request.Evidence, request.Batch, layouts);
    var targets = discovery.Targets;

    if (request.Batch)
    {
        if (!Directory.Exists(request.Evidence)) { Console.Error.WriteLine($"Not a directory: {request.Evidence}"); return null; }
        foreach (var unmatched in discovery.Unmatched)
            Console.Error.WriteLine($"  skipping {unmatched.Path}: {unmatched.Reason}");

        if (discovery.SelectionIsCollection)
            Console.Error.WriteLine($"  warning: '{request.Evidence}' looks like a collection in its own right. "
                                    + "Drop --batch unless it really is a folder of collections.");
    }
    else if (targets.Count == 0 && File.Exists(request.Evidence))
    {
        // A zip that is not a collection says why - encrypted, Velociraptor, not a zip at all -
        // rather than the generic 'no layout matched' below.
        foreach (var unmatched in discovery.Unmatched) Console.Error.WriteLine($"'{unmatched.Path}': {unmatched.Reason}.");
        return null;
    }

    // Two collections sharing a name would write into the same folder and interleave output -
    // in a batch, a folder 'HOST01' beside 'HOST01.zip'.
    var clash = targets.GroupBy(t => t.CollectionName, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
    if (clash is not null)
    {
        Console.Error.WriteLine($"More than one collection is named '{clash.Key}': "
                                + string.Join(", ", clash.Select(t => t.ArchivePath ?? t.SelectionPath))
                                + ". Rename or move one of them.");
        return null;
    }

    // The case name is the top-level output folder, so it needs the same check as --host.
    if (!string.IsNullOrWhiteSpace(request.CaseName)
        && !CollectionNaming.TryValidate(request.CaseName, out _, out var caseError))
    {
        Console.Error.WriteLine($"--case '{request.CaseName}' is not usable as a folder name: {caseError}.");
        return null;
    }

    // One name cannot cover many collections. Rather than guess which one it meant, say so.
    if (request.Host is not null && request.Batch)
    {
        Console.Error.WriteLine("--host names a single collection and cannot be combined with --batch.");
        Console.Error.WriteLine("Run each collection separately, or drop --host and let the folder names stand.");
        return null;
    }

    if (targets.Count == 0)
    {
        // --batch treats each SUBFOLDER as a collection, so pointing it at a mounted image or a
        // single collection finds nothing. Say which mistake it is rather than 'no layout matched'.
        if (request.Batch && LayoutDetector.Detect(request.Evidence, layouts).Count > 0)
            Console.Error.WriteLine($"'{request.Evidence}' is itself a collection, not a folder of them. Drop --batch to process it as one host.");
        else
            Console.Error.WriteLine($"No evidence layout matched '{request.Evidence}'.");
        return null;
    }

    if (request.Host is not null)
    {
        if (!CollectionNaming.TryValidate(request.Host, out var host, out var nameError))
        {
            Console.Error.WriteLine($"--host '{request.Host}' is not usable as a folder name: {nameError}.");
            return null;
        }

        // A mounted drive resolves to exactly one target; anything else would be ambiguous.
        if (targets.Count > 1)
        {
            Console.Error.WriteLine($"--host names one collection but {targets.Count} were detected under '{request.Evidence}'.");
            return null;
        }

        targets[0] = targets[0].Renamed(host);
    }

    var loaded = ModuleLoader.LoadDirectory(Path.Combine(repoRoot, "Modules"));
    foreach (var error in loaded.Errors) Console.Error.WriteLine($"  module error: {Path.GetFileName(error.Path)}: {error.Message}");

    var names = request.Modules;
    if (names.Count == 0 && request.Categories.Count == 0 && request.Profile is not null)
    {
        var profile = ProfileFile.Load(repoRoot, request.Profile);
        if (profile is null) { Console.Error.WriteLine($"Profile not found: {request.Profile}"); return null; }
        names = profile.Modules;
    }

    var modules = loaded.Items.Where(m =>
        names.Count > 0 ? names.Contains(m.Name, StringComparer.OrdinalIgnoreCase)
        : request.Categories.Count > 0 ? request.Categories.Contains(m.Category, StringComparer.OrdinalIgnoreCase)
        : m.DefaultEnabled).ToList();

    if (modules.Count == 0) { Console.Error.WriteLine("No modules selected."); return null; }

    // Validate every override against the module that declares it, before anything runs. An
    // unknown name or a bad value is a mistake worth stopping for, not something to ignore.
    var overrides = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
    foreach (var (key, value) in request.Set)
    {
        var dot = key.IndexOf('.');
        if (dot <= 0)
        {
            Console.Error.WriteLine($"--set expects Module.Option=value, got '{key}'.");
            return null;
        }

        var moduleName = key[..dot];
        var optionName = key[(dot + 1)..];

        var module = modules.FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase));
        if (module is null)
        {
            Console.Error.WriteLine($"--set refers to '{moduleName}', which is not among the selected modules.");
            return null;
        }

        if (!ModuleOptions.TryValidate(module, optionName, value, out var optionError))
        {
            Console.Error.WriteLine($"--set {key}={value}: {optionError}.");
            return null;
        }

        if (!overrides.TryGetValue(module.Name, out var forModule))
            overrides[module.Name] = forModule = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        ((Dictionary<string, string>)forModule)[optionName] = value;
    }

    var toolRoots = ToolInventory.Roots(repoRoot, request.ToolRoots);

    return new RunConfiguration
    {
        CaseName = string.IsNullOrWhiteSpace(request.CaseName) ? targets[0].CollectionName : request.CaseName.Trim(),
        OutputRoot = request.Output
                     ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ArtefactForge"),
        ToolRoots = toolRoots,
        ScriptsDirectory = Path.Combine(repoRoot, "Scripts"),
        Targets = targets,
        Modules = modules,
        MaxWorkers = request.Workers ?? Environment.ProcessorCount,
        MaxHeavyWorkers = request.HeavyWorkers ?? 2,
        Vss = request.Vss,
        SkipCompleted = request.SkipCompleted,
        OptionOverrides = overrides,
        Layouts = layouts,
        ExtractionRoot = string.IsNullOrWhiteSpace(request.ExtractTo) ? null : Path.GetFullPath(request.ExtractTo),
        CleanupExtracted = request.CleanupExtracted,
        ArchivesAtOnce = request.ZipsAtOnce ?? 2
    };
}

static string? FindRepoRoot(string start)
{
    for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
    {
        if (Directory.Exists(Path.Combine(dir.FullName, "Layouts")) &&
            Directory.Exists(Path.Combine(dir.FullName, "Modules")))
            return dir.FullName;
    }
    return null;
}

/// <summary>Minimal flag parser: positionals, --flag, --key value and --key a,b.</summary>
sealed class CommandLine
{
    public List<string> Positional { get; } = [];
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);

    public static CommandLine Parse(string[] args)
    {
        var parsed = new CommandLine();
        for (var i = 1; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--")) { parsed.Positional.Add(arg); continue; }

            var key = arg[2..];
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
            {
                if (!parsed._values.TryGetValue(key, out var list)) parsed._values[key] = list = [];
                list.Add(args[++i]);
            }
            else parsed._flags.Add(key);
        }
        return parsed;
    }

    public bool Has(string key) => _flags.Contains(key);
    public string? Value(string key) => _values.TryGetValue(key, out var v) ? v[0] : null;

    /// <summary>Every occurrence, unsplit. List() splits on commas, which would mangle a value.</summary>
    public List<string> Repeated(string key) => _values.TryGetValue(key, out var v) ? v : [];

    public List<string> List(string key) =>
        _values.TryGetValue(key, out var v)
            ? v.SelectMany(item => item.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList()
            : [];
}
