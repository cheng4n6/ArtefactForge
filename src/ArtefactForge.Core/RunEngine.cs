using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArtefactForge.Core;

public sealed class RunReport
{
    public required string CaseDirectory { get; init; }
    public required string LogDirectory { get; init; }
    public List<WorkResult> Results { get; } = [];
    public double DurationSeconds { get; set; }
    public bool Cancelled { get; set; }
    /// <summary>Case-level system inventory, when any collection produced a summary.</summary>
    public string? InventoryPath { get; set; }
    /// <summary>What happened to the case's evidence list at the end of the run.</summary>
    public EvidenceListResult? EvidenceList { get; set; }
    /// <summary>One per zip unpacked during the run.</summary>
    public List<ExtractionRecord> Extractions { get; } = [];
    /// <summary>The memory memory-heavy modules shared, and the free memory that decided it.</summary>
    public long? MemoryBudgetBytes { get; set; }
    public long? FreeMemoryBytesAtStart { get; set; }
    /// <summary>Modules held back because free memory was under Keep free.</summary>
    public int MemoryFloorWaits { get; set; }

    public int Count(WorkStatus status) => Results.Count(r => r.Status == status);

    /// <summary>Statuses an analyst must look at: something ran but may not have produced evidence.</summary>
    public int NeedsReview => Count(WorkStatus.Failed) + Count(WorkStatus.NoOutput)
                            + Count(WorkStatus.CheckLog) + Count(WorkStatus.ToolMissing)
                            + Count(WorkStatus.TimedOut);

    /// <summary>
    /// The tools that used the most memory, for the end of the run: "Most memory: Hayabusa on
    /// HOST01 3.2 GB, ...". Null when no peak was recorded (builtins only, or not Windows).
    /// </summary>
    public string? DescribePeakMemory(int top = 3)
    {
        var heaviest = Results
            .SelectMany(r => r.Processors.Where(p => p.PeakMemoryBytes > 0)
                                         .Select(p => (Result: r, Peak: p.PeakMemoryBytes!.Value)))
            .OrderByDescending(x => x.Peak)
            .Take(top)
            .Select(x => $"{x.Result.Module} on {x.Result.Collection} {x.Peak / (double)(1L << 30):F1} GB")
            .ToList();
        return heaviest.Count == 0 ? null : "Most memory: " + string.Join(", ", heaviest) + " (all in manifest.csv)";
    }
}

public sealed class RunEngine
{
    public event Action<ProgressEvent>? Progress;
    /// <summary>Progress of each zip being extracted, and the work found inside once it is.</summary>
    public event Action<ExtractionEvent>? Extraction;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>Set when output that could not be harvested was left in staging for the analyst.</summary>
    private volatile bool _keepStaging;

    public async Task<RunReport> RunAsync(RunConfiguration config, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.Now;
        _keepStaging = false;
        var caseDir = Path.Combine(config.OutputRoot, config.CaseName);
        var logDir = Path.Combine(caseDir, "_Logs");
        var consoleDir = Path.Combine(logDir, "Console");
        var stagingRoot = Path.Combine(caseDir, "_Staging");
        var extractionRoot = config.ExtractionRoot ?? Path.Combine(caseDir, "_Extracted");
        Directory.CreateDirectory(consoleDir);

        var report = new RunReport { CaseDirectory = caseDir, LogDirectory = logDir };
        var plan = RunPlanner.Build(config);
        report.Results.AddRange(plan.Skipped);

        var statePath = Path.Combine(logDir, "state.json");
        var completed = config.SkipCompleted ? LoadState(statePath) : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var results = new ConcurrentBag<WorkResult>();
        using var workers = new SemaphoreSlim(Math.Max(1, config.MaxWorkers));
        using var heavy = new SemaphoreSlim(Math.Max(1, config.MaxHeavyWorkers));
        // Memory-heavy tools share the memory free now across the whole run, zips included: three
        // Chainsaw runs at once took about 18 GB and brought down a 16 GB workstation, yet MFTECmd,
        // Hayabusa and Chainsaw hunt fit side by side in 4 GB and finish far sooner together.
        report.FreeMemoryBytesAtStart = MemoryBudget.Available();
        report.MemoryBudgetBytes = config.MemoryBudgetBytes
                                   ?? MemoryBudget.FromFree(report.FreeMemoryBytesAtStart, config.KeepFreeMemoryBytes);
        var memoryHeavy = new MemoryBudget(report.MemoryBudgetBytes);
        // The budget counts only the memory-heavy modules; this watches what is actually free.
        var memoryFloor = new MemoryFloor(config.KeepFreeMemoryBytes);
        // How long each module took when this case last ran, so the longest memory-heavy one starts
        // first instead of last: it is the long pole of the batch.
        var lastDurations = LoadDurations(Path.Combine(logDir, "manifest.json"));

        // What the manifest lists as processed: zips appear once extracted, under their real root.
        var collections = config.Targets.Where(t => !t.IsArchive)
            .Select(t => new CollectionRecord(t.CollectionName, t.Root, t.Layout.Id, t.IsLive, null))
            .ToList();

        // Zips run concurrently with each other and with collections on disk, so the report,
        // the manifest's collection list and the resume state are shared and locked.
        var gate = new object();

        // A host's own post-run steps start as soon as its last module finishes, beside the other
        // hosts' modules, instead of every host waiting for the whole batch. One host at a time:
        // the IOC sweep writes one hits file for the case. The case-wide steps still run at the end.
        var hostSteps = new List<Task>();
        var hostsDone = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sweptEarly = new List<Ioc.IocSweepResult>();
        using var hostGate = new SemaphoreSlim(1);

        try
        {
            // Collections already on disk all run at once through the shared pool, as before.
            var onDisk = RunItemsAsync(plan.Items);

            // Zips run a few at a time - extract, parse, optionally delete - so a batch of them
            // needs disk space for that many extracted collections, not all of them. More than
            // one keeps the pool busy: the next zip extracts, and its modules start, while the
            // previous one is down to its few long-running tools.
            using var archiveSlots = new SemaphoreSlim(Math.Max(1, config.ArchivesAtOnce));
            var zipped = config.Targets.Where(t => t.IsArchive)
                .GroupBy(t => t.ArchivePath!, StringComparer.OrdinalIgnoreCase)
                .Select(async archive =>
                {
                    await archiveSlots.WaitAsync(cancellationToken);
                    try { await RunArchiveAsync(archive.Key, archive.ToList()); }
                    finally { archiveSlots.Release(); }
                })
                .ToList();

            await Task.WhenAll(zipped.Append(onDisk));

            // Only once every zip is done: removed while two zips ran at once, it raced with the
            // other zip's cleanup (reported as a failed delete) or with its extraction starting.
            if (config.CleanupExtracted) CollectionExtractor.RemoveIfEmpty(extractionRoot);
        }
        catch (OperationCanceledException)
        {
            report.Cancelled = true;
        }

        // Kept when a module's output could not be moved out of it: that output exists nowhere else.
        if (!_keepStaging) TryDeleteDirectory(stagingRoot);

        await Task.WhenAll(hostSteps);
        report.Results.AddRange(results);
        // Reads the modules' output, so it runs once they are done; before the manifest, which
        // lists which IP history sources each domain controller had. Hosts already done above
        // come back unchanged and are left out; the rest, and the case files, are built here.
        report.Results.AddRange(NotDone(Windows.IpHistory.Build(caseDir, cancellationToken)));
        report.Results.AddRange(NotDone(Windows.RemoteAccess.Build(caseDir, cancellationToken)));   // for the RDP trace
        report.Results.AddRange(NotDone(Windows.Ransomware.Build(caseDir, cancellationToken)));
        report.DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds;

        report.MemoryFloorWaits = memoryFloor.Waits;
        SaveState(statePath, completed, results);
        WriteManifests(report, logDir, config, collections, started);
        await Ioc.IocSweep.AfterRunAsync(report, hostsDone, sweptEarly);   // the case's IOC hits for the hosts just processed

        // Rolls the per-collection system summaries into one inventory for the case. Runs after
        // everything else because it reads what the modules produced, and does nothing when no
        // collection produced a summary. The evidence list reads the same summaries.
        report.InventoryPath = SystemInventory.Build(caseDir);
        report.EvidenceList = EvidenceList.Rebuild(caseDir);
        Report.CaseReport.AfterRun(report);   // last: the case report reads everything above
        return report;

        IEnumerable<WorkResult> NotDone(IEnumerable<WorkResult> built) =>
            built.Where(r => !hostsDone.Contains(r.Collection));

        // The post-run steps that read only this host's own output.
        async Task AfterHostAsync(string host)
        {
            await hostGate.WaitAsync(CancellationToken.None);
            try
            {
                if (cancellationToken.IsCancellationRequested) return;
                var collectionDir = Path.Combine(caseDir, host);
                var built = new List<WorkResult>();
                if (Windows.IpHistory.BuildCollection(collectionDir, cancellationToken) is { } ip) built.Add(ip);
                if (Windows.RemoteAccess.BuildCollection(collectionDir, cancellationToken) is { } rdp) built.Add(rdp);
                if (Windows.Ransomware.BuildHost(collectionDir, cancellationToken) is { } ransom) built.Add(ransom);
                var swept = await Ioc.IocSweep.AfterHostAsync(caseDir, host,
                    results.Where(r => string.Equals(r.Collection, host, StringComparison.OrdinalIgnoreCase)).ToList());
                lock (gate)
                {
                    report.Results.AddRange(built);
                    hostsDone.Add(host);
                    if (swept is not null) sweptEarly.Add(swept);
                }
            }
            catch (OperationCanceledException)
            {
                // Stopped: the end of the run says which hosts were left out.
            }
            finally
            {
                hostGate.Release();
            }
        }

        void AddResult(WorkResult result)
        {
            lock (gate) report.Results.Add(result);
        }

        // Runs work items through the pool, skipping any an earlier run completed. Returns the
        // results of the items that ran.
        async Task<List<WorkResult>> RunItemsAsync(IReadOnlyList<WorkItem> items)
        {
            List<WorkItem> pending, done;
            lock (gate)
            {
                pending = items.Where(i => !completed.Contains(i.Key))
                    .OrderByDescending(i => i.Module.MemoryWeight == MemoryWeight.Heavy
                                            ? lastDurations.GetValueOrDefault(i.Module.Name) : 0)
                    .ThenBy(i => i.Module.Priority)
                    .ToList();
                done = items.Where(i => completed.Contains(i.Key)).ToList();
            }

            foreach (var item in done)
            {
                AddResult(new WorkResult
                {
                    Collection = item.Target.CollectionName,
                    Module = item.Module.Name,
                    Category = item.Module.Category,
                    Iteration = item.IterationKey,
                    Status = WorkStatus.Skipped,
                    Reason = "already completed in an earlier run",
                    Destination = item.Destination,
                    Started = DateTimeOffset.Now
                });
            }

            // How many of each host's modules are still to finish, for its post-run steps.
            var left = pending.GroupBy(i => i.Target.CollectionName, StringComparer.OrdinalIgnoreCase)
                              .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

            var ran = new ConcurrentBag<WorkResult>();
            var tasks = pending.Select(async item =>
            {
                // Memory-heavy tools queue only on the memory budget, not for a worker or a heavy-IO
                // slot. They are the long pole of a batch; queued behind everything else they would
                // all run at the end. This way they start at once, as many as the memory allows,
                // while the pool works through the other modules beside them, at the cost of a few
                // processes more than Workers and Heavy IO allow.
                var isMemoryHeavy = item.Module.MemoryWeight == MemoryWeight.Heavy;
                var isHeavy = !isMemoryHeavy && item.Module.IoWeight == IoWeight.Heavy;
                var memoryNeed = isMemoryHeavy ? MemoryBudget.EstimateBytes(item.Module) : 0;
                if (isMemoryHeavy) await memoryHeavy.WaitAsync(memoryNeed, cancellationToken);
                else await workers.WaitAsync(cancellationToken);
                if (isHeavy) await heavy.WaitAsync(cancellationToken);
                await memoryFloor.WaitAsync(cancellationToken);
                try
                {
                    Progress?.Invoke(new ProgressEvent(item, WorkStatus.Running));
                    WorkResult result;
                    try
                    {
                        result = await ExecuteAsync(item, config, consoleDir, stagingRoot, workers, cancellationToken);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        // One module that cannot write its folders or logs (a full disk, a file where
                        // a folder should be) fails on its own. Thrown on, it ended the whole run
                        // once every other module finished, with no manifest written.
                        result = new WorkResult
                        {
                            Collection = item.Target.CollectionName,
                            Module = item.Module.Name,
                            Category = item.Module.Category,
                            Iteration = item.IterationKey,
                            Destination = item.Destination,
                            Status = WorkStatus.Failed,
                            Reason = "could not run the module: " + ex.Message,
                            Started = DateTimeOffset.Now
                        };
                    }
                    results.Add(result);
                    ran.Add(result);
                    lock (gate)
                    {
                        var host = item.Target.CollectionName;
                        if (--left[host] == 0 && !cancellationToken.IsCancellationRequested)
                            hostSteps.Add(Task.Run(() => AfterHostAsync(host)));
                    }
                    Progress?.Invoke(new ProgressEvent(item, result.Status, result.Reason));
                }
                finally
                {
                    memoryFloor.Release();
                    if (isHeavy) heavy.Release();
                    if (isMemoryHeavy) memoryHeavy.Release(memoryNeed);
                    else workers.Release();
                }
            });

            await Task.WhenAll(tasks);
            return ran.ToList();
        }

        async Task RunArchiveAsync(string zipPath, IReadOnlyList<ResolvedTarget> pending)
        {
            // A collector's folder keeps its whole name; an archive loses its extension, both parts of ".tar.gz".
            var name = Sanitise(CollectionSource.Stem(zipPath));
            var destination = Path.Combine(extractionRoot, name);
            var extractLog = Path.Combine(logDir, "Extraction", name + ".csv");

            var doneKeys = pending.Select(t => ArchiveDoneKey(t, zipPath, config)).ToList();
            bool finishedBefore;
            lock (gate) finishedBefore = doneKeys.All(completed.Contains);
            if (finishedBefore)
            {
                // Nothing to extract or run. An extraction left from an earlier run without cleanup
                // goes now if cleanup is asked for - but only a folder ArtefactForge made.
                var reason = "already completed in an earlier run - not extracted again";
                if (config.CleanupExtracted && CollectionExtractor.IsOurs(destination))
                {
                    var error = CollectionExtractor.Delete(destination);
                    reason += error is null
                        ? "; deleted its extracted data left from that run"
                        : "; could not delete its extracted data left from that run: " + error;
                }
                foreach (var target in pending)
                    AddResult(ExtractionResult(target, WorkStatus.Skipped, reason, destination));
                Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.Skipped, reason));
                return;
            }

            Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.Extracting));
            long lastReported = 0;
            var progress = new Reporter<(long Done, long Total)>(p =>
            {
                // Every 1% is plenty for a progress bar and keeps a 15,000-entry zip from
                // flooding the GUI with events.
                if (p.Done - lastReported < Math.Max(p.Total / 100, 1) && p.Done < p.Total) return;
                lastReported = p.Done;
                Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.Extracting,
                                                       BytesDone: p.Done, BytesTotal: p.Total));
            });

            var record = await CollectionExtractor.ExtractAsync(zipPath, destination, extractLog, progress, cancellationToken);
            lock (gate) report.Extractions.Add(record);

            if (record.Error is not null)
            {
                foreach (var target in pending)
                    AddResult(ExtractionResult(target, WorkStatus.Failed,
                        "extraction failed: " + record.Error, destination, record.DurationSeconds));
                Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.Failed, record.Error));
                return;
            }

            // The zip was recognised from its entry names; this finds the same collection on disk
            // and gives it a real root. Matched by drive letter, keeping the analyst's names.
            var found = LayoutDetector.Detect(destination, config.Layouts);
            var resolved = new List<ResolvedTarget>();
            var problems = record.Problems.Count;

            // What the Extract row says: faults first, then what the analyst should know anyway.
            var summary = record.Problems.Where(p => p.StartsWith(CollectionExtractor.IncompletePrefix, StringComparison.Ordinal)).ToList();
            var badEntries = problems - summary.Count;
            if (badEntries > 0)
                summary.Add($"{badEntries} zip entr{(badEntries == 1 ? "y was" : "ies were")} not extracted cleanly - see "
                            + Path.Combine("_Logs", "Extraction", name + ".csv"));
            if (record.Reused) summary.Add("reused the extraction from an earlier run");
            summary.AddRange(record.Notes);
            foreach (var target in pending)
            {
                var match = found.FirstOrDefault(f => string.Equals(f.DriveLetter, target.DriveLetter, StringComparison.OrdinalIgnoreCase))
                            ?? (found.Count == 1 ? found[0] : null);
                if (match is null)
                {
                    AddResult(ExtractionResult(target, WorkStatus.Failed,
                        "extracted, but no collection was found in " + destination
                        + (problems > 0 ? $" - {problems} entries failed to extract" : ""),
                        destination, record.DurationSeconds));
                    continue;
                }

                resolved.Add(match.Renamed(target.CollectionName));
                lock (gate) collections.Add(new CollectionRecord(target.CollectionName, match.Root, match.Layout.Id, false, zipPath));

                AddResult(ExtractionResult(target,
                    problems > 0 ? WorkStatus.CheckLog : WorkStatus.Completed,
                    summary.Count > 0 ? string.Join("; ", summary) : null,
                    destination, record.DurationSeconds));
            }

            if (resolved.Count == 0)
            {
                Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.Failed,
                                                       "no collection found after extraction"));
                return;
            }

            var archivePlan = RunPlanner.Build(config, resolved);
            lock (gate) report.Results.AddRange(archivePlan.Skipped);
            Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.Extracted,
                                                   Planned: archivePlan.Items));

            var ran = await RunItemsAsync(archivePlan.Items);

            // Remembered once everything that ran reached an outcome a re-run would only repeat, so
            // a re-run of the batch skips this zip without extracting it again. NoOutput counts:
            // the tool read the evidence and found nothing (a dirty SRUM database, say), and
            // re-extracting gigabytes to get the same answer helps nobody. It is still on the
            // results for review, and "re-run all" processes the zip again. Failed, timed out,
            // missing tools and cancelled work do need another go, so the zip is processed again.
            if (resolved.Count == pending.Count && problems == 0
                && ran.All(r => r.Status is WorkStatus.Completed or WorkStatus.CheckLog or WorkStatus.NoOutput))
                lock (gate) foreach (var key in doneKeys) completed.Add(key);

            if (!config.CleanupExtracted) return;

            // Kept when something went wrong during extraction, so the analyst can see what was
            // and was not written, even though cleanup was asked for.
            if (problems > 0)
            {
                Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.CleanedUp,
                    "kept because extraction reported problems: " + destination));
                return;
            }

            record.CleanupError = CollectionExtractor.Delete(destination);
            record.CleanedUp = record.CleanupError is null;
            Extraction?.Invoke(new ExtractionEvent(zipPath, pending, ExtractionStage.CleanedUp,
                record.CleanedUp ? "deleted " + destination : "could not delete " + destination + ": " + record.CleanupError));
        }
    }

    /// <summary>A row in the results for unpacking a zip, so it sits in the manifest beside the modules.</summary>
    private static WorkResult ExtractionResult(
        ResolvedTarget target, WorkStatus status, string? reason, string destination, double duration = 0) => new()
    {
        Collection = target.CollectionName,
        Module = "Extract",
        Category = "Extraction",
        Status = status,
        Reason = reason,
        Destination = destination,
        Started = DateTimeOffset.Now.AddSeconds(-duration),
        DurationSeconds = duration
    };

    /// <summary>
    /// State key for a zip whose work all finished. It names the zip's size and date and the
    /// modules chosen, so adding a module or replacing the zip makes the next run process it again.
    /// </summary>
    private static string ArchiveDoneKey(ResolvedTarget target, string zipPath, RunConfiguration config)
    {
        var signature = CollectionExtractor.QuickSignature(zipPath) + "|"
                        + string.Join(",", config.Modules.Select(m => m.Name).Order(StringComparer.OrdinalIgnoreCase));
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signature)))[..16];
        return $"{target.CollectionName}|_archive|{hash}";
    }

    private sealed record CollectionRecord(string CollectionName, string Root, string Layout, bool IsLive, string? Archive);

    /// <summary>Reports on the caller's thread, unlike Progress&lt;T&gt;, which posts to whatever context created it.</summary>
    private sealed class Reporter<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    /// <param name="workers">The pool's slots, which a Split step's extra parts each take one of.</param>
    private async Task<WorkResult> ExecuteAsync(
        WorkItem item, RunConfiguration config, string consoleDir, string stagingRoot,
        SemaphoreSlim workers, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.Now;
        var result = new WorkResult
        {
            Collection = item.Target.CollectionName,
            Module = item.Module.Name,
            Category = item.Module.Category,
            Iteration = item.IterationKey,
            Destination = item.Destination,
            Status = WorkStatus.Running,
            Started = started
        };

        // The category folder is made up front; a user's folder only once something lands in it,
        // so a profile with nothing to show does not leave an empty folder behind.
        Directory.CreateDirectory(item.UserFolder is null
            ? item.Destination
            : Path.GetDirectoryName(item.Destination) ?? item.Destination);

        // VSS only means anything on a real volume; a collection folder has no shadow copies.
        var vss = config.Vss && item.Module.SupportsVss && item.Target.Layout.Detect.RootIsSelection;

        // Resolved once per module: every processor in it sees the same options.
        config.OptionOverrides.TryGetValue(item.Module.Name, out var overrides);
        var options = ModuleOptions.Expand(item.Module, overrides);
        var outputName = item.Module.OutputName ?? item.Module.Name;
        var delivered = 0;
        var emptyFiles = 0;
        var notMoved = new List<string>();
        // Set when a tool's log said it skipped a dirty hive with no logs; the reason for the review flag.
        string? dirtyHiveNote = null;
        // How a Split step ran - in parts, or as one process and why - for the module's reason.
        string? splitNote = null;

        var baseStem = Sanitise(item.Target.CollectionName + "_" + item.Module.Name
                                + (item.IterationKey is null ? "" : "_" + item.IterationKey));

        // Scratch space for Prepare steps: staged copies of locked files are working material,
        // not evidence output, so this is never harvested and is deleted with the module.
        var workDir = Path.Combine(stagingRoot, baseStem + "_work");
        TryDeleteDirectory(workDir);
        Directory.CreateDirectory(workDir);

        try
        {
            for (var i = 0; i < item.Module.Prepare.Count; i++)
                if (!await RunProcessorAsync(item.Module.Prepare[i], "prepare", i, item.Module.Prepare.Count, harvest: false))
                    break;

            if (result.Status == WorkStatus.Running)
                for (var i = 0; i < item.Module.Processors.Count; i++)
                    if (!await RunProcessorAsync(item.Module.Processors[i], "process", i, item.Module.Processors.Count, harvest: true))
                        break;
        }
        finally
        {
            TryDeleteDirectory(workDir);
        }

        // Returns false when the module should stop.
        async Task<bool> RunProcessorAsync(
            ProcessorDefinition processor, string phase, int index, int count, bool harvest)
        {
            var tool = ToolResolver.Resolve(processor.Executable, config.ToolRoots);
            if (tool is null)
            {
                result.Status = WorkStatus.ToolMissing;
                result.Reason = "not found in any tool root: " + processor.Executable;
                return false;
            }

            var stem = baseStem + phase switch
            {
                "prepare" => "_prep" + (count > 1 ? (index + 1).ToString() : ""),
                _ => count > 1 ? "_p" + (index + 1) : ""
            };

            // Output-producing processors write into a private staging folder. Category folders are
            // shared by several modules running at once, so writing tools straight into them would
            // make it impossible to tell which tool produced which file - and invites collisions.
            string? staging = null;
            if (harvest)
            {
                staging = Path.Combine(stagingRoot, stem + "_out");
                TryDeleteDirectory(staging);
                Directory.CreateDirectory(staging);
            }

            // Only made when a module asks for it, so the Console folder does not fill with empty ones.
            var toolLogDir = Path.Combine(consoleDir, "ToolLogs", stem);
            if ((processor.CommandLine + processor.WorkingDirectory).Contains("%toolLogDir%", StringComparison.OrdinalIgnoreCase))
                Directory.CreateDirectory(toolLogDir);

            var context = new PlaceholderContext
            {
                Root = item.Target.Root,
                // A Prepare step has nowhere to deliver to, so its destination is the scratch folder.
                DestinationDirectory = staging ?? workDir,
                WorkDir = workDir,
                ToolLogDir = toolLogDir,
                Options = options,
                ToolsDir = tool.ToolRoot,
                ScriptsDir = config.ScriptsDirectory,
                CaseName = config.CaseName,
                CollectionName = item.Target.CollectionName,
                ModuleName = item.Module.Name,
                User = item.IterationKey,
                UserHome = item.UserHome,
                Match = item.MatchPath,
                VssEnabled = vss
            };

            // A Split step reads %splitDir%: its whole input folder, unless it runs in parts.
            List<string>? partFolders = null;
            if (harvest && processor.Split is { } split)
            {
                var folder = Placeholders.Resolve(split.Folder, context);
                context = context with { SplitDir = folder };
                (partFolders, splitNote) = PlanSplit(
                    split, folder, Path.Combine(workDir, "split" + (index + 1)),
                    split.Option is null ? null : ModuleOptions.Effective(item.Module, overrides).GetValueOrDefault(split.Option),
                    vss, item.Target.IsLive);
            }

            var runs = new List<ToolRun>();
            if (partFolders is null)
            {
                var arguments = Placeholders.Resolve(processor.CommandLine, context);
                var workingDirectory = string.IsNullOrWhiteSpace(processor.WorkingDirectory)
                    ? null
                    : Placeholders.Resolve(processor.WorkingDirectory, context);

                var stdout = Path.Combine(consoleDir, stem + ".log");
                var stderr = Path.Combine(consoleDir, stem + ".err.log");

                var outcome = await RunToolAsync(arguments, stdout, stderr, workingDirectory);

                // A dirty hive whose .LOG1/.LOG2 were not collected: the EZ Tools hive readers skip it,
                // say so on stdout and exit 0, sometimes leaving header-only CSVs that would pass for a
                // clean run. Read it again without the logs where the tool can, keeping the first
                // attempt's log beside the second; either way the module goes for review.
                if (outcome is { ExitCode: 0, TimedOut: false, LogError: null }
                    && !cancellationToken.IsCancellationRequested
                    && ReportsDirtyHiveWithoutLogs(stdout))
                {
                    if (processor.NoLogsArgument is { } noLogs)
                    {
                        var firstStdout = Path.Combine(consoleDir, stem + "_first.log");
                        File.Move(stdout, firstStdout, overwrite: true);
                        File.Move(stderr, Path.Combine(consoleDir, stem + "_first.err.log"), overwrite: true);
                        if (staging is not null)
                        {
                            TryDeleteDirectory(staging);
                            Directory.CreateDirectory(staging);
                        }
                        arguments += " " + noLogs;
                        outcome = await RunToolAsync(arguments, stdout, stderr, workingDirectory);
                        dirtyHiveNote ??= "a registry hive was dirty and its transaction logs (.LOG1/.LOG2) were "
                                        + $"not collected, so it was read again with {noLogs}, as last written to "
                                        + "disk - recent entries may be missing; see " + Path.GetFileName(firstStdout);
                    }
                    else
                    {
                        dirtyHiveNote ??= "a registry hive was dirty and its transaction logs (.LOG1/.LOG2) were "
                                        + "not collected, so the tool skipped it and its entries are missing; see "
                                        + Path.GetFileName(stdout);
                    }
                }
                runs.Add(new ToolRun(arguments, workingDirectory, stdout, stderr, outcome));
            }
            else
            {
                // The module's own slot works through the parts one after another; each worker
                // that comes free takes a part beside it, so Workers still bounds how many tools
                // run at once. A part never waits for a worker while holding one: with every
                // worker busy - one, or a batch of hosts all in this step - waiting would never end.
                var queue = new ConcurrentQueue<int>(Enumerable.Range(0, partFolders.Count));
                var partRuns = new ToolRun[partFolders.Count];
                using var drained = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                async Task Lane(bool ownSlot)
                {
                    if (!ownSlot)
                    {
                        try { await workers.WaitAsync(drained.Token); }
                        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return; }
                    }
                    try
                    {
                        while (queue.TryDequeue(out var part)) partRuns[part] = await RunPartAsync(part);
                    }
                    finally
                    {
                        if (!ownSlot) workers.Release();
                    }
                }

                async Task<ToolRun> RunPartAsync(int part)
                {
                    var partContext = context with { SplitDir = partFolders[part], SplitPart = "_part" + (part + 1) };
                    var arguments = Placeholders.Resolve(processor.CommandLine, partContext);
                    var workingDirectory = string.IsNullOrWhiteSpace(processor.WorkingDirectory)
                        ? null
                        : Placeholders.Resolve(processor.WorkingDirectory, partContext);
                    var stdout = Path.Combine(consoleDir, stem + "_part" + (part + 1) + ".log");
                    var stderr = Path.Combine(consoleDir, stem + "_part" + (part + 1) + ".err.log");
                    var outcome = await RunToolAsync(arguments, stdout, stderr, workingDirectory);
                    return new ToolRun(arguments, workingDirectory, stdout, stderr, outcome);
                }

                var extra = Enumerable.Range(1, partFolders.Count - 1).Select(_ => Lane(ownSlot: false)).ToList();
                await Lane(ownSlot: true);
                // Every part has started; workers still being waited for are no longer needed.
                await drained.CancelAsync();
                await Task.WhenAll(extra);
                runs.AddRange(partRuns);
            }

            Task<ProcessOutcome> RunToolAsync(string arguments, string stdout, string stderr, string? workingDirectory) =>
                Builtins.IsBuiltin(tool.FullPath)
                    ? Builtins.RunAsync(tool.FullPath, arguments, stdout, stderr, item.Module.Timeout, cancellationToken)
                    : ProcessRunner.RunAsync(
                        tool.FullPath, arguments, stdout, stderr, item.Module.Timeout, cancellationToken, workingDirectory);

            // The parts are joined only when every one of them finished cleanly. Otherwise the
            // joined file would pass for the whole input while missing a part's events.
            var ranClean = !cancellationToken.IsCancellationRequested
                           && runs.All(r => r.Outcome is { TimedOut: false, LogError: null }
                                            && (r.Outcome.ExitCode == 0 || processor.ContinueOnError));
            string? joinError = null;
            if (partFolders is not null && ranClean)
                joinError = await JoinPartsAsync(staging!, processor.Split!.MergeInto, partFolders, context.SplitDir, cancellationToken);
            var unjoined = partFolders is not null && (!ranClean || joinError is not null);

            // A process killed part-way - timed out or cancelled - may have left files half written.
            // They are kept, because a partial CSV can still be evidence of what the tool reached,
            // but never beside finished output where they would pass for complete: they go to
            // <collection>\_Incomplete\<category>\ instead, and the reason says so. So do a Split
            // step's parts when they were not joined: each holds only some of the input.
            var killed = runs.Any(r => r.Outcome.TimedOut) || cancellationToken.IsCancellationRequested;
            var harvestTo = killed || unjoined ? IncompleteDestination(item.Destination, item.UserFolder) : item.Destination;
            var harvested = staging is null
                ? new HarvestResult([], 0, 0, 0)
                : Harvest(staging, harvestTo, outputName, item.IterationKey);
            // A file that could not be moved is still in staging, and is the only copy of it.
            if (harvested.Failed > 0)
            {
                notMoved.Add(staging!);
                _keepStaging = true;
            }
            else if (staging is not null) TryDeleteDirectory(staging);
            // Keep a tool's own log folder only when it wrote something into it.
            TryDeleteEmptyDirectory(toolLogDir);
            TryDeleteEmptyDirectory(Path.GetDirectoryName(toolLogDir)!);
            // A 0-byte file is not output: EvtxECmd and Hayabusa both leave one behind when they
            // cannot open a single log, then exit 0. A header-only CSV still counts - the tool ran
            // and found nothing - but a file with no bytes at all says the tool never got going.
            if (!killed && !unjoined)
            {
                delivered += harvested.Files.Count - harvested.Empty - harvested.Failed;
                emptyFiles += harvested.Empty;
            }
            var incomplete = Path.Combine("_Incomplete", item.UserFolder is null ? Path.GetFileName(item.Destination) : Path.Combine(Path.GetFileName(Path.GetDirectoryName(item.Destination) ?? ""), item.UserFolder));
            var partialNote = harvested.Files.Count == 0 ? ""
                : killed ? $"; {harvested.Files.Count} partial file(s) kept in {incomplete}"
                : unjoined ? $"; the parts' {harvested.Files.Count} file(s) were not joined and are kept in {incomplete}"
                : "";

            // One record per process. The output is the step's, delivered once, so it is listed
            // on the first.
            for (var r = 0; r < runs.Count; r++)
            {
                var run = runs[r];
                result.Processors.Add(new ProcessorRecord
                {
                    Phase = phase,
                    Executable = tool.FullPath,
                    Arguments = run.Arguments,
                    ToolVersion = tool.Version,
                    ToolSha256 = tool.Sha256,
                    WorkingDirectory = Builtins.IsBuiltin(tool.FullPath)
                        ? ""
                        : run.WorkingDirectory ?? Path.GetDirectoryName(tool.FullPath) ?? "",
                    ExitCode = run.Outcome.ExitCode,
                    WroteToStderr = run.Outcome.WroteToStderr,
                    StderrExpected = run.Outcome.WroteToStderr && OnlyExpectedStderr(run.Stderr, processor.ExpectedStderr),
                    DurationSeconds = run.Outcome.DurationSeconds,
                    PeakMemoryBytes = run.Outcome.PeakMemoryBytes,
                    StdoutLog = run.Stdout,
                    StderrLog = run.Stderr,
                    OutputFilesCreated = r == 0 ? harvested.Files.Count : 0,
                    OutputBytes = r == 0 ? harvested.Bytes : 0,
                    OutputFiles = r == 0 ? harvested.Files : [],
                    Error = run.Outcome.Error ?? run.Outcome.LogError
                });
            }

            // "part 2: " when the step ran in parts, so the reason names the log to read.
            string Part(ToolRun run) => runs.Count > 1 ? "part " + (runs.IndexOf(run) + 1) + ": " : "";

            if (runs.FirstOrDefault(r => r.Outcome.TimedOut) is { } timedOut)
            {
                result.Status = WorkStatus.TimedOut;
                result.Reason = Part(timedOut) + (partialNote.Length == 0
                    ? timedOut.Outcome.Error
                    : timedOut.Outcome.Error?.TrimEnd('.') + partialNote);
                return false;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                result.Status = WorkStatus.Cancelled;
                result.Reason = partialNote.Length > 0 ? partialNote[2..] : null;
                return false;
            }

            // The tool may well have finished, but its log is cut short, so neither its stderr nor
            // (on a full disk) its output can be trusted. Never passed, even for ContinueOnError.
            if (runs.FirstOrDefault(r => r.Outcome.LogError is not null) is { } cutShort)
            {
                result.Status = WorkStatus.Failed;
                result.Reason = (phase == "prepare" ? "preparation step " + (index + 1) + ": " : "")
                                + Part(cutShort) + cutShort.Outcome.LogError + " - is the output disk full?"
                                + partialNote;
                return false;
            }

            // Some staging tools report failure for conditions that still leave a usable copy.
            if (!processor.ContinueOnError && runs.FirstOrDefault(r => r.Outcome.ExitCode != 0) is { } failed)
            {
                result.Status = WorkStatus.Failed;
                result.Reason = (phase == "prepare" ? "preparation step " + (index + 1) + " failed: " : "")
                                + Part(failed) + "exit code " + failed.Outcome.ExitCode + "; see "
                                + Path.GetFileName(failed.Stderr) + partialNote;
                return false;
            }

            if (joinError is not null)
            {
                result.Status = WorkStatus.Failed;
                result.Reason = "the parts ran but were not joined: " + joinError + partialNote;
                return false;
            }

            return true;
        }

        if (result.Status == WorkStatus.Running)
        {
            // Exit codes are not trusted: RECmd returns 0 on bad arguments while writing nothing.
            if (notMoved.Count > 0)
            {
                result.Status = WorkStatus.Failed;
                result.Reason = "output could not be moved into " + item.Destination
                                + " (see the manifest); what is left of it is in " + string.Join(", ", notMoved);
            }
            else if (delivered == 0)
            {
                result.Status = WorkStatus.NoOutput;
                result.Reason = emptyFiles > 0
                    ? $"exit 0 but every output file was empty (0 bytes, {emptyFiles} file(s)) - the tool likely could not read its input; check the log"
                    : "exit 0 but no output files were produced - artefact may be empty, or check the log";
                if (dirtyHiveNote is not null) result.Reason += "; " + dirtyHiveNote;
            }
            else if (dirtyHiveNote is not null)
            {
                result.Status = WorkStatus.CheckLog;
                result.Reason = dirtyHiveNote
                                + (result.Processors.Any(p => p.WroteToStderr && !p.StderrExpected)
                                    ? "; the tool also wrote to stderr - review the .err.log"
                                    : "");
            }
            else if (result.Processors.Any(p => p.WroteToStderr && !p.StderrExpected))
            {
                result.Status = WorkStatus.CheckLog;
                result.Reason = "exit 0 but the tool wrote to stderr - review the .err.log";
            }
            else
            {
                result.Status = WorkStatus.Completed;
            }
        }

        if (splitNote is not null)
            result.Reason = result.Reason is null ? splitNote : result.Reason + "; " + splitNote;
        result.DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds;
        return result;
    }

    /// <summary>One process a step ran: the whole step, or one part of a Split step.</summary>
    private sealed record ToolRun(
        string Arguments, string? WorkingDirectory, string Stdout, string Stderr, ProcessOutcome Outcome);

    /// <summary>
    /// The folders a Split step's parts read, or null to run it as one process, with what the
    /// module's reason should say: how it was split, or why it was not when parts were asked for
    /// or could not be made. Nothing when one process was simply the right choice.
    /// </summary>
    private static (List<string>? Folders, string? Note) PlanSplit(
        SplitDefinition split, string folder, string linkRoot, string? setting, bool vss, bool live)
    {
        var asked = setting is not null && InputSplit.TryParseParts(setting, out var n) && n > 1;
        // Shadow copies are read by the tool itself, through the volume, not from the folder; a
        // live system's logs are locked and in use.
        if (vss) return (null, asked ? "run as one process: shadow copies are read by the tool itself" : null);
        if (live) return (null, asked ? "run as one process: the live system's files cannot be linked" : null);

        List<FileInfo> files;
        try
        {
            // Not there, or unreadable: the tool runs over the folder as it would unsplit, and
            // reports the problem itself.
            if (!Directory.Exists(folder)) return (null, null);
            var top = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar);
            var all = new DirectoryInfo(top).EnumerateFiles(split.Pattern, SearchOption.AllDirectories).ToList();
            files = all.Where(f => string.Equals(f.DirectoryName, top, StringComparison.OrdinalIgnoreCase)).ToList();
            if (files.Count < all.Count)
                return (null, "run as one process: some of its input is in subfolders, which the parts would not see");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (null, null);
        }

        var parts = InputSplit.Parts(setting, files.Count, files.Sum(f => f.Length));
        if (parts == 1) return (null, null);

        var groups = InputSplit.Group(files.Select(f => (f.FullName, f.Length)).ToList(), parts);
        var error = InputSplit.Link(groups, linkRoot, out var folders);
        return error is null
            ? (folders, $"ran as {folders.Count} processes over {files.Count} files, joined into {split.MergeInto}")
            : (null, "run as one process: " + error);
    }

    /// <summary>
    /// Joins a Split step's CSVs, named &lt;MergeInto&gt;_partN, into MergeInto in staging and
    /// removes them, with each part's folder written as <paramref name="folder"/>, the one it
    /// stands for. Returns why not, leaving the parts as they are: a file that is not one of the
    /// parts (a CommandLine that names its CSV some other way), headers that differ, or a part
    /// that cannot be read.
    /// </summary>
    private static async Task<string?> JoinPartsAsync(
        string staging, string mergeInto, IReadOnlyList<string> partFolders, string folder,
        CancellationToken cancellationToken)
    {
        var stem = Path.GetFileNameWithoutExtension(mergeInto);
        var extension = Path.GetExtension(mergeInto);
        var partFiles = Enumerable.Range(1, partFolders.Count)
            .Select(p => Path.Combine(staging, stem + "_part" + p + extension))
            .ToList();
        var unexpected = Directory.EnumerateFiles(staging, "*", SearchOption.AllDirectories)
            .FirstOrDefault(f => !partFiles.Contains(f, StringComparer.OrdinalIgnoreCase));
        if (unexpected is not null)
            return $"{Path.GetRelativePath(staging, unexpected)} is not one of the parts' files ({stem}_partN{extension})";

        var merged = Path.Combine(staging, mergeInto);
        string? error;
        try
        {
            error = await InputSplit.MergeAsync(partFiles, merged, cancellationToken,
                                                partFolders.Select(p => (p, folder)).ToList());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = "could not join them: " + ex.Message;
        }
        if (error is not null)
        {
            try { File.Delete(merged); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            return error;
        }

        // Joined: a part left beside the joined file would deliver its rows twice.
        foreach (var part in partFiles)
        {
            try { File.Delete(part); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return $"joined, but {Path.GetFileName(part)} could not be removed: {ex.Message}";
            }
        }
        return null;
    }

    /// <param name="Failed">Files that could not be moved out of staging; listed in Files as "=> FAILED".</param>
    private sealed record HarvestResult(List<string> Files, long Bytes, int Empty, int Failed);

    /// <summary>&lt;case&gt;\&lt;collection&gt;\&lt;category&gt; becomes &lt;case&gt;\&lt;collection&gt;\_Incomplete\&lt;category&gt;.</summary>
    internal static string IncompleteDestination(string destination) =>
        Path.Combine(Path.GetDirectoryName(destination) ?? destination, "_Incomplete", Path.GetFileName(destination));

    /// <summary>The same for per-user output: ...\&lt;category&gt;\&lt;user&gt; becomes ...\_Incomplete\&lt;category&gt;\&lt;user&gt;.</summary>
    internal static string IncompleteDestination(string destination, string? userFolder) =>
        userFolder is null
            ? IncompleteDestination(destination)
            : Path.Combine(IncompleteDestination(Path.GetDirectoryName(destination) ?? destination), userFolder);

    /// <summary>
    /// Moves everything a processor produced out of staging and into the category folder under the
    /// naming convention. Any folder structure the tool invented is flattened - RECmd, for one,
    /// buries its batch output in a timestamped subfolder.
    ///
    /// Called per processor rather than at the end of the run, so a module's output is reviewable
    /// as soon as that module finishes instead of waiting for the whole batch.
    ///
    /// Staging MUST stay on the same volume as the destination - it lives inside the case folder
    /// for exactly this reason. A same-volume move is a metadata rename and costs nothing even for
    /// a 600 MB MFT CSV; move staging to another volume (%TEMP%, say) and every harvest silently
    /// becomes a full byte copy of everything the run produces.
    /// </summary>
    private static HarvestResult Harvest(string staging, string destination, string outputName, string? user)
    {
        var moved = new List<string>();
        long bytes = 0;
        var empty = 0;
        var failed = 0;

        List<string> produced;
        try { produced = Directory.EnumerateFiles(staging, "*", SearchOption.AllDirectories).ToList(); }
        catch { return new HarvestResult(moved, 0, 0, 0); }

        // The category folder exists already; an _Incomplete one is only made when something lands in it.
        if (produced.Count > 0) Directory.CreateDirectory(destination);

        foreach (var source in produced.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            var original = Path.GetFileName(source);
            var target = OutputNaming.Deduplicate(destination, OutputNaming.Build(original, outputName, user));
            try
            {
                var size = new FileInfo(source).Length;
                File.Move(source, Path.Combine(destination, target), overwrite: false);
                moved.Add(original == target ? target : original + " => " + target);
                bytes += size;
                if (size == 0) empty++;
            }
            catch (Exception ex)
            {
                moved.Add(original + " => FAILED: " + ex.Message);
                failed++;
            }
        }
        return new HarvestResult(moved, bytes, empty, failed);
    }

    private static void TryDeleteEmptyDirectory(string path)
    {
        // Non-recursive: Delete refuses a folder that holds anything, which is the check itself.
        try { if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any()) Directory.Delete(path); }
        catch { /* not empty after all, or in use - either way it stays */ }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
        catch { /* a leftover staging folder is untidy, not harmful */ }
    }

    private static HashSet<string> LoadState(string path)
    {
        try
        {
            if (!File.Exists(path)) return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var keys = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) ?? [];
            return keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Each module's longest run in an earlier manifest of this case, by name. Empty for a new case
    /// or a manifest that cannot be read: then Priority alone decides the order, as before.
    /// </summary>
    public static Dictionary<string, double> LoadDurations(string manifestPath)
    {
        var durations = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(manifestPath)) return durations;
            using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
            if (!doc.RootElement.TryGetProperty("Results", out var results) || results.ValueKind != JsonValueKind.Array)
                return durations;
            foreach (var result in results.EnumerateArray())
            {
                if (result.ValueKind != JsonValueKind.Object
                    || !result.TryGetProperty("Module", out var module) || module.ValueKind != JsonValueKind.String
                    || !result.TryGetProperty("DurationSeconds", out var seconds) || !seconds.TryGetDouble(out var value))
                    continue;
                var name = module.GetString()!;
                if (value > durations.GetValueOrDefault(name)) durations[name] = value;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
        }
        return durations;
    }

    private static void SaveState(string path, HashSet<string> existing, IEnumerable<WorkResult> results)
    {
        // Only genuinely finished work is remembered, so a re-run retries failures and timeouts.
        foreach (var result in results.Where(r => r.Status is WorkStatus.Completed or WorkStatus.CheckLog))
        {
            existing.Add(result.Collection + "|" + result.Module + "|" + (result.Iteration ?? "-"));
        }

        try { File.WriteAllText(path, JsonSerializer.Serialize(existing.OrderBy(k => k), JsonOptions)); }
        catch { /* a lost state file only costs a re-run */ }
    }

    private static void WriteManifests(
        RunReport report, string logDir, RunConfiguration config, IReadOnlyList<CollectionRecord> collections,
        DateTimeOffset started)
    {
        var ordered = report.Results
            .OrderBy(r => r.Collection, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Module, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var manifest = new
        {
            Tool = new
            {
                Name = "ArtefactForge",
                BuildInfo.Version,
                BuildInfo.InformationalVersion,
                BuildInfo.Executable,
                BuildInfo.Sha256
            },
            Case = config.CaseName,
            Started = started,
            DurationSeconds = report.DurationSeconds,
            config.MaxWorkers,
            config.MaxHeavyWorkers,
            report.MemoryBudgetBytes,
            report.FreeMemoryBytesAtStart,
            config.KeepFreeMemoryBytes,
            report.MemoryFloorWaits,
            Vss = config.Vss,
            Cancelled = report.Cancelled,
            Collections = collections,
            Extractions = report.Extractions,
            Results = ordered
        };
        File.WriteAllText(Path.Combine(logDir, "manifest.json"), JsonSerializer.Serialize(manifest, JsonOptions));

        var csv = new StringBuilder();
        csv.AppendLine("Collection,Category,Module,Iteration,Status,Reason,DurationSec,Phase,Executable,ToolVersion,ToolSha256,ExitCode,Stderr,OutputFiles,OutputBytes,CommandLine,Destination,PeakMemoryMB");
        foreach (var r in ordered)
        {
            if (r.Processors.Count == 0)
            {
                csv.AppendLine(Row(r, null));
                continue;
            }
            foreach (var p in r.Processors) csv.AppendLine(Row(r, p));
        }
        File.WriteAllText(Path.Combine(logDir, "manifest.csv"), csv.ToString());

        var log = new StringBuilder();
        log.AppendLine(started.ToString("yyyy-MM-dd HH:mm:ss") + " === " + BuildInfo.Describe()
                       + " | case " + config.CaseName + " ===");
        foreach (var r in ordered)
        {
            log.AppendLine(r.Started.ToString("yyyy-MM-dd HH:mm:ss") + " [" + r.Status + "] "
                           + r.Collection + "/" + r.Module
                           + (r.Iteration is null ? "" : "[" + r.Iteration + "]")
                           + " (" + r.DurationSeconds.ToString("F1") + "s)"
                           + (r.Reason is null ? "" : " - " + r.Reason));
        }
        File.AppendAllText(Path.Combine(logDir, "ProcessingLog.txt"), log.ToString());
    }

    private static readonly System.Text.RegularExpressions.Regex AnsiEscape =
        new(@"\x1B\[[0-9;?]*[A-Za-z]", System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// True when every non-blank stderr line matches one of the patterns. No patterns, or a log
    /// that cannot be read, means false: the run is flagged rather than passed on an assumption.
    /// </summary>
    public static bool OnlyExpectedStderr(string stderrLog, IReadOnlyList<string> patterns)
    {
        if (patterns.Count == 0) return false;
        try
        {
            var regexes = patterns.Select(p => new System.Text.RegularExpressions.Regex(p)).ToList();
            foreach (var raw in File.ReadLines(stderrLog))
            {
                var line = AnsiEscape.Replace(raw, "").Trim();
                if (line.Length == 0) continue;
                if (!regexes.Any(r => r.IsMatch(line))) return false;
            }
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// True when the stdout log holds the line the EZ Tools registry library prints when it skips
    /// a dirty hive because its transaction logs are not beside it. A log that cannot be read is
    /// false: the usual checks on output and stderr still apply.
    /// </summary>
    public static bool ReportsDirtyHiveWithoutLogs(string stdoutLog)
    {
        try
        {
            return File.ReadLines(stdoutLog).Any(line =>
                line.Contains("hive is dirty and no transaction logs were found", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string Row(WorkResult r, ProcessorRecord? p)
    {
        var fields = new[]
        {
            r.Collection, r.Category, r.Module, r.Iteration ?? "", r.Status.ToString(), r.Reason ?? "",
            r.DurationSeconds.ToString("F1"), p?.Phase ?? "", p?.Executable ?? "", p?.ToolVersion ?? "", p?.ToolSha256 ?? "",
            p?.ExitCode.ToString() ?? "", p is null ? "" : p.StderrExpected ? "expected" : p.WroteToStderr.ToString(),
            p?.OutputFilesCreated.ToString() ?? "", p?.OutputBytes.ToString() ?? "",
            p?.Arguments ?? "", r.Destination,
            p?.PeakMemoryBytes is { } peak ? Math.Ceiling(peak / (1024.0 * 1024)).ToString("F0") : ""
        };
        return string.Join(",", fields.Select(Escape));
    }

    private static string Escape(string value)
    {
        var needsQuotes = value.Contains(',') || value.Contains('"') || value.Contains('\n');
        return needsQuotes ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }

    private static string Sanitise(string value) =>
        string.Concat(value.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
}
