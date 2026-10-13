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

    public int Count(WorkStatus status) => Results.Count(r => r.Status == status);

    /// <summary>Statuses an analyst must look at: something ran but may not have produced evidence.</summary>
    public int NeedsReview => Count(WorkStatus.Failed) + Count(WorkStatus.NoOutput)
                            + Count(WorkStatus.CheckLog) + Count(WorkStatus.ToolMissing)
                            + Count(WorkStatus.TimedOut);
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
        // One memory-heavy tool at a time across the whole run, zips included: three Chainsaw runs
        // at once took about 18 GB and brought down a 16 GB workstation.
        using var memoryHeavy = new SemaphoreSlim(1);

        // What the manifest lists as processed: zips appear once extracted, under their real root.
        var collections = config.Targets.Where(t => !t.IsArchive)
            .Select(t => new CollectionRecord(t.CollectionName, t.Root, t.Layout.Id, t.IsLive, null))
            .ToList();

        // Zips run concurrently with each other and with collections on disk, so the report,
        // the manifest's collection list and the resume state are shared and locked.
        var gate = new object();

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

        report.Results.AddRange(results);
        // Reads the modules' output, so it runs once they are done; before the manifest, which
        // lists which IP history sources each domain controller had.
        report.Results.AddRange(Windows.IpHistory.Build(caseDir, cancellationToken));
        report.Results.AddRange(Windows.RemoteAccess.Build(caseDir, cancellationToken));   // for the RDP trace
        report.DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds;

        SaveState(statePath, completed, results);
        WriteManifests(report, logDir, config, collections, started);
        await Ioc.IocSweep.AfterRunAsync(report);   // the case's IOC hits for the hosts just processed

        // Rolls the per-collection system summaries into one inventory for the case. Runs after
        // everything else because it reads what the modules produced, and does nothing when no
        // collection produced a summary. The evidence list reads the same summaries.
        report.InventoryPath = SystemInventory.Build(caseDir);
        report.EvidenceList = EvidenceList.Rebuild(caseDir);
        Report.CaseReport.AfterRun(report);   // last: the case report reads everything above
        return report;

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
                pending = items.Where(i => !completed.Contains(i.Key)).OrderBy(i => i.Module.Priority).ToList();
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

            var ran = new ConcurrentBag<WorkResult>();
            var tasks = pending.Select(async item =>
            {
                // Memory-heavy tools queue only on their own slot, not for a worker or a heavy-IO
                // slot. Run one at a time they are the long pole of a batch; queued behind
                // everything else they would all run at the end, one after another. This way the
                // first starts at once and the rest follow back to back while the pool works
                // through the other modules beside them, at the cost of one process more than
                // Workers and Heavy IO allow.
                var isMemoryHeavy = item.Module.MemoryWeight == MemoryWeight.Heavy;
                var isHeavy = !isMemoryHeavy && item.Module.IoWeight == IoWeight.Heavy;
                if (isMemoryHeavy) await memoryHeavy.WaitAsync(cancellationToken);
                else await workers.WaitAsync(cancellationToken);
                if (isHeavy) await heavy.WaitAsync(cancellationToken);
                try
                {
                    Progress?.Invoke(new ProgressEvent(item, WorkStatus.Running));
                    WorkResult result;
                    try
                    {
                        result = await ExecuteAsync(item, config, consoleDir, stagingRoot, cancellationToken);
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
                    Progress?.Invoke(new ProgressEvent(item, result.Status, result.Reason));
                }
                finally
                {
                    if (isHeavy) heavy.Release();
                    if (isMemoryHeavy) memoryHeavy.Release();
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

    private async Task<WorkResult> ExecuteAsync(
        WorkItem item, RunConfiguration config, string consoleDir, string stagingRoot,
        CancellationToken cancellationToken)
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

            var arguments = Placeholders.Resolve(processor.CommandLine, context);
            var workingDirectory = string.IsNullOrWhiteSpace(processor.WorkingDirectory)
                ? null
                : Placeholders.Resolve(processor.WorkingDirectory, context);

            var stdout = Path.Combine(consoleDir, stem + ".log");
            var stderr = Path.Combine(consoleDir, stem + ".err.log");

            var outcome = Builtins.IsBuiltin(tool.FullPath)
                ? await Builtins.RunAsync(tool.FullPath, arguments, stdout, stderr, item.Module.Timeout, cancellationToken)
                : await ProcessRunner.RunAsync(
                    tool.FullPath, arguments, stdout, stderr, item.Module.Timeout, cancellationToken, workingDirectory);

            // A process killed part-way - timed out or cancelled - may have left files half written.
            // They are kept, because a partial CSV can still be evidence of what the tool reached,
            // but never beside finished output where they would pass for complete: they go to
            // <collection>\_Incomplete\<category>\ instead, and the reason says so.
            var killed = outcome.TimedOut || cancellationToken.IsCancellationRequested;
            var harvestTo = killed ? IncompleteDestination(item.Destination, item.UserFolder) : item.Destination;
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
            if (!killed)
            {
                delivered += harvested.Files.Count - harvested.Empty - harvested.Failed;
                emptyFiles += harvested.Empty;
            }
            var partialNote = killed && harvested.Files.Count > 0
                ? $"; {harvested.Files.Count} partial file(s) kept in {Path.Combine("_Incomplete", item.UserFolder is null ? Path.GetFileName(item.Destination) : Path.Combine(Path.GetFileName(Path.GetDirectoryName(item.Destination) ?? ""), item.UserFolder))}"
                : "";

            result.Processors.Add(new ProcessorRecord
            {
                Phase = phase,
                Executable = tool.FullPath,
                Arguments = arguments,
                ToolVersion = tool.Version,
                ToolSha256 = tool.Sha256,
                WorkingDirectory = Builtins.IsBuiltin(tool.FullPath)
                    ? ""
                    : workingDirectory ?? Path.GetDirectoryName(tool.FullPath) ?? "",
                ExitCode = outcome.ExitCode,
                WroteToStderr = outcome.WroteToStderr,
                StderrExpected = outcome.WroteToStderr && OnlyExpectedStderr(stderr, processor.ExpectedStderr),
                DurationSeconds = outcome.DurationSeconds,
                StdoutLog = stdout,
                StderrLog = stderr,
                OutputFilesCreated = harvested.Files.Count,
                OutputBytes = harvested.Bytes,
                OutputFiles = harvested.Files,
                Error = outcome.Error ?? outcome.LogError
            });

            if (outcome.TimedOut)
            {
                result.Status = WorkStatus.TimedOut;
                result.Reason = partialNote.Length == 0 ? outcome.Error : outcome.Error?.TrimEnd('.') + partialNote;
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
            if (outcome.LogError is not null)
            {
                result.Status = WorkStatus.Failed;
                result.Reason = (phase == "prepare" ? "preparation step " + (index + 1) + ": " : "")
                                + outcome.LogError + " - is the output disk full?";
                return false;
            }

            if (outcome.ExitCode != 0)
            {
                // Some staging tools report failure for conditions that still leave a usable copy.
                if (processor.ContinueOnError) return true;

                result.Status = WorkStatus.Failed;
                result.Reason = (phase == "prepare" ? "preparation step " + (index + 1) + " failed: " : "")
                                + "exit code " + outcome.ExitCode + "; see " + Path.GetFileName(stderr);
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

        result.DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds;
        return result;
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
            Vss = config.Vss,
            Cancelled = report.Cancelled,
            Collections = collections,
            Extractions = report.Extractions,
            Results = ordered
        };
        File.WriteAllText(Path.Combine(logDir, "manifest.json"), JsonSerializer.Serialize(manifest, JsonOptions));

        var csv = new StringBuilder();
        csv.AppendLine("Collection,Category,Module,Iteration,Status,Reason,DurationSec,Phase,Executable,ToolVersion,ToolSha256,ExitCode,Stderr,OutputFiles,OutputBytes,CommandLine,Destination");
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

    private static string Row(WorkResult r, ProcessorRecord? p)
    {
        var fields = new[]
        {
            r.Collection, r.Category, r.Module, r.Iteration ?? "", r.Status.ToString(), r.Reason ?? "",
            r.DurationSeconds.ToString("F1"), p?.Phase ?? "", p?.Executable ?? "", p?.ToolVersion ?? "", p?.ToolSha256 ?? "",
            p?.ExitCode.ToString() ?? "", p is null ? "" : p.StderrExpected ? "expected" : p.WroteToStderr.ToString(),
            p?.OutputFilesCreated.ToString() ?? "", p?.OutputBytes.ToString() ?? "",
            p?.Arguments ?? "", r.Destination
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
