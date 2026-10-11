using System.Security.Principal;

namespace ArtefactForge.Core;

public sealed class RunPlan
{
    public List<WorkItem> Items { get; } = [];
    /// <summary>Modules that will not run, each carrying the reason - the Skip-Module equivalent.</summary>
    public List<WorkResult> Skipped { get; } = [];
}

public static class RunPlanner
{
    /// <summary>
    /// Plans every target that is on disk. Zipped targets are left out: their Requires can only be
    /// checked once they are extracted, so the engine plans each one then, through the overload.
    /// </summary>
    public static RunPlan Build(RunConfiguration config) =>
        Build(config, config.Targets.Where(t => !t.IsArchive));

    public static RunPlan Build(RunConfiguration config, IEnumerable<ResolvedTarget> targets)
    {
        var plan = new RunPlan();
        var elevated = IsElevated();

        foreach (var target in targets)
        {
            // Modules that cannot apply to this kind of target at all - the other platform's, or
            // live-only against a collection - are reported once per collection rather than one
            // line each. In a mixed batch they were most of the plan, and they buried the skips
            // worth reading: an artefact that should have been there and was not.
            var notApplicable = new List<ModuleDefinition>();

            foreach (var module in config.Modules.OrderBy(m => m.Priority))
            {
                if (!Applies(module, target)) { notApplicable.Add(module); continue; }

                var reason = Ineligible(module, target, elevated);
                if (reason is not null) { plan.Skipped.Add(Skip(module, target, reason)); continue; }

                switch (module.Iterate)
                {
                    case IterationMode.UserProfile: PlanPerUser(config, plan, module, target); break;
                    case IterationMode.Match:       PlanPerMatch(config, plan, module, target); break;
                    default:                        PlanSingle(config, plan, module, target); break;
                }
            }

            if (notApplicable.Count > 0)
                plan.Skipped.Add(new WorkResult
                {
                    Collection = target.CollectionName,
                    Module = $"{notApplicable.Count} module(s)",
                    Category = "",
                    Status = WorkStatus.Skipped,
                    Reason = $"not applicable to this target ({target.Kind}): "
                             + string.Join(", ", notApplicable.Select(m => m.Name)),
                    Destination = "",
                    Started = DateTimeOffset.Now
                });
        }
        return plan;
    }

    /// <summary>
    /// Whether a module can apply to this kind of target at all: the right platform, and the right
    /// side of live versus collected. Anything declaring Any, on either side, applies.
    /// </summary>
    public static bool Applies(ModuleDefinition module, ResolvedTarget target)
    {
        var platform = target.Layout.Platform;
        if (module.Platform != Platform.Any && platform != Platform.Any && module.Platform != platform) return false;
        if (module.Scope == TargetScope.LiveOnly && !target.IsLive) return false;
        if (module.Scope == TargetScope.OfflineOnly && target.IsLive) return false;
        return true;
    }

    private static string? Ineligible(ModuleDefinition module, ResolvedTarget target, bool elevated)
    {
        // Platform and live/offline scope are settled by Applies() before this is reached.
        if (module.Elevation == ElevationRequirement.Required && !elevated)
            return "requires an elevated session";
        // Checked before Requires: unelevated, a locked or admin-only path reads as absent, and
        // "not present" would wrongly suggest the system has no such artefact.
        if (module.Elevation == ElevationRequirement.Live && target.IsLive && !elevated)
            return "requires an elevated session on a live system";
        return null;
    }

    private static void PlanSingle(RunConfiguration config, RunPlan plan, ModuleDefinition module, ResolvedTarget target)
    {
        var missing = FirstUnmatched(module.Requires, target.Root, user: null);
        if (missing is not null) { plan.Skipped.Add(Skip(module, target, $"not present: {missing}")); return; }

        plan.Items.Add(new WorkItem
        {
            Module = module,
            Target = target,
            Destination = Destination(config, target, module, null)
        });
    }

    private static void PlanPerUser(RunConfiguration config, RunPlan plan, ModuleDefinition module, ResolvedTarget target)
    {
        var users = UserProfiles(target);
        if (users.Count == 0) { plan.Skipped.Add(Skip(module, target, "no user profiles found")); return; }

        var planned = 0;
        foreach (var user in users)
        {
            // Requires is re-checked per user: only profiles that actually hold the artefact run,
            // so an empty Default or Public profile is not reported as NoOutput.
            if (FirstUnmatched(module.Requires, target.Root, user.Name, user.Path) is not null) continue;

            plan.Items.Add(new WorkItem
            {
                Module = module,
                Target = target,
                IterationKey = user.Name,
                UserHome = user.Path,
                UserFolder = Sanitise(user.Name),
                Destination = Destination(config, target, module, Sanitise(user.Name))
            });
            planned++;
        }

        if (planned == 0)
            plan.Skipped.Add(Skip(module, target, "no user profile contains the required artefact"));
    }

    private static void PlanPerMatch(RunConfiguration config, RunPlan plan, ModuleDefinition module, ResolvedTarget target)
    {
        if (module.Requires.Count == 0)
        {
            plan.Skipped.Add(Skip(module, target, "Iterate: match needs at least one Requires glob"));
            return;
        }

        var matches = PathGlob.Expand(Resolve(module.Requires[0], target.Root, null));
        if (matches.Count == 0)
        {
            plan.Skipped.Add(Skip(module, target, $"not present: {module.Requires[0]}"));
            return;
        }

        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var match in matches)
        {
            // The key becomes the filename prefix, which is what keeps iterations apart: WxTCmd,
            // SrumECmd and SumECmd have no --csvf, so one would otherwise overwrite the next.
            // Prefer the owning user name: the immediate parent is often opaque, e.g.
            // ConnectedDevicesPlatform\6b7f60cf4f325ff8\ActivitiesCache.db.
            var owner = UserFromPath(match, target);
            var key = owner
                      ?? (Path.GetFileName(Path.GetDirectoryName(match) ?? "") is { Length: > 0 } parent
                          ? parent
                          : Path.GetFileNameWithoutExtension(match));

            var unique = key;
            for (var n = 2; !used.Add(unique); n++) unique = $"{key}_{n}";

            // A match inside a profile goes in that user's folder; one outside them all stays in
            // the category folder, since its key is only a parent directory name.
            var userFolder = owner is null ? null : Sanitise(owner);
            plan.Items.Add(new WorkItem
            {
                Module = module,
                Target = target,
                IterationKey = unique,
                MatchPath = match,
                UserFolder = userFolder,
                Destination = Destination(config, target, module, userFolder)
            });
        }
    }

    /// <summary>The profile a matched path belongs to, or null when it sits outside them all.</summary>
    private static string? UserFromPath(string match, ResolvedTarget target)
    {
        foreach (var profile in UserProfiles(target))
        {
            var prefix = profile.Path.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (match.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return profile.Name;
        }
        return null;
    }

    /// <summary>
    /// Profile directories, from the patterns the layout declares. Windows keeps them all under
    /// Users; Linux splits ordinary users under /home from root's own directory, so the patterns
    /// are a list and each may be a glob or a single directory.
    ///
    /// Junctions are skipped - on Windows 'Default User' and 'All Users' are reparse points into
    /// other profiles, and following them would process the same artefacts twice under two names.
    /// </summary>
    public static List<UserProfileDirectory> UserProfiles(ResolvedTarget target)
    {
        var root = target.Root.TrimEnd(Path.DirectorySeparatorChar);
        var found = new Dictionary<string, UserProfileDirectory>(StringComparer.OrdinalIgnoreCase);

        foreach (var pattern in target.Layout.Resolve.UserProfiles)
        {
            var normalised = pattern.Replace('/', Path.DirectorySeparatorChar)
                                    .TrimStart(Path.DirectorySeparatorChar);
            if (normalised.Length == 0) continue;

            foreach (var path in PathGlob.Expand(Path.Combine(root, normalised)))
            {
                if (!Directory.Exists(path)) continue;

                try
                {
                    if (new DirectoryInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
                if (name.Length > 0) found.TryAdd(path, new UserProfileDirectory(name, path));
            }
        }

        return found.Values.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string? FirstUnmatched(IReadOnlyList<string> requires, string root,
                                          string? user = null, string? userHome = null)
    {
        foreach (var requirement in requires)
            if (!PathGlob.AnyMatch(Resolve(requirement, root, user, userHome)))
                return requirement;
        return null;
    }

    private static string Resolve(string pattern, string root, string? user, string? userHome = null) =>
        pattern.Replace("%root%", root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
               // Before %user%, or the shorter token would eat the start of the longer one.
               .Replace("%userHome%", userHome ?? Path.Combine(root, "*"), StringComparison.OrdinalIgnoreCase)
               .Replace("%user%", user ?? "*", StringComparison.OrdinalIgnoreCase);

    private static string Destination(RunConfiguration config, ResolvedTarget target, ModuleDefinition module, string? userFolder)
    {
        // One folder per category, shared by every module in it, so output is grouped by artefact
        // type rather than scattered across a folder per tool. Per-user output goes one level
        // down, in a folder per profile, so one user's registry, LNK or ShellBags files sit together.
        var category = Path.Combine(config.OutputRoot, config.CaseName, target.CollectionName, module.Category);
        return userFolder is null ? category : Path.Combine(category, userFolder);
    }

    private static WorkResult Skip(ModuleDefinition module, ResolvedTarget target, string reason) => new()
    {
        Collection = target.CollectionName,
        Module = module.Name,
        Category = module.Category,
        Status = WorkStatus.Skipped,
        Reason = reason,
        Started = DateTimeOffset.Now
    };

    private static string Sanitise(string value) =>
        string.Concat(value.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
