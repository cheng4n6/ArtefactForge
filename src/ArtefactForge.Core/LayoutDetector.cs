namespace ArtefactForge.Core;

/// <summary>
/// Maps a selected evidence path onto a canonical drive root using layout profiles, so
/// modules can reference %root%\Windows\... regardless of how the collection is shaped.
/// </summary>
public static class LayoutDetector
{
    /// <summary>
    /// Returns every target found under <paramref name="selectionPath"/>. Profiles are tried in
    /// Priority order and the first that matches wins; a collection holding several drive-letter
    /// folders yields one target each.
    /// </summary>
    public static IReadOnlyList<ResolvedTarget> Detect(string selectionPath, IEnumerable<LayoutProfile> profiles)
    {
        if (!Directory.Exists(selectionPath))
            return [];

        var selection = Path.GetFullPath(selectionPath).TrimEnd(Path.DirectorySeparatorChar);
        if (selection.Length == 2 && selection[1] == ':') selection += Path.DirectorySeparatorChar;

        var view = new EvidenceView(
            relative =>
            {
                // Path.Combine is safe here: markers contain '$' and drive-letter folders but never
                // a rooted path, unlike the target paths handled elsewhere.
                var full = Path.Combine(selection, relative);
                return File.Exists(full) || Directory.Exists(full);
            },
            () => SafeEnumerateDirectories(selection).Select(Path.GetFileName).OfType<string>());

        return Detect(view, profiles, (root, profile, driveFolder, multiple) =>
            BuildTarget(selection, root is null ? selection : Path.Combine(selection, root),
                        profile, driveFolder, multiple));
    }

    /// <summary>
    /// The same detection run over the entry names of a zip, so a collection can be recognised
    /// - and named - before anything is extracted. The targets carry the zip as their
    /// <see cref="ResolvedTarget.ArchivePath"/> and are named after the zip file, which is how
    /// CyLR records the host, unless <paramref name="name"/> gives a better one.
    /// </summary>
    public static IReadOnlyList<ResolvedTarget> DetectArchive(
        string zipPath, IEnumerable<string> entryNames, IEnumerable<LayoutProfile> profiles, string? name = null)
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var topFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in entryNames)
        {
            var parts = raw.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;

            // A directory entry ends in '/'; a file entry implies every folder above it.
            var isFolder = raw.EndsWith('/') || raw.EndsWith('\\');
            for (var i = 1; i < parts.Length; i++) folders.Add(string.Join('\\', parts[..i]));
            if (isFolder) folders.Add(string.Join('\\', parts));
            else files.Add(string.Join('\\', parts));
            if (parts.Length > 1 || isFolder) topFolders.Add(parts[0]);
        }

        var view = new EvidenceView(relative => files.Contains(relative) || folders.Contains(relative),
                                    () => topFolders);
        var fullZip = Path.GetFullPath(zipPath);
        if (string.IsNullOrWhiteSpace(name)) name = CollectionSource.Stem(fullZip);
        if (string.IsNullOrWhiteSpace(name)) name = "Collection";

        return Detect(view, profiles, (_, profile, driveFolder, multiple) => new ResolvedTarget
        {
            SelectionPath  = fullZip,
            Root           = fullZip,
            Layout         = profile,
            DriveLetter    = driveFolder,
            IsLive         = false,
            CollectionName = multiple ? $"{name}_{driveFolder}" : name,
            ArchivePath    = fullZip
        });
    }

    /// <summary>
    /// What detection needs to know about the evidence, whether it is a folder on disk or the
    /// entry list of a zip: whether a relative path exists, and which folders sit at the top.
    /// </summary>
    private sealed record EvidenceView(Func<string, bool> Exists, Func<IEnumerable<string>> TopFolders);

    /// <summary>Makes a target from a match: root is relative to the selection, null for the selection itself.</summary>
    private delegate ResolvedTarget TargetFactory(string? root, LayoutProfile profile, string? driveFolder, bool multiple);

    private static IReadOnlyList<ResolvedTarget> Detect(
        EvidenceView view, IEnumerable<LayoutProfile> profiles, TargetFactory build)
    {
        foreach (var profile in profiles.OrderBy(p => p.Priority))
        {
            var matches = Match(view, profile, build);
            if (matches.Count > 0) return matches;
        }
        return [];
    }

    private static List<ResolvedTarget> Match(EvidenceView view, LayoutProfile profile, TargetFactory build)
    {
        var found = new List<ResolvedTarget>();

        if (profile.Detect.RootIsSelection && MarkersMatch(view, profile, driveFolder: null))
        {
            found.Add(build(null, profile, driveFolder: null, multiple: false));
            return found;
        }

        if (!profile.Detect.DriveLetterFolder) return found;

        var driveFolders = view.TopFolders()
            .Where(name => name.Length == 1 && char.IsLetter(name[0]))
            .Where(name => MarkersMatch(view, profile, name))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var folder in driveFolders)
        {
            var root = profile.Resolve.RootOffset == "?" ? folder : null;
            found.Add(build(root, profile, folder, multiple: driveFolders.Count > 1));
        }
        return found;
    }

    /// <summary>
    /// Lists subdirectories without throwing. Every drive root carries 'System Volume Information',
    /// readable only by SYSTEM, so a batch run pointed at a mounted image would otherwise die on a
    /// folder that could never have been evidence. A directory we cannot read simply does not match.
    /// </summary>
    private static IEnumerable<string> SafeEnumerateDirectories(string path)
    {
        try { return Directory.EnumerateDirectories(path).ToList(); }
        catch (UnauthorizedAccessException) { return []; }
        catch (DirectoryNotFoundException) { return []; }
        catch (IOException) { return []; }
    }

    private static bool MarkersMatch(EvidenceView view, LayoutProfile profile, string? driveFolder)
    {
        var markers = profile.Detect.Markers;
        if (markers.Count == 0) return false;

        var hits = markers.Count(marker => MarkerExists(view, marker, driveFolder));
        return profile.Detect.MatchMode == MarkerMatchMode.All ? hits == markers.Count : hits > 0;
    }

    private static bool MarkerExists(EvidenceView view, string marker, string? driveFolder)
    {
        // Layouts write markers with either separator ('etc/passwd', '?\$MFT').
        var relative = marker.Replace("?", driveFolder ?? string.Empty)
                             .Replace('/', '\\')
                             .TrimStart('\\');
        return relative.Length > 0 && view.Exists(relative.Replace('\\', Path.DirectorySeparatorChar));
    }

    private static ResolvedTarget BuildTarget(
        string selection, string root, LayoutProfile profile, string? driveFolder, bool multiple)
    {
        var letter = driveFolder
                     ?? (root.Length >= 2 && root[1] == ':' ? root[..1] : null);

        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System))
                          ?? "C:\\";
        var isLive = profile.Detect.RootIsSelection
                     && string.Equals(EnsureTrailingSeparator(root), systemDrive, StringComparison.OrdinalIgnoreCase);

        var baseName = root.Length >= 2 && root[1] == ':' && root.TrimEnd(Path.DirectorySeparatorChar).Length == 2
            ? (isLive ? Environment.MachineName : DriveRootName(root, letter))
            : Path.GetFileName(selection.TrimEnd(Path.DirectorySeparatorChar));

        if (string.IsNullOrWhiteSpace(baseName)) baseName = "Collection";

        return new ResolvedTarget
        {
            SelectionPath  = selection,
            Root           = root,
            Layout         = profile,
            DriveLetter    = letter,
            IsLive         = isLive,
            CollectionName = multiple ? $"{baseName}_{letter}" : baseName
        };
    }

    /// <summary>
    /// Names a mounted drive that is not this machine's. A Windows volume is named after the host
    /// in its own SYSTEM hive, so a mounted image reads as WKSTN-042 rather than the drive letter
    /// it happened to get; anything else keeps IMAGE_&lt;letter&gt;.
    /// </summary>
    public static string DriveRootName(string root, string? letter) =>
        WindowsHostName.FromRoot(root) ?? $"IMAGE_{letter}";

    private static string EnsureTrailingSeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;
}
