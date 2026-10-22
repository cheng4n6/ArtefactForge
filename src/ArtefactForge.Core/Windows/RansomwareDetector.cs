using System.Globalization;

namespace ArtefactForge.Core.Windows;

/// <summary>
/// What the analyst has settled for a host, from Ransomware-Overrides.csv. A null value is not
/// settled; an empty one is "none" (the analyst says there is no extension, or no note). The
/// sweep sets hold every value confirmed anywhere in the case, looked for on every host.
/// </summary>
public sealed record RansomwareHints(
    string? Extension, string? NoteName, IReadOnlySet<string> SweepExtensions, IReadOnlySet<string> SweepNotes)
{
    public static RansomwareHints None { get; } = new(null, null, new HashSet<string>(), new HashSet<string>());

    /// <summary>A stable text form, stored with the host's result so a change to it rebuilds the host.</summary>
    public string Key() =>
        $"v1;ext={Extension ?? "-"};note={NoteName ?? "-"};"
        + $"sweepExt={string.Join("|", SweepExtensions.Order(StringComparer.Ordinal))};"
        + $"sweepNote={string.Join("|", SweepNotes.Order(StringComparer.Ordinal))}";
}

/// <summary>What the detector found on one host, before it is saved.</summary>
internal sealed record RansomwareDetection(
    RansomwareFinding Finding, List<RansomwareEvidence> Evidence, List<(string Path, string ResidentBase64)> NoteSources);

/// <summary>
/// Finds the signs of ransomware in a host's MFTECmd output: the extension added to encrypted
/// files, the ransom note, and when encryption ran.
///
/// Extension. In the USN journal, a rename that adds to the name (report.docx to
/// report.docx.lockbit) is what encryption in place looks like. One extension added to many
/// files, in many folders, to files of several types, is the finding. In the MFT, which still
/// holds the files when the journal has wrapped or was not collected, it is an extension that
/// nearly always follows another one (docx, pdf, jpg) and does so across many folders.
///
/// The type count is what keeps real systems quiet: Windows and installers rename and create
/// files with a second extension in bulk too (.dll.old, .dll.mui, .js.map, Windows Update's .mum
/// and .cat), but always behind the same one or two types, or in one or two folders. Measured on
/// a real workstation (2026-10-22): no extension passes both the folder and the type counts.
///
/// Note. The same file name, at the same size, in many folders, written within a few hours. The
/// name must either read like a note (README, DECRYPT, RESTORE and the like) or sit in the
/// folders that hold the encrypted files. Python and Node packages put identical files in
/// thousands of folders (__init__.py, INSTALLER), so neither the count nor the size is enough.
/// </summary>
internal static class RansomwareDetector
{
    // USN: renames that add the extension.
    internal const int UsnMinFiles = 50;
    internal const int UsnMinFolders = 5;
    internal const int UsnMinTypes = 3;

    // MFT: files with the extension behind another one.
    internal const int MftMinFiles = 50;
    internal const int MftMinFolders = 10;
    internal const int MftMinTypes = 5;
    internal const double MftMinShare = 0.8;
    private const double MaxOneType = 0.75;
    private static readonly TimeSpan MftWindow = TimeSpan.FromHours(24);
    private const double MftMinInWindow = 0.5;

    internal const int NoteMinFolders = 10;
    private const double NoteSameSizeShare = 0.9;
    private static readonly TimeSpan NoteWindow = TimeSpan.FromHours(6);
    private const long NoteMaxSize = 1 << 20;
    private const long NoteMinSize = 16;

    // The journal starting this close before the first rename means it may have lost the start.
    private static readonly TimeSpan JournalMargin = TimeSpan.FromMinutes(10);

    // What software adds or swaps in bulk as a matter of course. Never reported unless confirmed.
    private static readonly HashSet<string> Routine = new(StringComparer.OrdinalIgnoreCase)
    {
        "tmp", "temp", "old", "bak", "bk", "backup", "orig", "prev", "sav", "save", "new", "partial", "part",
        "crdownload", "download", "log", "lock", "swp", "deleting", "deletepending", "vsctmp", "af-old",
        "cache", "etl", "mui", "map", "config", "manifest", "cat", "mum", "gz", "zip", "7z", "sig", "sha256",
        "md5", "asc", "meta", "lnk", "url", "ini", "dat"
    };

    private static readonly HashSet<string> NoteExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "txt", "hta", "html", "htm", "rtf", "url", "mht"
    };

    private static readonly string[] NoteWords =
    [
        "readme", "read_me", "read-me", "decrypt", "restore", "recover", "how_to", "how-to", "howto", "ransom",
        "instruction", "unlock", "encrypt", "help_", "_help", "!!!"
    ];

    private readonly record struct MftFile(
        string Folder, string Name, long Size, bool InUse, DateTime? Created, DateTime? Changed, string Resident);

    private readonly record struct Rename(string Folder, string OldName, string NewName, DateTime? Time, string Key);

    // Software keeps its own second-extension files under these (Program Files\...\logo.png.DATA,
    // AppData\...\index.d.ts), and ransomware commonly leaves them alone so the machine still
    // starts. A candidate is judged on the files outside them; once found, every file counts.
    private static readonly string[] SystemFolders =
        [@".\Windows", @".\Program Files", @".\ProgramData", @".\$Recycle.Bin", @"\AppData\"];

    private static bool IsSystemFolder(string folder) =>
        SystemFolders.Any(s => s[0] == '.'
            ? folder.StartsWith(s, StringComparison.OrdinalIgnoreCase)   // also Program Files (x86)
            : folder.Contains(s, StringComparison.OrdinalIgnoreCase) || folder.EndsWith(s.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));

    private sealed class ExtensionStats
    {
        public readonly List<MftFile> Files = [];   // behind another extension (all files, when forced)
        // The rest count only files outside the system folders.
        public int UserFiles;
        public readonly TypeCounts Types = new();
        public readonly HashSet<string> Folders = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The types an extension was added to. Encryption takes whatever is in a folder, so no one
    /// type is most of it; tooling that adds a second extension does it to one type (.d.ts,
    /// .dll.mui, .js.map), and real names with dots in them (jquery.min.js) add a long tail.
    /// </summary>
    private sealed class TypeCounts
    {
        private readonly Dictionary<string, int> _counts = new(StringComparer.OrdinalIgnoreCase);
        private int _total;

        public void Add(string type)
        {
            _counts[type] = _counts.GetValueOrDefault(type) + 1;
            _total++;
        }

        /// <summary>At least this many types with this many files each, and none more than three quarters of them.</summary>
        public bool Varied(int types, int each) =>
            _total > 0 && _counts.Count(c => c.Value >= each) >= types && _counts.Values.Max() < _total * MaxOneType;
    }

    private sealed class RenameStats
    {
        public readonly List<Rename> Renames = [];
        public readonly HashSet<string> Files = new(StringComparer.Ordinal);
        // The rest count only renames outside the system folders.
        public int UserFiles;
        public readonly TypeCounts Types = new();
        public readonly HashSet<string> Folders = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>"lockbit", ".LockBit" or " .lockbit " as ".lockbit"; empty stays empty.</summary>
    public static string NormaliseExtension(string extension)
    {
        var e = extension.Trim().TrimStart('.').ToLowerInvariant();
        return e.Length == 0 ? "" : "." + e;
    }

    public static RansomwareDetection Detect(string collection, string? mftPath, string? usnPath, RansomwareHints hints,
                                             CancellationToken cancellationToken = default)
    {
        var forced = new HashSet<string>(hints.SweepExtensions.Select(e => e.TrimStart('.')), StringComparer.OrdinalIgnoreCase);
        if (hints.Extension is { Length: > 0 } o) forced.Add(o.TrimStart('.'));
        var forcedNotes = new HashSet<string>(hints.SweepNotes, StringComparer.OrdinalIgnoreCase);
        if (hints.NoteName is { Length: > 0 } n) forcedNotes.Add(n);

        var mft = mftPath is null ? null : ReadMft(mftPath, forced, forcedNotes, cancellationToken);
        var usn = usnPath is null ? null : ReadUsn(usnPath, forced, cancellationToken);

        var detail = new List<string>();
        var evidence = new List<RansomwareEvidence>();

        // --- extension ---
        string extension = "";
        string extensionBasis = "";
        if (hints.Extension is { } settled)
        {
            extension = NormaliseExtension(settled);
            if (extension.Length > 0)
            {
                var detected = Candidates(mft, usn).FirstOrDefault();
                extensionBasis = detected.Extension == extension.TrimStart('.') ? RansomwareFinding.Confirmed : RansomwareFinding.Override;
            }
        }
        else
        {
            var candidates = Candidates(mft, usn);
            if (candidates.Count > 0)
            {
                extension = "." + candidates[0].Extension;
                extensionBasis = RansomwareFinding.Detected;
                if (candidates.Count > 1)
                    detail.Add("other candidate extensions: "
                               + string.Join(", ", candidates.Skip(1).Take(5).Select(c => $".{c.Extension} ({c.Files:N0} files)")));
            }
            else
            {
                // Confirmed on another host: found here at any count.
                var swept = hints.SweepExtensions
                    .Select(e => (Extension: e, Files: Math.Max(Count(usn, e), mft?.Stats.GetValueOrDefault(e.TrimStart('.'))?.Files.Count ?? 0)))
                    .Where(c => c.Files > 0)
                    .OrderByDescending(c => c.Files)
                    .FirstOrDefault();
                if (swept.Files > 0)
                {
                    extension = NormaliseExtension(swept.Extension);
                    extensionBasis = RansomwareFinding.Swept;
                }
            }
        }

        DateTime? start = null, finish = null;
        var earliestSeen = false;
        long files = 0;
        int? peak = null;
        var source = "";
        HashSet<string> encryptedFolders = new(StringComparer.OrdinalIgnoreCase);

        if (extension.Length > 0)
        {
            var bare = extension.TrimStart('.');
            var renames = usn?.Stats.GetValueOrDefault(bare);
            var mftFiles = mft?.Stats.GetValueOrDefault(bare)?.Files ?? [];
            encryptedFolders.UnionWith(mftFiles.Select(f => f.Folder));
            if (renames is not null) encryptedFolders.UnionWith(renames.Renames.Select(r => r.Folder));

            foreach (var r in renames?.Renames ?? [])
                evidence.Add(new RansomwareEvidence(RansomwareEvidence.Renamed, r.Time, r.Folder, r.NewName, r.OldName, null, null, "USN"));
            foreach (var f in mftFiles)
                evidence.Add(new RansomwareEvidence(RansomwareEvidence.EncryptedFile, f.Changed, f.Folder, f.Name, "", f.Size, f.InUse, "MFT"));

            var usnTimes = (renames?.Renames ?? []).Select(r => r.Time).OfType<DateTime>().Order().ToList();
            var mftTimes = mftFiles.Select(f => f.Changed).OfType<DateTime>().Order().ToList();
            var usnCount = renames?.Files.Count ?? 0;
            files = Math.Max(usnCount, mftFiles.Count);

            if (usnTimes.Count > 0)
            {
                start = usnTimes[0];
                finish = usnTimes[^1];
                source = "USN";
                peak = Peak(usnTimes);
                if (usn!.JournalStart is { } journalStart && start - journalStart < JournalMargin)
                {
                    earliestSeen = true;
                    detail.Add($"the USN journal starts at {IpHistoryRecord.Format(journalStart)} UTC, just before the first rename: it may have wrapped during encryption");
                }
                if (mftFiles.Count > usnCount * 1.2 + 10)
                {
                    earliestSeen = true;
                    detail.Add($"the MFT holds {mftFiles.Count:N0} files with {extension} but the journal renamed {usnCount:N0}: the rest are older than the journal");
                    if (mftTimes.Count > 0 && mftTimes[0] < start) start = mftTimes[0];
                    source = "USN and MFT";
                }
            }
            else if (mftTimes.Count > 0)
            {
                start = mftTimes[0];
                finish = mftTimes[^1];
                earliestSeen = true;
                source = "MFT";
                peak = Peak(mftTimes);
                detail.Add(usn is null
                    ? "no USN journal output, so the times are the files' last MFT record changes"
                    : "no renames to it in the USN journal, so the times are the files' last MFT record changes");
            }

            var sample = renames?.Renames.FirstOrDefault();
            if (sample is { } s) detail.Add($"e.g. {s.OldName} renamed to {s.NewName}");
        }
        else if (hints.Extension is { Length: 0 })
        {
            detail.Add("no extension, as set in Ransomware-Overrides.csv");
        }

        // --- note ---
        var note = FindNote(mft, hints, encryptedFolders);
        string noteName = "", noteBasis = "";
        long? noteSize = null;
        var noteFolders = 0;
        var noteSources = new List<(string, string)>();
        if (note is { } found)
        {
            noteName = found.Name;
            noteBasis = found.Basis;
            noteSize = found.Size;
            noteFolders = found.Copies.Select(c => c.Folder).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            foreach (var c in found.Copies)
                evidence.Add(new RansomwareEvidence(RansomwareEvidence.RansomNote, c.Created, c.Folder, c.Name, "", c.Size, c.InUse, "MFT"));

            // Where the note can be read from: the collection, through the $MFT's own path, or
            // the MFT itself when the note is small enough to be resident.
            var root = mft?.Root;
            foreach (var c in found.Copies.Where(c => c.InUse && c.Size == found.Size).Take(20))
            {
                var path = root is null ? "" : Path.Combine(root, c.Folder.TrimStart('.', '\\'), c.Name);
                noteSources.Add((path, c.Resident));
            }

            if (start is null)
            {
                var created = found.Copies.Select(c => c.Created).OfType<DateTime>().Order().ToList();
                if (created.Count > 0)
                {
                    start = created[0];
                    finish = created[^1];
                    earliestSeen = true;
                    source = "MFT";
                    detail.Add("no extension found, so the times are when the note's copies were created");
                }
            }
        }
        else if (hints.NoteName is { Length: 0 })
        {
            detail.Add("no ransom note, as set in Ransomware-Overrides.csv");
        }

        if (mft is null)
            detail.Add("no MFT output (FileSystem\\MFTECmd_MFT.csv), so no note could be looked for - run MFTECmd_MFT");
        if (usn is null && extension.Length > 0 && source != "MFT")
            detail.Add("no USN journal output");

        var anything = extension.Length > 0 || noteName.Length > 0;
        double? rate = null;
        if (anything && start is { } a && finish is { } b && files > 0)
            rate = files / Math.Max(1.0, (b - a).TotalMinutes);

        var finding = new RansomwareFinding
        {
            Collection = collection,
            Status = anything ? RansomwareFinding.Found : RansomwareFinding.NoneFound,
            Extension = extension,
            ExtensionBasis = extensionBasis,
            NoteName = noteName,
            NoteBasis = noteBasis,
            NoteSize = noteSize,
            NoteFolders = noteFolders,
            StartUtc = anything ? start : null,
            StartIsEarliestSeen = anything && earliestSeen,
            FinishUtc = anything ? finish : null,
            FilesAffected = files,
            RatePerMinute = rate is null ? null : Math.Round(rate.Value, 1),
            PeakPerMinute = peak,
            Source = anything ? source : "",
            Detail = string.Join("; ", detail)
        };
        return new RansomwareDetection(finding, evidence, noteSources);
    }

    // --- extension candidates -------------------------------------------------------------------

    private readonly record struct Candidate(string Extension, int Files);

    private static List<Candidate> Candidates(MftRead? mft, UsnRead? usn)
    {
        var found = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var (ext, s) in usn?.Stats ?? new Dictionary<string, RenameStats>())
            if (!Routine.Contains(ext) && s.UserFiles >= UsnMinFiles && s.Folders.Count >= UsnMinFolders && s.Types.Varied(UsnMinTypes, 2))
                found[ext] = s.Files.Count;
        foreach (var (ext, s) in mft?.Stats ?? new Dictionary<string, ExtensionStats>())
        {
            if (Routine.Contains(ext) || s.UserFiles < MftMinFiles || s.Folders.Count < MftMinFolders
                || !s.Types.Varied(MftMinTypes, 3) || s.Files.Count < mft!.Totals.GetValueOrDefault(ext) * MftMinShare)
                continue;
            // Encryption runs in hours. A browser's resilience copies (logo.png.DATA, one set per
            // version it installs) pass every count above but are spread over months.
            var times = s.Files.Select(f => f.Changed).OfType<DateTime>().Order().ToList();
            if (MostWithin(times, MftWindow) < s.Files.Count * MftMinInWindow) continue;
            found[ext] = Math.Max(found.GetValueOrDefault(ext), s.Files.Count);
        }
        return found.Select(f => new Candidate(f.Key, f.Value))
                    .OrderByDescending(c => c.Files).ThenBy(c => c.Extension, StringComparer.Ordinal).ToList();
    }

    private static int Count(UsnRead? usn, string extension) =>
        usn?.Stats.GetValueOrDefault(extension.TrimStart('.'))?.Files.Count ?? 0;

    private static int Peak(IReadOnlyList<DateTime> sorted)
    {
        var peak = 0;
        foreach (var minute in sorted.GroupBy(t => t.Ticks / TimeSpan.TicksPerMinute)) peak = Math.Max(peak, minute.Count());
        return peak;
    }

    /// <summary>A real file type for the extension before the added one: one to five letters or digits, at least one a letter.</summary>
    private static bool IsType(string part) =>
        part.Length is >= 1 and <= 5 && part.All(char.IsAsciiLetterOrDigit) && part.Any(char.IsAsciiLetter);

    /// <summary>An extension that could be a ransomware one: a letter in it, no spaces, not absurdly long.</summary>
    private static bool IsCandidateExtension(string ext) =>
        ext.Length is >= 1 and <= 40 && ext.Any(char.IsLetter) && !ext.Any(char.IsWhiteSpace);

    // --- note -----------------------------------------------------------------------------------

    private sealed record Note(string Name, string Basis, long Size, List<MftFile> Copies);

    private static Note? FindNote(MftRead? mft, RansomwareHints hints, HashSet<string> encryptedFolders)
    {
        if (mft is null) return null;

        if (hints.NoteName is { } settled)
        {
            if (settled.Length == 0) return null;
            var copies = mft.Notes.GetValueOrDefault(settled) ?? [];
            var basis = Detect(mft, encryptedFolders)?.Name.Equals(settled, StringComparison.OrdinalIgnoreCase) == true
                ? RansomwareFinding.Confirmed
                : RansomwareFinding.Override;
            return new Note(copies.FirstOrDefault().Name ?? settled, basis, DominantSize(copies) ?? 0, copies);
        }

        if (Detect(mft, encryptedFolders) is { } detected) return detected;

        var swept = hints.SweepNotes
            .Select(n => mft.Notes.GetValueOrDefault(n) ?? [])
            .Where(c => c.Count > 0)
            .OrderByDescending(c => c.Count)
            .FirstOrDefault();
        return swept is null ? null : new Note(swept[0].Name, RansomwareFinding.Swept, DominantSize(swept) ?? 0, swept);

        static Note? Detect(MftRead mft, HashSet<string> encryptedFolders)
        {
            Note? best = null;
            var bestScore = 0.0;
            foreach (var (name, copies) in mft.Notes)
            {
                if (copies.Count < NoteMinFolders || DominantSize(copies) is not { } size) continue;
                var same = copies.Where(c => c.Size == size).ToList();
                if (same.Count < copies.Count * NoteSameSizeShare || same.Count < NoteMinFolders) continue;
                if (size is < NoteMinSize or > NoteMaxSize) continue;
                if (!NoteExtensions.Contains(Path.GetExtension(name).TrimStart('.'))) continue;

                var created = same.Select(c => c.Created).OfType<DateTime>().Order().ToList();
                if (MostWithin(created, NoteWindow) < same.Count * NoteSameSizeShare) continue;

                // The same package installed many times puts the file in many folders of one name
                // (site-packages\win32com); a note goes into whatever folders there are.
                var leaves = same.Select(c => LeafName(c.Folder)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                if (leaves < same.Count * 0.5) continue;

                var withEncrypted = encryptedFolders.Count == 0 ? 0 : same.Count(c => encryptedFolders.Contains(c.Folder));
                var besideFiles = withEncrypted >= same.Count * 0.5;
                var lower = name.ToLowerInvariant();
                var reads = NoteWords.Any(lower.Contains);
                if (!besideFiles && !reads) continue;

                var score = same.Count * (besideFiles ? 10.0 : 1.0) * (reads ? 2.0 : 1.0);
                if (score > bestScore)
                {
                    bestScore = score;
                    best = new Note(same[0].Name, RansomwareFinding.Detected, size, copies);
                }
            }
            return best;
        }
    }

    private static string LeafName(string folder)
    {
        var at = folder.TrimEnd('\\').LastIndexOf('\\');
        return at < 0 ? folder : folder[(at + 1)..];
    }

    private static long? DominantSize(List<MftFile> copies) =>
        copies.Count == 0 ? null : copies.GroupBy(c => c.Size).OrderByDescending(g => g.Count()).First().Key;

    /// <summary>The most of these sorted times that fall inside any one window of this length.</summary>
    private static int MostWithin(List<DateTime> sorted, TimeSpan window)
    {
        var most = 0;
        for (int i = 0, j = 0; i < sorted.Count; i++)
        {
            while (sorted[i] - sorted[j] > window) j++;
            most = Math.Max(most, i - j + 1);
        }
        return most;
    }

    // --- reading MFTECmd output -----------------------------------------------------------------

    private sealed class MftRead
    {
        public string? Root;
        public readonly Dictionary<string, ExtensionStats> Stats = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Every file with each extension, the share's denominator.</summary>
        public readonly Dictionary<string, int> Totals = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, List<MftFile>> Notes = new(StringComparer.OrdinalIgnoreCase);
    }

    private static MftRead ReadMft(string path, HashSet<string> forced, HashSet<string> forcedNotes, CancellationToken cancellationToken)
    {
        var read = new MftRead();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord() ?? throw new InvalidDataException($"{Path.GetFileName(path)} is empty");
        int Column(string n) => header.FindIndex(h => h.Trim().Equals(n, StringComparison.OrdinalIgnoreCase));
        var nameCol = Column("FileName");
        var folderCol = Column("ParentPath");
        var sizeCol = Column("FileSize");
        var dirCol = Column("IsDirectory");
        if (nameCol < 0 || folderCol < 0 || sizeCol < 0 || dirCol < 0)
            throw new InvalidDataException($"{Path.GetFileName(path)} is not MFTECmd $MFT output: FileName, ParentPath, FileSize or IsDirectory column missing");
        var inUseCol = Column("InUse");
        var adsCol = Column("IsAds");
        var nameTypeCol = Column("NameType");
        var createdCol = Column("Created0x10");
        var modifiedCol = Column("LastModified0x10");
        var changedCol = Column("LastRecordChange0x10");
        var sourceCol = Column("SourceFile");
        var residentCol = Column("ResidentDataBase64");

        var rows = 0;
        while (reader.ReadRecord() is { } f)
        {
            if ((++rows & 0xFFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (f.Count <= Math.Max(Math.Max(nameCol, folderCol), Math.Max(sizeCol, dirCol))) continue;
            string Cell(int i) => i >= 0 && i < f.Count ? f[i] : "";

            if (read.Root is null && Cell(sourceCol) is { Length: > 0 } source)
                read.Root = Path.GetDirectoryName(source);
            if (Cell(dirCol).Equals("True", StringComparison.OrdinalIgnoreCase)) continue;
            if (Cell(adsCol).Equals("True", StringComparison.OrdinalIgnoreCase)) continue;
            // The 8.3 name of a file that also has a long one: the same file twice.
            if (Cell(nameTypeCol).Equals("Dos", StringComparison.OrdinalIgnoreCase)) continue;

            var name = f[nameCol];
            var parts = name.Split('.');
            if (parts.Length < 2 && !forcedNotes.Contains(name)) continue;
            var ext = parts.Length < 2 ? "" : parts[^1];

            var addedTo = parts.Length >= 3 ? parts[1..^1].FirstOrDefault(IsType) : null;
            var isForced = ext.Length > 0 && forced.Contains(ext);
            var noteLike = forcedNotes.Contains(name) || NoteExtensions.Contains(ext);
            if (ext.Length > 0)
            {
                read.Totals[ext] = read.Totals.GetValueOrDefault(ext) + 1;
                if ((addedTo is not null && IsCandidateExtension(ext)) || isForced)
                {
                    if (!read.Stats.TryGetValue(ext, out var stats)) read.Stats[ext] = stats = new ExtensionStats();
                    var file = Parse();
                    stats.Files.Add(file);
                    if (!IsSystemFolder(file.Folder))
                    {
                        stats.UserFiles++;
                        if (addedTo is not null) stats.Types.Add(addedTo);
                        stats.Folders.Add(file.Folder);
                    }
                }
            }

            if (noteLike)
            {
                var file = Parse();
                if (forcedNotes.Contains(name) || file.Size is >= NoteMinSize and <= NoteMaxSize)
                {
                    if (!read.Notes.TryGetValue(name, out var copies)) read.Notes[name] = copies = [];
                    copies.Add(file);
                }
            }

            MftFile Parse() => new(
                f[folderCol], name,
                long.TryParse(f[sizeCol], CultureInfo.InvariantCulture, out var size) ? size : 0,
                !Cell(inUseCol).Equals("False", StringComparison.OrdinalIgnoreCase),
                ParseTime(Cell(createdCol)),
                ParseTime(Cell(changedCol)) ?? ParseTime(Cell(modifiedCol)),
                Cell(residentCol));
        }
        return read;
    }

    private sealed class UsnRead
    {
        public DateTime? JournalStart;
        public readonly Dictionary<string, RenameStats> Stats = new(StringComparer.OrdinalIgnoreCase);
    }

    private static UsnRead ReadUsn(string path, HashSet<string> forced, CancellationToken cancellationToken)
    {
        var read = new UsnRead();
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord() ?? throw new InvalidDataException($"{Path.GetFileName(path)} is empty");
        int Column(string n) => header.FindIndex(h => h.Trim().Equals(n, StringComparison.OrdinalIgnoreCase));
        var nameCol = Column("Name");
        var entryCol = Column("EntryNumber");
        var seqCol = Column("SequenceNumber");
        var folderCol = Column("ParentPath");
        var timeCol = Column("UpdateTimestamp");
        var reasonsCol = Column("UpdateReasons");
        if (nameCol < 0 || entryCol < 0 || timeCol < 0 || reasonsCol < 0)
            throw new InvalidDataException($"{Path.GetFileName(path)} is not MFTECmd USN journal output: Name, EntryNumber, UpdateTimestamp or UpdateReasons column missing");
        var last = new[] { nameCol, entryCol, timeCol, reasonsCol }.Max();

        // The old name of each file part-way through a rename, by MFT entry and sequence.
        var pending = new Dictionary<string, string>(StringComparer.Ordinal);
        var rows = 0;
        while (reader.ReadRecord() is { } f)
        {
            if ((++rows & 0xFFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (f.Count <= last) continue;
            var time = ParseTime(f[timeCol]);
            if (time is { } t && (read.JournalStart is null || t < read.JournalStart)) read.JournalStart = t;

            var reasons = f[reasonsCol];
            var key = f[entryCol] + "-" + (seqCol >= 0 && seqCol < f.Count ? f[seqCol] : "");
            if (reasons.Contains("RenameOldName", StringComparison.Ordinal))
            {
                pending[key] = f[nameCol];
                continue;
            }
            if (!reasons.Contains("RenameNewName", StringComparison.Ordinal) || !pending.Remove(key, out var oldName)) continue;

            var newName = f[nameCol];
            var ext = Path.GetExtension(newName).TrimStart('.');
            if (ext.Length == 0) continue;
            var appended = newName.Length > oldName.Length + 1
                           && newName.StartsWith(oldName + ".", StringComparison.OrdinalIgnoreCase);
            var swapped = forced.Contains(ext) && !Path.GetExtension(oldName).TrimStart('.').Equals(ext, StringComparison.OrdinalIgnoreCase);
            if (!(appended && IsCandidateExtension(ext)) && !swapped) continue;

            if (!read.Stats.TryGetValue(ext, out var stats)) read.Stats[ext] = stats = new RenameStats();
            var folder = folderCol >= 0 && folderCol < f.Count ? f[folderCol] : "";
            stats.Renames.Add(new Rename(folder, oldName, newName, time, key));
            stats.Files.Add(key);
            if (IsSystemFolder(folder)) continue;
            stats.UserFiles++;
            stats.Folders.Add(folder);
            var type = Path.GetExtension(oldName).TrimStart('.');
            if (IsType(type)) stats.Types.Add(type);
        }
        return read;
    }

    /// <summary>MFTECmd's times, 2026-10-09 19:53:24.7804040, to the second. They are UTC.</summary>
    private static DateTime? ParseTime(string text) =>
        text.Length >= 19 ? IpHistoryRecord.ParseTime(text[..19]) : null;
}
