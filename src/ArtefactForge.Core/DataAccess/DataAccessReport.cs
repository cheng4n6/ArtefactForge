using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Core.DataAccess;

/// <summary>
/// The files and folders the case's compromised users opened or browsed, for the client to judge
/// whether sensitive data was reached. Read from the output of modules that already ran:
///
///   LNK files in Recent and Office Recent (LECmd)    opened: LNK modified, and LNK created when
///                                                    it is not after modified (a copied
///                                                    collection's LNK was created when copied)
///   Automatic jump lists (JLECmd)                    opened: DestList last modified per entry
///   ShellBags (SBECmd)                               folder browsed: first and last interacted
///   RecentDocs, OpenSavePidlMRU, Office File MRU     opened (or saved): the times RECmd gives,
///   (RECmd NTUSER batch)                             which is the newest entry of each key only
///   Security 5140 and 5145 (EvtxECmd)                a share, or a file on it, reached over SMB
///
/// A row with no time is left out, and so are the times of a shortcut's or jump list's target
/// file, which say when the file changed, not when the user opened it.
///
///   &lt;collection&gt;\DataAccess\Activity.csv   every account's rows on the host (columns: AccessRow.HostColumns)
///   &lt;collection&gt;\DataAccess\Sources.csv    each artefact: used or not present, and its rows
///   &lt;case&gt;\DataAccess.csv                  the compromised users' rows, sorted by time
///
/// A host's activity is read only when the case has a list of compromised users, because the
/// event log pass is the slow part; the account list is read for every host.
/// </summary>
public static class DataAccessReport
{
    public const string Folder = "DataAccess";
    public const string ActivityFileName = "Activity.csv";
    public const string SourcesFileName = "Sources.csv";
    public const string FileName = "DataAccess.csv";
    public const string ModuleName = "DataAccess";

    public static readonly string[] SourceColumns = ["Source", "Status", "Rows", "Input"];

    public const string LnkRecent = "LNK (Recent)";
    public const string LnkOffice = "LNK (Office Recent)";
    public const string JumpLists = "Jump lists";
    public const string ShellBags = "ShellBags";
    public const string RecentDocs = "RecentDocs";
    public const string OpenSave = "OpenSavePidlMRU";
    public const string OfficeMru = "Office File MRU";
    public const string ShareEvents = "Share access (5140/5145)";

    public static string PathFor(string caseDirectory) => Path.Combine(caseDirectory, FileName);

    /// <summary>
    /// Brings every host's account list, and with a list of compromised users every host's
    /// activity, up to date, then writes the case's UserList.csv and DataAccess.csv. Returns a
    /// result per host whose activity was read, and one for the case when it could not be written.
    /// </summary>
    public static List<WorkResult> Build(string caseDirectory, CancellationToken cancellationToken = default)
    {
        var results = new List<WorkResult>();
        if (!Directory.Exists(caseDirectory)) return results;

        List<CompromisedUser> compromised;
        try { compromised = CaseUsers.ReadCompromised(caseDirectory); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            results.Add(CaseResult(caseDirectory, WorkStatus.Failed, $"could not read {CaseUsers.CompromisedFileName}: {ex.Message}"));
            compromised = [];
        }

        foreach (var collectionDir in CollectionDirectories(caseDirectory))
        {
            if (cancellationToken.IsCancellationRequested) return results;
            try
            {
                BuildUsers(collectionDir);
                if (compromised.Count > 0 && BuildActivity(collectionDir, cancellationToken) is { } result) results.Add(result);
            }
            catch (OperationCanceledException)
            {
                return results;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                results.Add(new WorkResult
                {
                    Collection = Path.GetFileName(collectionDir), Module = ModuleName, Category = Folder,
                    Status = WorkStatus.Failed, Reason = "could not read the host's accounts: " + ex.Message,
                    Destination = Path.Combine(collectionDir, Folder), Started = DateTimeOffset.Now
                });
            }
        }

        try { BuildCase(caseDirectory, compromised, cancellationToken); }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            results.Add(CaseResult(caseDirectory, WorkStatus.Failed, $"could not write {FileName} or {CaseUsers.UserListFileName}: {ex.Message}"));
        }
        return results;
    }

    /// <summary>
    /// Only the account lists: every host's and the case's UserList.csv. Quick, as it reads the
    /// registry output and folder names, so the page can show the accounts as soon as it opens.
    /// </summary>
    public static void BuildUserList(string caseDirectory)
    {
        if (!Directory.Exists(caseDirectory)) return;
        var hosts = CollectionDirectories(caseDirectory).ToList();
        foreach (var host in hosts) BuildUsers(host);
        var users = hosts.SelectMany(h => CaseUsers.ReadUsers(Path.Combine(h, Folder, CaseUsers.HostFileName))).ToList();
        if (users.Count > 0) CaseUsers.WriteUsers(CaseUsers.UserListPathFor(caseDirectory), users);
    }

    /// <summary>The case's UserList.csv from every host's, and DataAccess.csv when there is a list to match.</summary>
    public static void BuildCase(string caseDirectory, IReadOnlyList<CompromisedUser> compromised, CancellationToken cancellationToken = default)
    {
        var hosts = CollectionDirectories(caseDirectory).ToList();
        var users = hosts.SelectMany(h => CaseUsers.ReadUsers(Path.Combine(h, Folder, CaseUsers.HostFileName))).ToList();
        if (users.Count > 0) CaseUsers.WriteUsers(CaseUsers.UserListPathFor(caseDirectory), users);

        var report = PathFor(caseDirectory);
        if (compromised.Count == 0)
        {
            // Derived: with nobody listed there is nothing to report, and an old report would mislead.
            if (File.Exists(report)) File.Delete(report);
            return;
        }

        var seen = new HashSet<(DateTime, string, string, string, string)>();
        var rows = new List<AccessRow>();
        foreach (var host in hosts)
        {
            var file = Path.Combine(host, Folder, ActivityFileName);
            if (!File.Exists(file)) continue;
            foreach (var row in AccessRow.ReadHost(file, cancellationToken))
                if (compromised.Any(u => CaseUsers.Matches(u, row.User, row.Sid)) && seen.Add(row.Key)) rows.Add(row);
        }
        AccessRow.WriteCase(report, rows.OrderBy(r => r.TimeUtc)
                                        .ThenBy(r => r.System, StringComparer.OrdinalIgnoreCase)
                                        .ThenBy(r => r.User, StringComparer.OrdinalIgnoreCase)
                                        .ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>A host's account list, rebuilt when one of its inputs or per-user folders changed.</summary>
    public static void BuildUsers(string collectionDir)
    {
        var outFile = Path.Combine(collectionDir, Folder, CaseUsers.HostFileName);
        var accounts = CaseUsers.ReadHost(collectionDir, HostName(collectionDir));
        if (accounts.Count == 0)
        {
            if (File.Exists(outFile)) File.Delete(outFile);
            return;
        }
        // Cheap enough to read every time; written only when it changed, so its date means something.
        if (File.Exists(outFile) && CaseUsers.ReadUsers(outFile).SequenceEqual(accounts)) return;
        Directory.CreateDirectory(Path.GetDirectoryName(outFile)!);
        CaseUsers.WriteUsers(outFile, accounts);
    }

    /// <summary>
    /// A host's activity. Null when it has none of the artefacts, or nothing changed since it was
    /// read, so hosts with nothing new add nothing to the results.
    /// </summary>
    public static WorkResult? BuildActivity(string collectionDir, CancellationToken cancellationToken = default)
    {
        var name = Path.GetFileName(collectionDir);
        var outDir = Path.Combine(collectionDir, Folder);
        var outFile = Path.Combine(outDir, ActivityFileName);
        var sourcesFile = Path.Combine(outDir, SourcesFileName);

        var inputs = FindInputs(collectionDir);
        var all = inputs.SelectMany(i => i.Files).Concat(CaseUsers.ProfileListFiles(collectionDir)).ToList();
        if (inputs.All(i => i.Files.Count == 0)) return null;
        if (UpToDate([outFile, sourcesFile], all)) return null;

        var stopwatch = Stopwatch.StartNew();
        var started = DateTimeOffset.Now;
        WorkResult Result(WorkStatus status, string reason) => new()
        {
            Collection = name, Module = ModuleName, Category = Folder, Status = status, Reason = reason,
            Destination = outDir, Started = started, DurationSeconds = stopwatch.Elapsed.TotalSeconds
        };

        try
        {
            var system = HostName(collectionDir);
            var sids = CaseUsers.ReadProfiles(collectionDir);
            string SidFor(string user) => sids.FirstOrDefault(p => CaseUsers.SameFolder(p.Name, user))?.Sid ?? "";

            var rows = new List<AccessRow>();
            var sources = new List<string[]>();
            foreach (var input in inputs)
            {
                if (input.Files.Count == 0)
                {
                    sources.Add([input.Source, $"not present: no {input.Module} output", "0", ""]);
                    continue;
                }
                var before = rows.Count;
                foreach (var file in input.Files)
                {
                    var user = UserFor(collectionDir, file, input.Category, input.Marker);
                    foreach (var r in input.Read(file, cancellationToken))
                    {
                        // The profile folder the output sits in; else the hive or LNK's own path, or the event's account.
                        var who = user.Length > 0 ? user : r.User;
                        rows.Add(r with { System = system, User = who, Sid = r.Sid.Length > 0 ? r.Sid : SidFor(who), Source = input.Source });
                    }
                }
                sources.Add([input.Source, "used", (rows.Count - before).ToString(CultureInfo.InvariantCulture),
                             string.Join("; ", input.Files.Select(f => Path.GetRelativePath(collectionDir, f)))]);
            }

            var seen = new HashSet<(DateTime, string, string, string, string)>();
            var unique = rows.Where(r => seen.Add(r.Key)).OrderBy(r => r.TimeUtc).ToList();
            Directory.CreateDirectory(outDir);
            AccessRow.WriteHost(outFile, unique);
            Ioc.AtomicFile.Write(sourcesFile, writer =>
            {
                Linux.CsvFile.WriteRow(writer, SourceColumns);
                foreach (var s in sources) Linux.CsvFile.WriteRow(writer, s);
            });

            var users = unique.Select(r => r.User).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            return Result(WorkStatus.Completed,
                $"{unique.Count:N0} dated file and folder rows for {users} account{(users == 1 ? "" : "s")}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return Result(WorkStatus.Failed, "could not read the host's file and folder activity: " + ex.Message);
        }
    }

    // --- what the page shows ----------------------------------------------------------------------

    /// <summary>A source across the case: how many hosts had it and how many rows it gave.</summary>
    public sealed record SourceSummary(string Source, int Hosts, int Rows);

    public sealed record Summary(int Rows, int Users, int Hosts, IReadOnlyList<SourceSummary> Sources, DateTime? Written);

    /// <summary>The case's report as it stands: its rows, and which artefacts the hosts had.</summary>
    public static Summary Summarise(string caseDirectory)
    {
        var report = PathFor(caseDirectory);
        var rows = 0;
        var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(report))
        {
            foreach (var cell in CaseUsers.Rows(report))
            {
                rows++;
                users.Add(cell("System") + "\\" + cell("User"));
                hosts.Add(cell("System"));
            }
        }

        var sources = new Dictionary<string, (int Hosts, int Rows)>(StringComparer.Ordinal);
        foreach (var host in CollectionDirectories(caseDirectory))
        {
            var file = Path.Combine(host, Folder, SourcesFileName);
            if (!File.Exists(file)) continue;
            foreach (var cell in CaseUsers.Rows(file))
            {
                var name = cell("Source");
                var used = cell("Status") == "used";
                var count = int.TryParse(cell("Rows"), NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : 0;
                var (h, r) = sources.GetValueOrDefault(name);
                sources[name] = (h + (used ? 1 : 0), r + count);
            }
        }

        return new Summary(rows, users.Count, hosts.Count,
                           sources.Select(s => new SourceSummary(s.Key, s.Value.Hosts, s.Value.Rows)).ToList(),
                           File.Exists(report) ? File.GetLastWriteTimeUtc(report) : null);
    }

    // --- inputs -----------------------------------------------------------------------------------

    private sealed record Input(string Source, string Module, string Category, string Marker, List<string> Files,
                                Func<string, CancellationToken, IEnumerable<AccessRow>> Read);

    private static List<Input> FindInputs(string collectionDir)
    {
        List<string> Files(string folder, string pattern) =>
            CaseUsers.Files(collectionDir, folder, pattern, SearchOption.AllDirectories);

        // A module re-run writes beside the old file (EvtxECmd_EventLogs_2.csv); the newest is complete.
        var evtx = Files("EventLogs", "EvtxECmd*.csv").OrderByDescending(File.GetLastWriteTimeUtc).Take(1).ToList();
        return
        [
            new(LnkRecent, "LECmd_Recent", "LNKFiles", "_LECmd_Recent", Files("LNKFiles", "*LECmd_Recent*.csv"), ReadLnk),
            new(LnkOffice, "LECmd_OfficeRecent", "LNKFiles", "_LECmd_OfficeRecent", Files("LNKFiles", "*LECmd_OfficeRecent*.csv"), ReadLnk),
            new(JumpLists, "JLECmd", "JumpLists", "_JLECmd", Files("JumpLists", "*AutomaticDestinations*.csv"), ReadJumpList),
            new(ShellBags, "SBECmd", "ShellBags", "_SBECmd", Files("ShellBags", "*SBECmd*.csv"), ReadShellBags),
            new(RecentDocs, "RECmd_NTUSER", "Registry", "_RECmd_NTUSER", Files("Registry", "*_RECmd_NTUSER_RecentDocs*.csv"), ReadRecentDocs),
            new(OpenSave, "RECmd_NTUSER", "Registry", "_RECmd_NTUSER", Files("Registry", "*_RECmd_NTUSER_OpenSavePidlMRU*.csv"), ReadOpenSave),
            new(OfficeMru, "RECmd_NTUSER", "Registry", "_RECmd_NTUSER", Files("Registry", "*_RECmd_NTUSER_OfficeMRU*.csv"), ReadOfficeMru),
            new(ShareEvents, "EvtxECmd", "EventLogs", "", evtx, ReadShareEvents),
        ];
    }

    /// <summary>
    /// Whose a per-user output file is: the profile folder it sits in, or for output written
    /// before per-user folders, the name in front of the tool's in its file name.
    /// </summary>
    internal static string UserFor(string collectionDir, string file, string category, string marker)
    {
        var categoryDir = Path.Combine(collectionDir, category);
        var parent = Path.GetDirectoryName(file) ?? "";
        if (!string.Equals(Path.TrimEndingDirectorySeparator(parent), Path.TrimEndingDirectorySeparator(categoryDir), StringComparison.OrdinalIgnoreCase)
            && Path.GetRelativePath(categoryDir, parent) is { } relative && !relative.StartsWith(".."))
            return relative.Split(Path.DirectorySeparatorChar)[0];
        if (marker.Length == 0) return "";
        var stem = Path.GetFileNameWithoutExtension(file);
        var at = stem.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        return at > 0 ? stem[..at] : "";
    }

    // --- readers ----------------------------------------------------------------------------------

    private static AccessRow Row(DateTime time, string path, string activity, string user = "", string sid = "") =>
        new(time, "", user, sid, path, activity, "");

    private static DateTime? Time(string text) => IpHistory.ParseEventTime(text.Trim());

    public static IEnumerable<AccessRow> ReadLnk(string file, CancellationToken cancellationToken)
    {
        foreach (var cell in CaseUsers.Rows(file, cancellationToken))
        {
            var target = cell("LocalPath");
            if (target.Length == 0 && cell("NetworkPath").Length > 0)
                target = cell("NetworkPath").TrimEnd('\\') + (cell("CommonPath").Length > 0 ? "\\" + cell("CommonPath").TrimStart('\\') : "");
            if (target.Length == 0) target = cell("TargetIDAbsolutePath");
            if (CleanPath(target) is not { } path) continue;

            var user = UserFromPath(cell("SourceFile"));
            var modified = Time(cell("SourceModified"));
            var created = Time(cell("SourceCreated"));
            if (modified is { } m) yield return Row(m, path, AccessRow.Opened, user);
            // A collection copied without creation times gets them set to when it was copied, later than modified.
            if (created is { } c && (modified is null || c <= modified)) yield return Row(c, path, AccessRow.Opened, user);
        }
    }

    public static IEnumerable<AccessRow> ReadJumpList(string file, CancellationToken cancellationToken)
    {
        foreach (var cell in CaseUsers.Rows(file, cancellationToken))
        {
            var target = cell("Path").Length > 0 ? cell("Path") : cell("LocalPath");
            if (CleanPath(target) is not { } path || Time(cell("LastModified")) is not { } time) continue;
            yield return Row(time, path, AccessRow.Opened, UserFromPath(cell("SourceFile")));
        }
    }

    public static IEnumerable<AccessRow> ReadShellBags(string file, CancellationToken cancellationToken)
    {
        foreach (var cell in CaseUsers.Rows(file, cancellationToken))
        {
            if (CleanPath(cell("AbsolutePath")) is not { } path || !IsFolderPath(path)) continue;
            var user = UserFromPath(cell("SourceFile"));
            var first = Time(cell("FirstInteracted"));
            var last = Time(cell("LastInteracted"));
            if (first is { } f) yield return Row(f, path, AccessRow.FolderBrowsed, user);
            if (last is { } l && l != first) yield return Row(l, path, AccessRow.FolderBrowsed, user);
        }
    }

    public static IEnumerable<AccessRow> ReadRecentDocs(string file, CancellationToken cancellationToken)
    {
        foreach (var cell in CaseUsers.Rows(file, cancellationToken))
        {
            // RecentDocs keeps the file's name only, not its folder.
            if (CleanPath(cell("TargetName")) is not { } path || Time(cell("OpenedOn")) is not { } time) continue;
            yield return Row(time, path, AccessRow.Opened);
        }
    }

    public static IEnumerable<AccessRow> ReadOpenSave(string file, CancellationToken cancellationToken)
    {
        foreach (var cell in CaseUsers.Rows(file, cancellationToken))
        {
            if (CleanPath(cell("AbsolutePath")) is not { } path || Time(cell("OpenedOn")) is not { } time) continue;
            yield return Row(time, path, AccessRow.OpenedOrSaved);
        }
    }

    public static IEnumerable<AccessRow> ReadOfficeMru(string file, CancellationToken cancellationToken)
    {
        foreach (var cell in CaseUsers.Rows(file, cancellationToken))
        {
            if (CleanPath(cell("FileName")) is not { } path || Time(cell("LastOpened")) is not { } time) continue;
            yield return Row(time, path, AccessRow.Opened);
        }
    }

    /// <summary>
    /// Security 5140 (a share was reached) and 5145 (a file or folder on it was checked for
    /// access), from EvtxECmd's CSV. Both need file share auditing, so most hosts have neither.
    /// Failures and computer accounts are left out, and so is IPC$, which is not data.
    /// </summary>
    public static IEnumerable<AccessRow> ReadShareEvents(string file, CancellationToken cancellationToken)
    {
        using var reader = new CsvRecordReader(file);
        var header = reader.ReadRecord();
        if (header is null) yield break;
        int Column(string n) => header.FindIndex(h => h.Trim().TrimStart('\uFEFF').Equals(n, StringComparison.OrdinalIgnoreCase));
        var timeCol = Column("TimeCreated");
        var idCol = Column("EventId");
        var channelCol = Column("Channel");
        var computerCol = Column("Computer");
        var keywordsCol = Column("Keywords");
        var payloadCol = Column("Payload");
        if (timeCol < 0 || idCol < 0 || channelCol < 0 || payloadCol < 0)
            throw new InvalidDataException($"{Path.GetFileName(file)} is not EvtxECmd output: TimeCreated, EventId, Channel or Payload column missing");

        bool Wanted(List<string> f) =>
            f[channelCol].Trim().Equals("Security", StringComparison.OrdinalIgnoreCase) && f[idCol].Trim() is "5140" or "5145";
        var last = new[] { timeCol, idCol, channelCol, computerCol, keywordsCol }.Max();
        Func<List<string>, bool>? wantPayload = payloadCol > last ? Wanted : null;

        var rows = 0;
        while (reader.ReadRecord(last, wantPayload) is { } fields)
        {
            if ((++rows & 0xFFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (fields.Count <= payloadCol || !Wanted(fields)) continue;
            if (keywordsCol >= 0 && fields[keywordsCol].Contains("Failure", StringComparison.OrdinalIgnoreCase)) continue;
            if (IpHistory.ParseEventTime(fields[timeCol]) is not { } time) continue;

            var data = RemoteAccess.Fields(fields[payloadCol]);
            var account = data.GetValueOrDefault("SubjectUserName", "");
            if (account.Length == 0 || account.EndsWith('$')) continue;
            var share = data.GetValueOrDefault("ShareName", "");
            if (share.Length == 0 || share.EndsWith("IPC$", StringComparison.OrdinalIgnoreCase)) continue;

            // \\*\Finance names this host's own share; the event's Computer is the host.
            var computer = computerCol >= 0 ? fields[computerCol].Trim().Split('.')[0] : "";
            if (share.StartsWith(@"\\*\", StringComparison.Ordinal) && computer.Length > 0) share = @"\\" + computer + share[3..];
            var relative = data.GetValueOrDefault("RelativeTargetName", "").Trim().TrimStart('\\');
            var id = fields[idCol].Trim();
            var path = id == "5145" && relative.Length > 0 ? share.TrimEnd('\\') + "\\" + relative : share;

            var domain = data.GetValueOrDefault("SubjectDomainName", "");
            yield return Row(time, path, id == "5145" ? AccessRow.AccessedOverShare : AccessRow.ShareAccessed,
                             domain.Length > 0 ? domain + "\\" + account : account,
                             data.GetValueOrDefault("SubjectUserSid", ""));
        }
    }

    // --- paths ------------------------------------------------------------------------------------

    private static readonly Regex Scheme = new(@"^[A-Za-z][A-Za-z0-9+.\-]+:", RegexOptions.Compiled);
    private static readonly Regex DrivePath = new(@"(?:^|\\)([A-Za-z]:\\.*)$", RegexOptions.Compiled);

    /// <summary>
    /// A path as the client should read it, or null for something that is not a file or folder:
    /// a web address, an app link (ms-teams:) or a shell namespace (::{GUID}). Shell paths that
    /// reach a drive (Desktop\This PC\C:\Finance) start at the drive.
    /// </summary>
    public static string? CleanPath(string text)
    {
        var path = text.Trim();
        if (path.Length == 0 || path.StartsWith("::", StringComparison.Ordinal)
            || path.StartsWith("Internet Folder", StringComparison.OrdinalIgnoreCase)
            || Scheme.IsMatch(path))
            return null;
        var drive = DrivePath.Match(path);
        return drive.Success ? drive.Groups[1].Value : path;
    }

    /// <summary>
    /// ShellBags name every place Explorer showed, including This PC and Quick Access. A folder a
    /// client cares about is on a drive or a share, or below a known folder (Desktop\Downloads\Tools).
    /// </summary>
    private static bool IsFolderPath(string path) =>
        (path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\')
        || path.StartsWith(@"\\", StringComparison.Ordinal)
        || path.Split('\\', StringSplitOptions.RemoveEmptyEntries).Length >= 3;

    private static string UserFromPath(string path)
    {
        var parts = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        var users = Array.FindLastIndex(parts, p => p.Equals("Users", StringComparison.OrdinalIgnoreCase));
        return users >= 0 && users + 1 < parts.Length - 1 ? parts[users + 1] : "";
    }

    // --- helpers ----------------------------------------------------------------------------------

    private static IEnumerable<string> CollectionDirectories(string caseDirectory) =>
        Directory.EnumerateDirectories(caseDirectory)
                 .Where(d => !Path.GetFileName(d).StartsWith('_'))   // _Logs, _Extracted
                 .Order(StringComparer.OrdinalIgnoreCase);

    private static bool UpToDate(IEnumerable<string> outputs, IReadOnlyList<string> inputs)
    {
        var built = DateTime.MaxValue;
        foreach (var output in outputs)
        {
            if (!File.Exists(output)) return false;
            var written = File.GetLastWriteTimeUtc(output);
            if (written < built) built = written;
        }
        return inputs.All(i => File.GetLastWriteTimeUtc(i) <= built);
    }

    internal static string HostName(string collectionDir)
    {
        var summary = Path.Combine(collectionDir, "SystemInfo", "SystemInfo.csv");
        try
        {
            return File.Exists(summary) && IpHistory.ReadFacts(summary).GetValueOrDefault("Hostname", "") is { Length: > 0 } name
                ? name
                : Path.GetFileName(collectionDir);
        }
        catch (IOException)
        {
            return Path.GetFileName(collectionDir);
        }
    }

    private static WorkResult CaseResult(string caseDirectory, WorkStatus status, string reason) => new()
    {
        Collection = Path.GetFileName(caseDirectory),
        Module = ModuleName,
        Category = Folder,
        Status = status,
        Reason = reason,
        Destination = caseDirectory,
        Started = DateTimeOffset.Now
    };
}
