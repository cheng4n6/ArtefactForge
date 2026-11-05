using ArtefactForge.Core.Ioc;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Core.DataAccess;

/// <summary>One account seen on one host: from the registry, the per-user output folders or passwd.</summary>
public sealed record UserAccount(string System, string Username, string Sid, string ProfilePath, string Source);

/// <summary>One row of CompromisedUsers.csv: a username, a SID, or both.</summary>
public sealed record CompromisedUser(string Username, string Sid);

/// <summary>One account across the case: every host it was seen on, under one SID or one name.</summary>
public sealed record AccountGroup(string Username, string Sid, IReadOnlyList<UserAccount> Accounts)
{
    public CompromisedUser AsCompromised => new(Username, Sid);
    public bool IsListed(IEnumerable<CompromisedUser> compromised) =>
        compromised.Any(u => Accounts.Count == 0 ? Same(u) : Accounts.Any(a => CaseUsers.Matches(u, a.Username, a.Sid)));
    private bool Same(CompromisedUser u) =>
        u.Username.Equals(Username, StringComparison.OrdinalIgnoreCase) && u.Sid.Equals(Sid, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// The case's accounts and the analyst's list of compromised ones.
///
///   &lt;collection&gt;\DataAccess\Users.csv   the host's accounts (columns: UserColumns)
///   &lt;case&gt;\UserList.csv                  every host's accounts, to check names and SIDs against
///   &lt;case&gt;\CompromisedUsers.csv          the analyst's: Username and/or SID per row. ArtefactForge
///                                            adds and removes only the rows the analyst ticks or
///                                            unticks on the Data access page; every other row,
///                                            and any extra column, is kept as it is.
/// </summary>
public static class CaseUsers
{
    public const string UserListFileName = "UserList.csv";
    public const string CompromisedFileName = "CompromisedUsers.csv";
    public const string HostFileName = "Users.csv";

    public static readonly string[] UserColumns = ["System", "Username", "SID", "ProfilePath", "Source"];
    public static readonly string[] CompromisedColumns = ["Username", "SID", "Comment"];

    // Profiles that are not accounts: templates and the shared folder.
    private static readonly HashSet<string> NotAccounts =
        new(["Default", "Default User", "Public", "All Users"], StringComparer.OrdinalIgnoreCase);

    // The per-user output categories: one folder per profile below each.
    internal static readonly string[] PerUserCategories = ["Registry", "LNKFiles", "JumpLists", "ShellBags", "Timeline", "UserFiles"];

    public static string UserListPathFor(string caseDirectory) => Path.Combine(caseDirectory, UserListFileName);

    public static string CompromisedPathFor(string caseDirectory) => Path.Combine(caseDirectory, CompromisedFileName);

    // --- a host's accounts ------------------------------------------------------------------------

    /// <summary>The files a host's account list is read from.</summary>
    internal static List<string> UserInputs(string collectionDir) =>
    [
        .. ProfileListFiles(collectionDir),
        .. Files(collectionDir, "Registry", "*UserAccounts*.csv", SearchOption.TopDirectoryOnly),
        .. Files(collectionDir, "Users", "*passwd*.csv", SearchOption.TopDirectoryOnly)
    ];

    internal static List<string> ProfileListFiles(string collectionDir) =>
        Files(collectionDir, "Registry", "*ProfileList*.csv", SearchOption.TopDirectoryOnly);

    /// <summary>
    /// A host's accounts: ProfileList (SID and profile folder), the SAM's local accounts, the
    /// profile folders AF wrote per-user output into, and on Linux the passwd accounts that can log on.
    /// </summary>
    public static List<UserAccount> ReadHost(string collectionDir, string system)
    {
        var accounts = new List<UserAccount>();
        var profiles = ReadProfiles(collectionDir);
        foreach (var p in profiles)
            accounts.Add(new UserAccount(system, p.Name, p.Sid, p.Path, "ProfileList"));

        foreach (var file in Files(collectionDir, "Registry", "*UserAccounts*.csv", SearchOption.TopDirectoryOnly))
        {
            foreach (var cell in Rows(file))
            {
                var name = cell("UserName").Trim();
                if (name.Length == 0) continue;
                var rid = cell("UserId").Trim();
                // The SAM holds the RID only; the SID is the profile's whose folder and RID agree.
                var sid = profiles.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
                                                       && rid.Length > 0 && p.Sid.EndsWith("-" + rid, StringComparison.Ordinal))?.Sid ?? "";
                accounts.Add(new UserAccount(system, name, sid, "", "SAM"));
            }
        }

        foreach (var folder in UserFolders(collectionDir))
        {
            var sid = profiles.FirstOrDefault(p => SameFolder(p.Name, folder))?.Sid ?? "";
            accounts.Add(new UserAccount(system, folder, sid, "", "Output folders"));
        }

        foreach (var file in Files(collectionDir, "Users", "*passwd*.csv", SearchOption.TopDirectoryOnly))
        {
            foreach (var cell in Rows(file))
            {
                var name = cell("Username").Trim();
                if (name.Length == 0 || !cell("CanLogin").Trim().Equals("yes", StringComparison.OrdinalIgnoreCase)) continue;
                accounts.Add(new UserAccount(system, name, "", cell("HomeDir").Trim(), "passwd"));
            }
        }

        return Merge(accounts);
    }

    /// <summary>One row per account: the sources that saw it joined, a SID or profile path filled from any of them.</summary>
    internal static List<UserAccount> Merge(IEnumerable<UserAccount> accounts)
    {
        var merged = new List<UserAccount>();
        foreach (var group in accounts.GroupBy(a => (a.System.ToUpperInvariant(), a.Username.ToUpperInvariant())))
        {
            // Two SIDs for one name (a local and a domain account both called admin) stay two rows.
            var sids = group.Select(a => a.Sid).Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            foreach (var sid in sids.Count == 0 ? [""] : sids)
            {
                var rows = group.Where(a => a.Sid.Length == 0 || a.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase)).ToList();
                var first = rows[0];
                merged.Add(first with
                {
                    Sid = sid,
                    ProfilePath = rows.Select(a => a.ProfilePath).FirstOrDefault(p => p.Length > 0) ?? "",
                    Source = string.Join("; ", rows.Select(a => a.Source).Distinct(StringComparer.OrdinalIgnoreCase))
                });
            }
        }
        return merged.OrderBy(a => a.System, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(a => a.Username, StringComparer.OrdinalIgnoreCase)
                     .ToList();
    }

    /// <summary>A profile from ProfileList: its SID, its folder and the folder's name.</summary>
    internal sealed record Profile(string Sid, string Path, string Name);

    internal static List<Profile> ReadProfiles(string collectionDir)
    {
        var profiles = new List<Profile>();
        foreach (var file in ProfileListFiles(collectionDir))
        {
            foreach (var cell in Rows(file))
            {
                var sid = cell("KeyName").Trim();
                var path = cell("ProfileImagePath").Trim();
                // LocalSystem, LocalService and NetworkService: not people.
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || path.Length == 0) continue;
                var name = path.TrimEnd('\\', '/').Split('\\', '/').Last();
                if (profiles.Any(p => p.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase))) continue;
                profiles.Add(new Profile(sid, path, name));
            }
        }
        return profiles;
    }

    /// <summary>The profile folders AF wrote per-user output into on this host.</summary>
    internal static List<string> UserFolders(string collectionDir) =>
        PerUserCategories.Select(c => Path.Combine(collectionDir, c))
                         .Where(Directory.Exists)
                         .SelectMany(Directory.EnumerateDirectories)
                         .Select(d => Path.GetFileName(d))
                         .Where(n => !NotAccounts.Contains(n))
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .Order(StringComparer.OrdinalIgnoreCase)
                         .ToList();

    /// <summary>
    /// A profile folder name against an output folder name: the output folder is the profile name
    /// with characters a file name cannot hold replaced by '_'.
    /// </summary>
    internal static bool SameFolder(string profileName, string folder) =>
        string.Concat(profileName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c))
              .Equals(folder, StringComparison.OrdinalIgnoreCase);

    public static void WriteUsers(string path, IEnumerable<UserAccount> accounts) =>
        AtomicFile.Write(path, writer =>
        {
            Linux.CsvFile.WriteRow(writer, UserColumns);
            foreach (var a in accounts) Linux.CsvFile.WriteRow(writer, a.System, a.Username, a.Sid, a.ProfilePath, a.Source);
        });

    public static List<UserAccount> ReadUsers(string path)
    {
        var rows = new List<UserAccount>();
        if (!File.Exists(path)) return rows;
        foreach (var cell in Rows(path))
        {
            if (cell("Username").Length == 0) continue;
            rows.Add(new UserAccount(cell("System"), cell("Username"), cell("SID"), cell("ProfilePath"), cell("Source")));
        }
        return rows;
    }

    /// <summary>The case's UserList.csv, or none when it has not been built.</summary>
    public static List<UserAccount> LoadUserList(string caseDirectory) => ReadUsers(UserListPathFor(caseDirectory));

    // --- the compromised users --------------------------------------------------------------------

    /// <summary>The analyst's list. None when the file is missing; a file without its columns stops the report.</summary>
    public static List<CompromisedUser> ReadCompromised(string caseDirectory)
    {
        var path = CompromisedPathFor(caseDirectory);
        var rows = new List<CompromisedUser>();
        if (!File.Exists(path)) return rows;

        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) return rows;
        var index = Index(header);
        if (!index.ContainsKey("Username") && !index.ContainsKey("SID"))
            throw new InvalidDataException($"{CompromisedFileName} needs a Username or SID column on its first line");

        while (reader.ReadRecord() is { } fields)
        {
            string Cell(string n) => index.TryGetValue(n, out var i) && i < fields.Count ? fields[i].Trim() : "";
            var user = new CompromisedUser(Cell("Username"), Cell("SID"));
            if (user.Username.Length == 0 && user.Sid.Length == 0) continue;
            if (!rows.Contains(user)) rows.Add(user);
        }
        return rows;
    }

    /// <summary>
    /// Adds an account to CompromisedUsers.csv, creating it with its header when the case has none.
    /// Every row already there stays exactly as it is.
    /// </summary>
    public static void AddCompromised(string caseDirectory, CompromisedUser user, string comment = "")
    {
        var path = CompromisedPathFor(caseDirectory);
        var lines = ReadLines(path);
        if (lines.Count == 0) lines.Add(Line(CompromisedColumns));
        if (ReadCompromised(caseDirectory).Any(u => Same(u, user))) return;

        var header = CsvText.Split(lines[0]).Select(h => h.Trim()).ToList();
        var cells = header.Select(h => h.ToUpperInvariant() switch
        {
            "USERNAME" => user.Username,
            "SID" => user.Sid,
            "COMMENT" => comment,
            _ => ""
        }).ToArray();
        lines.Add(Line(cells));
        AtomicFile.WriteAllText(path, string.Join("\r\n", lines) + "\r\n");
    }

    /// <summary>Removes the rows that name exactly this account. Every other row stays as it is.</summary>
    public static void RemoveCompromised(string caseDirectory, CompromisedUser user)
    {
        var path = CompromisedPathFor(caseDirectory);
        var lines = ReadLines(path);
        if (lines.Count < 2) return;
        var header = CsvText.Split(lines[0]).Select(h => h.Trim()).ToList();
        var userAt = header.FindIndex(h => h.Equals("Username", StringComparison.OrdinalIgnoreCase));
        var sidAt = header.FindIndex(h => h.Equals("SID", StringComparison.OrdinalIgnoreCase));

        var kept = new List<string> { lines[0] };
        foreach (var line in lines.Skip(1))
        {
            var fields = CsvText.Split(line);
            string Cell(int i) => i >= 0 && i < fields.Length ? fields[i].Trim() : "";
            if (!Same(new CompromisedUser(Cell(userAt), Cell(sidAt)), user)) kept.Add(line);
        }
        if (kept.Count == lines.Count) return;
        AtomicFile.WriteAllText(path, string.Join("\r\n", kept) + "\r\n");
    }

    /// <summary>Creates CompromisedUsers.csv with only its header when the case has none. An existing file is left alone.</summary>
    public static string EnsureCompromisedFile(string caseDirectory)
    {
        var path = CompromisedPathFor(caseDirectory);
        if (!File.Exists(path)) AtomicFile.WriteAllText(path, Line(CompromisedColumns) + "\r\n");
        return path;
    }

    private static bool Same(CompromisedUser a, CompromisedUser b) =>
        a.Username.Equals(b.Username, StringComparison.OrdinalIgnoreCase) && a.Sid.Equals(b.Sid, StringComparison.OrdinalIgnoreCase);

    // --- grouping ---------------------------------------------------------------------------------

    /// <summary>
    /// The accounts as one entry per account rather than per host. Accounts with a SID group by
    /// it, so a domain account is one entry and two hosts' local Administrators stay two. An
    /// account without a SID (a profile folder, a Linux user) joins the one SID entry of that
    /// name (the one on its own host, when several hosts have a local account of that name), or
    /// else the entry for that name, with profile folder suffixes (user.000, user.CORP) ignored
    /// the way <see cref="Matches"/> ignores them.
    /// </summary>
    public static List<AccountGroup> Group(IEnumerable<UserAccount> accounts)
    {
        var all = accounts.ToList();
        var bySid = all.Where(a => a.Sid.Length > 0)
                       .GroupBy(a => a.Sid, StringComparer.OrdinalIgnoreCase)
                       .Select(g => (Name: g.GroupBy(a => a.Username, StringComparer.OrdinalIgnoreCase)
                                            .OrderByDescending(n => n.Count()).ThenBy(n => n.Key.Length).First().Key,
                                     Sid: g.Key, Members: g.ToList()))
                       .ToList();
        var byName = new List<(string Name, List<UserAccount> Members)>();

        // Shorter names first, so jsmith is the entry jsmith.CORP joins rather than the other way round.
        foreach (var a in all.Where(a => a.Sid.Length == 0).OrderBy(a => a.Username.Length))
        {
            var bare = new CompromisedUser("", "");
            var sidMatches = bySid.Where(g => Matches(bare with { Username = g.Name }, a.Username, "")).ToList();
            // Two hosts' local accounts of that name: the one on this account's own host.
            if (sidMatches.Count > 1)
                sidMatches = sidMatches.Where(g => g.Members.Any(m => m.System.Equals(a.System, StringComparison.OrdinalIgnoreCase))).ToList();
            if (sidMatches.Count == 1)
            {
                sidMatches[0].Members.Add(a);
                continue;
            }
            var named = byName.FindIndex(g => Matches(bare with { Username = g.Name }, a.Username, ""));
            if (named >= 0) byName[named].Members.Add(a);
            else byName.Add((a.Username, [a]));
        }

        return bySid.Select(g => new AccountGroup(g.Name, g.Sid, Ordered(g.Members)))
                    .Concat(byName.Select(g => new AccountGroup(g.Name, "", Ordered(g.Members))))
                    .OrderBy(g => g.Username, StringComparer.OrdinalIgnoreCase)
                    .ToList();

        static List<UserAccount> Ordered(List<UserAccount> members) =>
            members.OrderBy(m => m.System, StringComparer.OrdinalIgnoreCase).ThenBy(m => m.Username, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // --- matching ---------------------------------------------------------------------------------

    /// <summary>
    /// Whether an account in the output is one of the compromised. A SID is compared when both
    /// sides have one, so a local admin and a domain admin are told apart; otherwise the names
    /// are, without the domain (DOMAIN\user, user@domain) and without the suffix Windows adds to
    /// a second profile folder for the same name (user.000, user.CORP).
    /// </summary>
    public static bool Matches(CompromisedUser user, string name, string sid)
    {
        if (user.Sid.Length > 0 && sid.Length > 0) return user.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase);
        if (user.Username.Length == 0) return false;
        var (wanted, domain) = Split(user.Username);
        var (candidate, _) = Split(name);
        if (wanted.Length == 0 || candidate.Length == 0) return false;
        if (wanted.Equals(candidate, StringComparison.OrdinalIgnoreCase)) return true;

        // Profile folder suffixes, peeled one at a time: jsmith.CORP.001 is jsmith.
        while (candidate.LastIndexOf('.') is var dot and > 0)
        {
            var suffix = candidate[(dot + 1)..];
            var isSuffix = suffix.Length > 0
                           && (suffix.All(char.IsAsciiDigit)
                               || (domain.Length > 0 && suffix.Equals(domain, StringComparison.OrdinalIgnoreCase))
                               || suffix.All(c => char.IsAsciiLetterUpper(c) || char.IsAsciiDigit(c) || c == '-'));
            if (!isSuffix) return false;
            candidate = candidate[..dot];
            if (wanted.Equals(candidate, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>The account name without its domain, and the domain when it was given as DOMAIN\user.</summary>
    private static (string Name, string Domain) Split(string account)
    {
        var text = account.Trim();
        var slash = text.LastIndexOf('\\');
        if (slash >= 0) return (text[(slash + 1)..], text[..slash]);
        var at = text.IndexOf('@');
        return at > 0 ? (text[..at], "") : (text, "");
    }

    // --- helpers ----------------------------------------------------------------------------------

    internal static List<string> Files(string collectionDir, string folder, string pattern, SearchOption option)
    {
        var dir = Path.Combine(collectionDir, folder);
        return Directory.Exists(dir)
            ? Directory.EnumerateFiles(dir, pattern, option).Order(StringComparer.OrdinalIgnoreCase).ToList()
            : [];
    }

    /// <summary>Each row of a CSV as a lookup by column name, so a column moving in a tool's output does not matter.</summary>
    internal static IEnumerable<Func<string, string>> Rows(string path, CancellationToken cancellationToken = default)
    {
        using var reader = new CsvRecordReader(path);
        var header = reader.ReadRecord();
        if (header is null) yield break;
        var index = Index(header);
        var rows = 0;
        while (reader.ReadRecord() is { } fields)
        {
            if ((++rows & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            yield return n => index.TryGetValue(n, out var i) && i < fields.Count ? fields[i] : "";
        }
    }

    private static Dictionary<string, int> Index(List<string> header) =>
        header.Select((n, i) => (n: n.Trim().TrimStart('﻿'), i))
              .GroupBy(p => p.n, StringComparer.OrdinalIgnoreCase)
              .ToDictionary(g => g.Key, g => g.First().i, StringComparer.OrdinalIgnoreCase);

    private static List<string> ReadLines(string path)
    {
        if (!File.Exists(path)) return [];
        using var reader = CsvText.OpenRead(path);
        return CsvText.Records(reader).Select(r => r.Text).Where(t => t.Trim().Length > 0).ToList();
    }

    private static string Line(IEnumerable<string> cells) => string.Join(",", cells.Select(CsvText.Escape));
}
