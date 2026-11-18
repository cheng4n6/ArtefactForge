namespace ArtefactForge.Lake.Queries;

/// <summary>What <see cref="DataAccessResults.Write"/> did.</summary>
public sealed record DataAccessResultsSummary(string OutputRoot, int Hosts, int HostsRead, int ListedUsers, int CaseRows,
    string? Problem)
{
    public string Describe() =>
        $"{Hosts} host(s) with accounts, {HostsRead} read for activity; " +
        (ListedUsers == 0 ? "no compromised users listed, so no DataAccess.csv" : $"{CaseRows} row(s) for {ListedUsers} listed user(s)") +
        (Problem is null ? "" : "; " + Problem);
}

/// <summary>
/// ArtefactForge's data access files from the lake's saved queries: the same names, columns and
/// layout as the DataAccess step writes in the case (Users.csv, Activity.csv and Sources.csv in
/// each host's DataAccess folder, UserList.csv and DataAccess.csv for the case), under an output
/// root of their own. Every decision is the queries'; this only writes the files, and only those
/// the step would write: a host's activity only when someone is listed and the host has one of
/// the artefacts, DataAccess.csv only when someone is listed.
/// </summary>
public static class DataAccessResults
{
    public const string Folder = "DataAccess";
    public const string UsersFileName = "Users.csv";
    public const string ActivityFileName = "Activity.csv";
    public const string SourcesFileName = "Sources.csv";
    public const string UserListFileName = "UserList.csv";
    public const string CaseFileName = "DataAccess.csv";
    public const string CompromisedFileName = "CompromisedUsers.csv";

    public static readonly string[] UserColumns = ["System", "Username", "SID", "ProfilePath", "Source"];
    public static readonly string[] ActivityColumns = ["TimeUtc", "System", "User", "SID", "Path", "Activity", "Source"];
    public static readonly string[] SourceColumns = ["Source", "Status", "Rows", "Input"];
    public static readonly string[] CaseColumns = ["Date/Time (UTC)", "System", "User", "Path", "Activity"];

    /// <summary>Where the lake build writes them: &lt;lake&gt;\results\DataAccess.</summary>
    public static string OutputRootFor(string lakeDirectory) => Path.Combine(lakeDirectory, LakeNames.ResultsFolder, Folder);

    /// <summary>
    /// Runs the data access queries and writes the files under <paramref name="outputRoot"/>, laid
    /// out as a case folder: &lt;root&gt;\&lt;Collection&gt;\DataAccess\... and &lt;root&gt;\DataAccess.csv.
    /// What was there before is removed first. A CompromisedUsers.csv without a Username or SID
    /// column lists nobody, as in the DataAccess step, and is reported in the summary.
    /// </summary>
    public static DataAccessResultsSummary Write(LakeQuerySession session, string outputRoot, CancellationToken cancellationToken = default)
    {
        var users = session.RunToRows(Query("data_access_users"));
        var problem = CheckCompromised(session);
        var listed = session.RunToRows(Query("data_access_compromised")).Count;
        cancellationToken.ThrowIfCancellationRequested();
        var sources = session.RunToRows(Query("data_access_sources"));
        var activity = session.RunToRows(Query("data_access_activity"));
        cancellationToken.ThrowIfCancellationRequested();

        if (Directory.Exists(outputRoot)) Directory.Delete(outputRoot, recursive: true);
        Directory.CreateDirectory(outputRoot);

        foreach (var host in users.GroupBy(r => r["Collection"], StringComparer.Ordinal))
            LakeCsv.Write(Path.Combine(outputRoot, host.Key, Folder, UsersFileName), UserColumns,
                host.Select(r => UserColumns.Select(c => r[c])));

        var byHost = activity.ToLookup(r => r["Collection"], StringComparer.Ordinal);
        var read = sources.GroupBy(r => r["Collection"], StringComparer.Ordinal).ToList();
        foreach (var host in read)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var outDir = Path.Combine(outputRoot, host.Key, Folder);
            LakeCsv.Write(Path.Combine(outDir, ActivityFileName), ActivityColumns,
                byHost[host.Key].Select(r => ActivityColumns.Select(c => r[c])));
            LakeCsv.Write(Path.Combine(outDir, SourcesFileName), SourceColumns, host.Select(r => SourceColumns.Select(c => r[c])));
        }

        if (users.Count > 0)
            LakeCsv.Write(Path.Combine(outputRoot, UserListFileName), UserColumns,
                session.RunToRows(Query("data_access_user_list")).Select(r => UserColumns.Select(c => r[c])));

        var caseRows = 0;
        if (listed > 0)
        {
            var rows = session.RunToRows(Query("data_access_case"));
            caseRows = rows.Count;
            LakeCsv.Write(Path.Combine(outputRoot, CaseFileName), CaseColumns, rows.Select(r => CaseColumns.Select(c => r[c])));
        }

        return new DataAccessResultsSummary(outputRoot, users.Select(r => r["Collection"]).Distinct(StringComparer.Ordinal).Count(),
            read.Count, listed, caseRows, problem);
    }

    private static LakeQuery Query(string name) =>
        LakeQueryCatalogue.Find(name) ?? throw new InvalidDataException($"The saved query {name} is missing from the lake library");

    /// <summary>The list needs a Username or SID column, as the DataAccess step reads it.</summary>
    private static string? CheckCompromised(LakeQuerySession session)
    {
        if (!session.InputHeaders.TryGetValue("compromised_users", out var header)) return null;
        bool Has(string column) => header.Any(h => h.Trim().Equals(column, StringComparison.OrdinalIgnoreCase));
        return Has("Username") || Has("SID")
            ? null
            : $"{CompromisedFileName} needs a Username or SID column on its first line, so nobody is listed";
    }
}
