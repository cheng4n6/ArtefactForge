using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core;

/// <summary>The programs the Analysis tab can open a case's evidence lake in.</summary>
public enum LakeQueryApp
{
    /// <summary>The DuckDB command line, in a console window.</summary>
    DuckDbCli,

    /// <summary>DuckDB's own local web UI, which the CLI serves and opens in the browser.</summary>
    DuckDbUi,

    /// <summary>DBeaver, with a DuckDB connection to the lake and an SQL editor.</summary>
    DBeaver
}

/// <summary>What stops the lake opening, and what the analyst can do about it.</summary>
public enum LakeQueryFix
{
    /// <summary>Nothing to offer: the message says what to check.</summary>
    None,

    /// <summary>The program was not found: the analyst can point at it.</summary>
    Locate,

    /// <summary>DuckDB's ui extension is not installed: the CLI can install it, which downloads it.</summary>
    InstallUi
}

/// <summary>
/// The outcome of checking a program before it opens the lake: either the process to start, or
/// why it cannot be started and what would fix it. <see cref="Program"/> is the executable that
/// was found, if any, so a fix can use it (the CLI installs the ui extension).
/// </summary>
public sealed record LakeQueryPlan
{
    public ProcessStartInfo? Start { get; init; }
    public string? Problem { get; init; }
    public LakeQueryFix Fix { get; init; }
    public string? Program { get; init; }
}

/// <summary>
/// Finds DuckDB's CLI and DBeaver, checks each can open the case's lake, and builds the command
/// that opens it. The lake is always opened read-only: one writer per DuckDB file, so a read-only
/// session never changes the lake, and a rebuild while it is open writes case.duckdb.new rather
/// than failing. Nothing is installed or downloaded here unasked; installing the ui extension is
/// a separate step the analyst confirms (<see cref="InstallUiStart"/>).
/// </summary>
public static class LakeQueryApps
{
    public const string DuckDbExe = "duckdb.exe";
    public const string DBeaverExe = "dbeaver.exe";

    /// <summary>The DuckDB CLI's -ui switch arrived in DuckDB 1.2.1.</summary>
    public static readonly Version FirstUiVersion = new(1, 2, 1);

    /// <summary>How long a version or extension check of the CLI may take before it counts as broken.</summary>
    public static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Where duckdb.exe is: the path the analyst chose, then each PATH folder, then the folder
    /// winget links its command-line installs into. Null when none has it.
    /// </summary>
    public static string? FindDuckDb(string? chosen, string? pathVariable, string? localAppData, Func<string, bool> exists)
    {
        if (!string.IsNullOrWhiteSpace(chosen) && exists(chosen)) return chosen;
        foreach (var folder in (pathVariable ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string candidate;
            try { candidate = Path.Combine(folder.Trim('"'), DuckDbExe); }
            catch (ArgumentException) { continue; }   // a PATH entry with characters no path can hold
            if (exists(candidate)) return candidate;
        }
        if (!string.IsNullOrEmpty(localAppData))
        {
            var winget = Path.Combine(localAppData, "Microsoft", "WinGet", "Links", DuckDbExe);
            if (exists(winget)) return winget;
        }
        return null;
    }

    /// <summary>
    /// Where dbeaver.exe is: the path the analyst chose, then the folders DBeaver Community
    /// installs into for all users and for one user. Null when none has it.
    /// </summary>
    public static string? FindDBeaver(string? chosen, string? programFiles, string? localAppData, Func<string, bool> exists)
    {
        if (!string.IsNullOrWhiteSpace(chosen) && exists(chosen)) return chosen;
        string?[] candidates =
        [
            programFiles is null ? null : Path.Combine(programFiles, "DBeaver", DBeaverExe),
            localAppData is null ? null : Path.Combine(localAppData, "DBeaver", DBeaverExe),
            localAppData is null ? null : Path.Combine(localAppData, "Programs", "DBeaver", DBeaverExe)
        ];
        return candidates.FirstOrDefault(c => c is not null && exists(c));
    }

    /// <summary>The version in DuckDB's own version text ("v1.4.2 (Andium) 68d7555f68", or "1.4.2"), or null.</summary>
    public static Version? ParseVersion(string? text)
    {
        if (text is null) return null;
        var match = Regex.Match(text, @"\bv?(\d+)\.(\d+)\.(\d+)");
        return match.Success
            ? new Version(int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value), int.Parse(match.Groups[3].Value))
            : null;
    }

    /// <summary>
    /// Why a CLI of this version cannot open a lake written by DuckDB <paramref name="lakeVersion"/>,
    /// or null when it can. DuckDB reads files written by older versions but not newer ones, so the
    /// CLI must be at least the version that built the lake. An unknown lake version is not held
    /// against the CLI: DuckDB itself says if the file is too new.
    /// </summary>
    public static string? TooOld(Version cli, Version? lakeVersion, LakeQueryApp app)
    {
        if (app == LakeQueryApp.DuckDbUi && cli < FirstUiVersion)
            return $"The DuckDB CLI found is version {cli}, and its web UI needs {FirstUiVersion} or later. Install a newer DuckDB CLI.";
        if (lakeVersion is not null && new Version(cli.Major, cli.Minor) < new Version(lakeVersion.Major, lakeVersion.Minor))
            return $"The DuckDB CLI found is version {cli}, but the lake was built with DuckDB {lakeVersion}, and older versions cannot open it. Install DuckDB CLI {lakeVersion.Major}.{lakeVersion.Minor} or later.";
        return null;
    }

    /// <summary>The command that opens the lake read-only in the CLI, or in its web UI.</summary>
    public static ProcessStartInfo DuckDbStart(string duckDb, string lakePath, bool ui)
    {
        var start = new ProcessStartInfo(duckDb)
        {
            // A console window of its own: the CLI is the session, and for the UI it is the server
            // the browser talks to, so closing the window ends it.
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(lakePath) ?? ""
        };
        start.ArgumentList.Add("-readonly");
        start.ArgumentList.Add(lakePath);
        if (ui) start.ArgumentList.Add("-ui");
        return start;
    }

    /// <summary>The command that installs DuckDB's ui extension. It downloads it, so it runs only when the analyst says so.</summary>
    public static ProcessStartInfo InstallUiStart(string duckDb)
    {
        var start = CaptureStart(duckDb);
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("INSTALL ui");
        return start;
    }

    /// <summary>
    /// The command that opens the lake in DBeaver: a connection made for this launch with the
    /// DuckDB driver, read-only, connected, with an SQL editor open on it.
    /// </summary>
    public static ProcessStartInfo DBeaverStart(string dbeaver, string lakePath, string connectionName)
    {
        var start = new ProcessStartInfo(dbeaver) { UseShellExecute = false };
        // DBeaver's -con takes name=value pairs split by "|"; a Windows path cannot hold one, and
        // the name is cleaned here. The driver is named as provider:driver id (DBeaver's DuckDB
        // plugin), because a bare "duckdb" only matches the driver's display name. A -con
        // connection is temporary: it is not saved in the analyst's DBeaver workspace.
        var name = connectionName.Replace('|', ' ').Replace('=', ' ');
        start.ArgumentList.Add("-con");
        start.ArgumentList.Add($"driver=duckdb:duckdb_jdbc|name={name}|url=jdbc:duckdb:{lakePath}|prop.duckdb.read_only=true|connect=true|openConsole=true");
        return start;
    }

    /// <summary>
    /// Checks <paramref name="app"/> can open the lake and returns the command to start, or what
    /// stops it. <paramref name="run"/> runs a check and returns its output, or null when it could
    /// not run or did not finish in time; tests pass their own.
    /// </summary>
    public static LakeQueryPlan Plan(LakeQueryApp app, string? lakePath, string? lakeDuckDbVersion, string connectionName,
        string? duckDb, string? dbeaver, Func<ProcessStartInfo, string?> run)
    {
        if (lakePath is null || !File.Exists(lakePath))
            return new LakeQueryPlan { Problem = "The case has no evidence lake to open. Build it first." };

        if (app == LakeQueryApp.DBeaver)
        {
            return dbeaver is null
                ? new LakeQueryPlan
                {
                    Problem = "DBeaver was not found. Install DBeaver Community, or point ArtefactForge at dbeaver.exe if it is somewhere else. DBeaver downloads its DuckDB driver the first time it connects.",
                    Fix = LakeQueryFix.Locate
                }
                : new LakeQueryPlan { Start = DBeaverStart(dbeaver, lakePath, connectionName), Program = dbeaver };
        }

        if (duckDb is null)
            return new LakeQueryPlan
            {
                Problem = "The DuckDB CLI (duckdb.exe) was not found on PATH. Install it (winget install DuckDB.cli, or the Windows download from the DuckDB website), or point ArtefactForge at duckdb.exe.",
                Fix = LakeQueryFix.Locate
            };

        var versionCheck = CaptureStart(duckDb);
        versionCheck.ArgumentList.Add("--version");
        if (ParseVersion(run(versionCheck)) is not { } version)
            return new LakeQueryPlan
            {
                Problem = $"{duckDb} did not report a DuckDB version, so it may not be the DuckDB CLI. Point ArtefactForge at duckdb.exe.",
                Fix = LakeQueryFix.Locate,
                Program = duckDb
            };
        if (TooOld(version, ParseVersion(lakeDuckDbVersion), app) is { } tooOld)
            return new LakeQueryPlan { Problem = tooOld, Fix = LakeQueryFix.Locate, Program = duckDb };

        var ui = app == LakeQueryApp.DuckDbUi;
        if (ui)
        {
            // In memory, so the check never touches the lake.
            var extensionCheck = CaptureStart(duckDb);
            foreach (var argument in (string[])["-noheader", "-list", "-c",
                         "SELECT installed FROM duckdb_extensions() WHERE extension_name = 'ui'"])
                extensionCheck.ArgumentList.Add(argument);
            if (!string.Equals(run(extensionCheck)?.Trim(), "true", StringComparison.OrdinalIgnoreCase))
                return new LakeQueryPlan
                {
                    Problem = "DuckDB's web UI needs its ui extension, which is not installed. Installing it downloads it from DuckDB once. The UI page itself is also loaded from DuckDB's website, so it needs internet access each time.",
                    Fix = LakeQueryFix.InstallUi,
                    Program = duckDb
                };
        }

        return new LakeQueryPlan { Start = DuckDbStart(duckDb, lakePath, ui), Program = duckDb };
    }

    /// <summary>
    /// Runs a check and returns what it wrote to stdout, or null when it could not start, failed,
    /// or did not finish within <see cref="CheckTimeout"/>.
    /// </summary>
    public static string? RunCheck(ProcessStartInfo start) => RunCheck(start, CheckTimeout);

    public static string? RunCheck(ProcessStartInfo start, TimeSpan timeout)
    {
        try
        {
            using var process = Process.Start(start);
            if (process is null) return null;
            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();   // drained so a chatty check cannot block on a full pipe
            if (!process.WaitForExit(timeout))
            {
                try { process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { }   // it finished as it was killed
                return null;
            }
            return process.ExitCode == 0 ? output.GetAwaiter().GetResult() : null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }

    private static ProcessStartInfo CaptureStart(string executable) => new(executable)
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
}
