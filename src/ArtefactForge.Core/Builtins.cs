using System.Diagnostics;
using System.Text;
using ArtefactForge.Core.Linux;
using ArtefactForge.Core.Windows;

namespace ArtefactForge.Core;

/// <summary>
/// Parsers compiled into ArtefactForge itself, for artefacts no external tool reads on Windows.
///
/// A module names one with <c>Executable: builtin:Name</c>. Everything else about the module is
/// unchanged - Requires, the CommandLine placeholders, staging, harvest, the manifest - so the
/// engine treats a builtin exactly like a tool, except that it runs in-process. The manifest
/// records the ArtefactForge build and hash as the tool, because that is what did the parsing.
/// </summary>
public static class Builtins
{
    public const string Prefix = "builtin:";

    private delegate int Handler(IReadOnlyDictionary<string, string> args, TextWriter log, TextWriter errors, CancellationToken cancellationToken);

    private static readonly Dictionary<string, Handler> Registry = new(StringComparer.OrdinalIgnoreCase)
    {
        ["LinuxJournal"] = (args, log, errors, token) =>
            JournalExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxWebLogs"] = (args, log, errors, token) =>
            WebLogExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxContainers"] = (args, log, errors, token) =>
            ContainerExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxDnfHistory"] = (args, log, errors, token) =>
            DnfHistoryExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxYumHistory"] = (args, log, errors, token) =>
            YumHistoryExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxLiveResponse"] = (args, log, errors, token) =>
            LiveResponseExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxAudit"] = (args, log, errors, token) =>
            AuditExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxSyslog"] = (args, log, errors, token) =>
            SyslogExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxPersistence"] = (args, log, errors, token) =>
            PersistenceExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxExecutableHashes"] = (args, log, errors, token) =>
            UacChecksExport.Hashes(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxChkrootkit"] = (args, log, errors, token) =>
            UacChecksExport.Chkrootkit(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["LinuxBodyfile"] = (args, log, errors, token) =>
            BodyfileExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token),
        ["WindowsDhcpServerLog"] = (args, log, errors, token) =>
            DhcpServerLogExport.Run(Required(args, "root"), Required(args, "out"), log, errors, token)
    };

    public static IEnumerable<string> Names => Registry.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase);

    public static bool IsBuiltin(string executable) =>
        executable.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    public static bool Exists(string executable) =>
        IsBuiltin(executable) && Registry.ContainsKey(executable[Prefix.Length..]);

    /// <summary>
    /// Same contract as <see cref="ProcessRunner.RunAsync"/>: stdout and stderr go to the log files,
    /// anything written to stderr marks the run for review, and a timeout or cancellation stops it.
    /// An unhandled exception is a failure with exit code 1 and the exception in the .err.log.
    /// </summary>
    public static async Task<ProcessOutcome> RunAsync(
        string executable, string arguments, string stdoutLog, string stderrLog,
        int? timeoutSeconds, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        if (!Registry.TryGetValue(executable[Prefix.Length..], out var handler))
            return new ProcessOutcome(-1, false, 0, false, "unknown builtin: " + executable);

        IReadOnlyDictionary<string, string> args;
        try { args = ParseArguments(arguments); }
        catch (FormatException ex) { return new ProcessOutcome(-1, false, 0, false, ex.Message); }

        using var timeoutSource = timeoutSeconds is > 0
            ? new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds.Value))
            : new CancellationTokenSource();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);

        await using var outWriter = new StreamWriter(stdoutLog, append: false);
        await using var errFile = new StreamWriter(stderrLog, append: false);
        var errWriter = new CountingWriter(errFile);

        try
        {
            var exitCode = await Task.Run(() => handler(args, outWriter, errWriter, linked.Token), linked.Token);
            return new ProcessOutcome(exitCode, errWriter.Written, stopwatch.Elapsed.TotalSeconds, false, null);
        }
        catch (OperationCanceledException)
        {
            var timedOut = timeoutSource.IsCancellationRequested;
            return new ProcessOutcome(-1, errWriter.Written, stopwatch.Elapsed.TotalSeconds, timedOut,
                timedOut ? $"Stopped after {timeoutSeconds}s timeout." : "Cancelled.");
        }
        catch (Exception ex)
        {
            errWriter.WriteLine(ex.ToString());
            return new ProcessOutcome(1, true, stopwatch.Elapsed.TotalSeconds, false, ex.Message);
        }
    }

    /// <summary>
    /// <c>--name "value" --other value</c>. Deliberately small: builtins take named paths and
    /// nothing else, and a malformed line is an authoring error to report, not to guess around.
    /// </summary>
    public static IReadOnlyDictionary<string, string> ParseArguments(string arguments)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        var quoted = false;
        var inToken = false;

        foreach (var c in arguments)
        {
            if (c == '"') { quoted = !quoted; inToken = true; continue; }
            if (char.IsWhiteSpace(c) && !quoted)
            {
                if (inToken) { tokens.Add(current.ToString()); current.Clear(); inToken = false; }
                continue;
            }
            current.Append(c);
            inToken = true;
        }
        if (quoted) throw new FormatException("unbalanced quotes in builtin arguments");
        if (inToken) tokens.Add(current.ToString());

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!tokens[i].StartsWith("--") || i + 1 >= tokens.Count)
                throw new FormatException($"builtin arguments must be --name value pairs; problem at '{tokens[i]}'");
            result[tokens[i][2..]] = tokens[++i];
        }
        return result;
    }

    private static string Required(IReadOnlyDictionary<string, string> args, string name) =>
        args.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"missing --{name}");

    /// <summary>Records whether anything reached stderr, which the engine reports as CheckLog.</summary>
    private sealed class CountingWriter(TextWriter inner) : TextWriter
    {
        private readonly Lock _gate = new();
        public bool Written { get; private set; }
        public override Encoding Encoding => inner.Encoding;

        public override void Write(char value)
        {
            lock (_gate) { Written = true; inner.Write(value); }
        }

        public override void Write(string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            lock (_gate) { Written = true; inner.Write(value); }
        }

        public override void WriteLine(string? value)
        {
            lock (_gate) { Written = true; inner.WriteLine(value); }
        }
    }
}
