using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ArtefactForge.Core;

/// <param name="LogError">
/// Set when the tool's console log could not be written (a full disk, typically). The run went on,
/// but the log is incomplete, so stderr can no longer be judged and the module must not pass.
/// </param>
/// <param name="PeakMemoryBytes">
/// The most memory the tool's process held at once (peak working set), on Windows. Processes it
/// starts are not counted. Null where it could not be read, and for builtins, which run inside
/// ArtefactForge itself.
/// </param>
public sealed record ProcessOutcome(
    int ExitCode, bool WroteToStderr, double DurationSeconds, bool TimedOut, string? Error,
    string? LogError = null, long? PeakMemoryBytes = null);

public static class ProcessRunner
{
    /// <summary>
    /// Runs one tool, streaming stdout and stderr to log files.
    /// The working directory is set to the executable's own folder: Hayabusa and Chainsaw resolve
    /// their rules and config relative to it, as do many community mkape modules.
    /// <paramref name="openLog"/> opens each log file; tests pass one that fails like a full disk.
    /// </summary>
    public static async Task<ProcessOutcome> RunAsync(
        string executable, string arguments, string stdoutLog, string stderrLog,
        int? timeoutSeconds, CancellationToken cancellationToken, string? workingDirectory = null,
        Func<string, Stream>? openLog = null)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName               = executable,
            Arguments              = arguments,
            WorkingDirectory       = workingDirectory
                                     ?? Path.GetDirectoryName(executable)
                                     ?? Environment.CurrentDirectory,
            UseShellExecute        = false,
            CreateNoWindow         = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true
        };

        var stopwatch = Stopwatch.StartNew();
        using var process = new Process { StartInfo = startInfo };

        openLog ??= path => new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        var outWriter = new StreamWriter(openLog(stdoutLog));
        var errWriter = new StreamWriter(openLog(stderrLog));
        var stderrBytes = 0L;
        string? logError = null;

        // These handlers run on thread-pool threads. An exception thrown there is unhandled and
        // ends the whole process, GUI or CLI, so a full disk while logging once took the app down
        // instead of failing one module. A write failure is recorded and logging stops; the tool
        // is left to finish, and the module is failed on the recorded error.
        void Write(StreamWriter writer, string path, string line)
        {
            if (Volatile.Read(ref logError) is not null) return;
            try { writer.WriteLine(line); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                Interlocked.CompareExchange(ref logError, $"could not write {Path.GetFileName(path)}: {ex.Message}", null);
            }
        }

        process.OutputDataReceived += (_, e) => { if (e.Data is not null) Write(outWriter, stdoutLog, e.Data); };
        process.ErrorDataReceived  += (_, e) =>
        {
            if (e.Data is null) return;
            Write(errWriter, stderrLog, e.Data);
            Interlocked.Add(ref stderrBytes, e.Data.Length);
        };

        ProcessOutcome outcome;
        try
        {
            outcome = await RunStartedAsync();
        }
        finally
        {
            // Disposing flushes the buffer, which fails the same way on a full disk.
            foreach (var (writer, path) in new[] { (outWriter, stdoutLog), (errWriter, stderrLog) })
            {
                try { await writer.DisposeAsync(); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Interlocked.CompareExchange(ref logError, $"could not write {Path.GetFileName(path)}: {ex.Message}", null);
                }
            }
        }
        return outcome with { LogError = Volatile.Read(ref logError), PeakMemoryBytes = PeakMemory(process) };

        async Task<ProcessOutcome> RunStartedAsync()
        {
            try
            {
                process.Start();
                LowerPriority(process);
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                return new ProcessOutcome(-1, false, stopwatch.Elapsed.TotalSeconds, false, ex.Message);
            }

            using var timeoutSource = timeoutSeconds is > 0
                ? new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds.Value))
                : new CancellationTokenSource();
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);

            try
            {
                await process.WaitForExitAsync(linked.Token);
            }
            catch (OperationCanceledException)
            {
                var timedOut = timeoutSource.IsCancellationRequested;
                try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return new ProcessOutcome(-1, stderrBytes > 0, stopwatch.Elapsed.TotalSeconds, timedOut,
                    timedOut ? $"Killed after {timeoutSeconds}s timeout." : "Cancelled.");
            }

            // Flush the tail of the async output readers before the writers are disposed.
            process.WaitForExit();
            return new ProcessOutcome(process.ExitCode, stderrBytes > 0, stopwatch.Elapsed.TotalSeconds, false, null);
        }
    }

    /// <summary>
    /// Read once the tool has finished, from its process handle, which Windows keeps until the
    /// handle is closed. One call per tool: nothing is sampled while it runs.
    /// </summary>
    private static long? PeakMemory(Process process)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var counters = new MemoryCounters { Size = (uint)Marshal.SizeOf<MemoryCounters>() };
            return GetProcessMemoryInfo(process.SafeHandle, ref counters, counters.Size)
                ? (long)counters.PeakWorkingSetSize
                : null;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;   // never started
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryCounters
    {
        public uint Size;
        public uint PageFaultCount;
        public nuint PeakWorkingSetSize;
        public nuint WorkingSetSize;
        public nuint QuotaPeakPagedPoolUsage;
        public nuint QuotaPagedPoolUsage;
        public nuint QuotaPeakNonPagedPoolUsage;
        public nuint QuotaNonPagedPoolUsage;
        public nuint PagefileUsage;
        public nuint PeakPagefileUsage;
    }

    [DllImport("kernel32.dll", EntryPoint = "K32GetProcessMemoryInfo", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMemoryInfo(
        Microsoft.Win32.SafeHandles.SafeProcessHandle process, ref MemoryCounters counters, uint size);

    /// <summary>
    /// Tools run below normal priority, which processes they start inherit. A batch keeps every core
    /// busy for hours; at normal priority it left the app and the rest of the PC slow to respond.
    /// An idle PC gives the tools the same time either way.
    /// </summary>
    private static void LowerPriority(Process process)
    {
        try { process.PriorityClass = ProcessPriorityClass.BelowNormal; }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception
                                       or PlatformNotSupportedException)
        {
            // Already exited, or not allowed: the tool runs at normal priority, as it always did.
        }
    }
}
