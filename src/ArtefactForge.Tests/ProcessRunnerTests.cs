using ArtefactForge.Core;
using Xunit;

namespace ArtefactForge.Tests;

public class ProcessRunnerTests
{
    /// <summary>A log file on a disk that is already full: every write fails.</summary>
    private sealed class FullDiskStream : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new IOException("There is not enough space on the disk.");

        public override void Write(ReadOnlySpan<byte> buffer) =>
            throw new IOException("There is not enough space on the disk.");

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            throw new IOException("There is not enough space on the disk.");

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            throw new IOException("There is not enough space on the disk.");
    }

    private static (string Exe, string Args) Chatty(int lines)
    {
        // Enough output to fill the log writer's buffer several times over, on both streams.
        if (OperatingSystem.IsWindows())
            return (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
                $"/c for /l %i in (1,1,{lines}) do @(echo line %i of the tool's progress output & echo warning %i 1>&2)");
        return ("/bin/sh", $"-c \"for i in $(seq 1 {lines}); do echo line $i; echo warning $i 1>&2; done\"");
    }

    [Fact]
    public async Task A_full_disk_while_logging_fails_the_tool_run_instead_of_crashing_the_app()
    {
        using var dir = new TempDirectory();
        var (exe, args) = Chatty(500);

        // Before the fix the exception escaped from the output callback on a thread-pool thread,
        // which ends the test host as it ended the GUI.
        var outcome = await ProcessRunner.RunAsync(exe, args,
            Path.Combine(dir.Path, "tool.log"), Path.Combine(dir.Path, "tool.err.log"),
            60, CancellationToken.None, openLog: _ => new FullDiskStream());

        Assert.NotNull(outcome.LogError);
        Assert.Contains("not enough space", outcome.LogError);
        Assert.Equal(0, outcome.ExitCode);
    }

    [Fact]
    public async Task A_normal_run_reports_no_log_error()
    {
        using var dir = new TempDirectory();
        var (exe, args) = Chatty(5);
        var stdout = Path.Combine(dir.Path, "tool.log");

        var outcome = await ProcessRunner.RunAsync(exe, args, stdout, Path.Combine(dir.Path, "tool.err.log"),
            60, CancellationToken.None);

        Assert.Null(outcome.LogError);
        Assert.True(outcome.WroteToStderr);
        Assert.Equal(5, File.ReadAllLines(stdout).Length);
    }

    [Fact]
    public async Task A_tool_runs_peak_memory_is_recorded_on_windows()
    {
        using var dir = new TempDirectory();
        var (exe, args) = Chatty(5);

        var outcome = await ProcessRunner.RunAsync(exe, args, Path.Combine(dir.Path, "tool.log"),
            Path.Combine(dir.Path, "tool.err.log"), 60, CancellationToken.None);

        if (OperatingSystem.IsWindows()) Assert.True(outcome.PeakMemoryBytes > 0);
        else Assert.Null(outcome.PeakMemoryBytes);
    }

    [Fact]
    public async Task A_tool_that_cannot_start_has_no_peak_memory()
    {
        using var dir = new TempDirectory();

        var outcome = await ProcessRunner.RunAsync(Path.Combine(dir.Path, "missing.exe"), "",
            Path.Combine(dir.Path, "tool.log"), Path.Combine(dir.Path, "tool.err.log"), 60, CancellationToken.None);

        Assert.NotNull(outcome.Error);
        Assert.Null(outcome.PeakMemoryBytes);
    }
}
