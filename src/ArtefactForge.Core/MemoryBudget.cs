using System.Runtime.InteropServices;

namespace ArtefactForge.Core;

/// <summary>
/// Memory-heavy modules share the memory free when the run starts, less a reserve for everything
/// else. Each asks for its estimate (MemoryEstimateMB in its .forge, measured peaks) and starts
/// once that fits beside the ones already running, so a workstation with 5 GB free runs MFTECmd,
/// Hayabusa and Chainsaw side by side but never two of Chainsaw's SRUM analysis (5.3 GB). One always runs, even when it needs
/// more than the whole budget, so a small machine still gets through the batch one at a time.
/// </summary>
public sealed class MemoryBudget
{
    /// <summary>For a memory-heavy module with no estimate: the heaviest tool measured, rounded up.</summary>
    public const int DefaultEstimateMB = 6000;

    /// <summary>
    /// The budget for this much free memory, less what the analyst keeps free (Keep free) for the
    /// modules the budget does not count: RECmd and WindowsSystemInfo each took about 0.8 GB beside
    /// MFTECmd, leaving 0.02 GB free and the whole PC paging. Null stays null (one at a time).
    /// </summary>
    public static long? FromFree(long? freeBytes, long keepFreeBytes) =>
        freeBytes is { } free ? Math.Max(0, free - Math.Max(0, keepFreeBytes)) : null;

    private readonly object _gate = new();
    private readonly LinkedList<(long Need, TaskCompletionSource Ready)> _waiting = new();
    private long _used;
    private int _running;

    /// <summary>Null when free memory could not be read: then one at a time, the safe answer.</summary>
    public MemoryBudget(long? budgetBytes) => BudgetBytes = budgetBytes;

    public long? BudgetBytes { get; }

    public static long EstimateBytes(ModuleDefinition module) =>
        (long)(module.MemoryEstimateMB ?? DefaultEstimateMB) << 20;

    /// <summary>Waits until <paramref name="bytes"/> fits, then holds it until <see cref="Release"/>.</summary>
    public async Task WaitAsync(long bytes, CancellationToken cancellationToken)
    {
        LinkedListNode<(long, TaskCompletionSource)> node;
        lock (_gate)
        {
            if (Fits(bytes))
            {
                Take(bytes);
                return;
            }
            node = _waiting.AddLast((bytes, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)));
        }

        using var registration = cancellationToken.Register(() =>
        {
            lock (_gate)
            {
                if (node.List is null) return;   // already started
                _waiting.Remove(node);
            }
            node.Value.Item2.TrySetCanceled(cancellationToken);
        });
        await node.Value.Item2.Task;
    }

    public void Release(long bytes)
    {
        var ready = new List<TaskCompletionSource>();
        lock (_gate)
        {
            _used -= bytes;
            _running--;
            // In queue order, but a smaller module further back starts when it fits and the one
            // ahead of it does not: the one ahead still starts at the latest once the rest finish.
            for (var node = _waiting.First; node is not null;)
            {
                var next = node.Next;
                if (Fits(node.Value.Need))
                {
                    Take(node.Value.Need);
                    _waiting.Remove(node);
                    ready.Add(node.Value.Ready);
                }
                node = next;
            }
        }
        foreach (var r in ready) r.TrySetResult();
    }

    private bool Fits(long bytes) =>
        _running == 0 || (BudgetBytes is { } budget && _used + bytes <= budget);

    private void Take(long bytes)
    {
        _used += bytes;
        _running++;
    }

    /// <summary>Physical memory free for new work now, or null when it cannot be read.</summary>
    public static long? Available()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
                return GlobalMemoryStatusEx(ref status) ? (long)Math.Min(status.AvailablePhysical, long.MaxValue) : null;
            }

            // MemAvailable is the kernel's own estimate of what new work can use without swapping.
            const string meminfo = "/proc/meminfo";
            if (!File.Exists(meminfo)) return null;
            var line = File.ReadLines(meminfo).FirstOrDefault(l => l.StartsWith("MemAvailable:", StringComparison.Ordinal));
            var kb = line?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1);
            return long.TryParse(kb, out var value) ? value * 1024 : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
}
