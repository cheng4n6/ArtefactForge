namespace ArtefactForge.Core.Ioc;

/// <summary>
/// The output files IOC sweeps scan at once, shared by every sweep in the process: the hosts of a
/// run swept as each finishes, and the sweeps started from the IOCs tab, scan side by side instead
/// of waiting for each other. A scan starts while fewer than <see cref="MaxScans"/> are running and
/// the memory free, less what the analyst keeps free (Keep free), leaves room for one more. One
/// always runs, so a machine short of memory still gets through the sweep a file at a time. As
/// with the memory budget of the run, memory that cannot be read means one at a time.
/// </summary>
public sealed class SweepSlots
{
    /// <summary>
    /// Room one scan needs: the reader's buffers, a record of up to the largest event payload, and
    /// the hits found so far. Measured on four hosts of a 1.2 GB case, four scans at once and
    /// 300,000 hits took the whole process from about 290 MB to 360 MB; this leaves headroom for a
    /// common IOC in a multi-GB event log.
    /// </summary>
    public const long ScanEstimateBytes = 128L << 20;

    /// <summary>Shared by every sweep in the process.</summary>
    public static SweepSlots Shared { get; } = new(DefaultMaxScans);

    /// <summary>
    /// Four files at once, as a single sweep scanned before: the disk sets the pace. On a 16-core
    /// workstation's SSD, eight at once swept four hosts of a 1.2 GB case no faster than four
    /// (about 11 s either way, against 15 s with the hosts swept one after another). Half the
    /// cores on a smaller machine, so a sweep beside a run leaves the modules room.
    /// </summary>
    public static int DefaultMaxScans => Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    private readonly object _gate = new();
    private readonly Func<long?> _available;
    private readonly TimeSpan _poll;
    private TaskCompletionSource _released = NewSignal();
    private int _running;
    private long _keepFreeBytes = 1L << 30;

    public SweepSlots(int maxScans, Func<long?>? available = null, TimeSpan? poll = null)
    {
        MaxScans = Math.Max(1, maxScans);
        _available = available ?? MemoryBudget.Available;
        _poll = poll ?? TimeSpan.FromSeconds(2);
    }

    public int MaxScans { get; }

    /// <summary>The analyst's Keep free, set by a run and by the app before a sweep; 1 GB until then.</summary>
    public long KeepFreeBytes
    {
        get => Interlocked.Read(ref _keepFreeBytes);
        set => Interlocked.Exchange(ref _keepFreeBytes, Math.Max(0, value));
    }

    /// <summary>The most scans that have run at once, for tests.</summary>
    public int Peak { get; private set; }

    /// <summary>Returns once a file may be scanned; pair with <see cref="Release"/>.</summary>
    public async Task WaitAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Task released;
            lock (_gate)
            {
                if (_running == 0 || (_running < MaxScans && HasRoom()))
                {
                    _running++;
                    Peak = Math.Max(Peak, _running);
                    return;
                }
                released = _released.Task;
            }
            // Memory can come free without a scan finishing (a module of the run ends), so look again
            // every few seconds as well as whenever a scan finishes.
            await Task.WhenAny(released, Task.Delay(_poll, cancellationToken));
        }
    }

    public void Release()
    {
        TaskCompletionSource released;
        lock (_gate)
        {
            _running--;
            released = _released;
            _released = NewSignal();
        }
        released.TrySetResult();
    }

    private bool HasRoom() => _available() is { } free && free - KeepFreeBytes >= ScanEstimateBytes;

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}
