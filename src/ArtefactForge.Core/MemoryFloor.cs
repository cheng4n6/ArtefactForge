namespace ArtefactForge.Core;

/// <summary>
/// Holds back new modules while free memory is under the floor the analyst set (Keep free, 1 GB
/// by default), checked again every few seconds and whenever one finishes. A module still starts
/// when nothing else is running, so a PC that is short of memory works through the batch one at a
/// time instead of stopping. Zero turns it off.
/// </summary>
public sealed class MemoryFloor
{
    private readonly long _floorBytes;
    private readonly Func<long?> _available;
    private readonly TimeSpan _poll;
    private readonly object _gate = new();
    private TaskCompletionSource _finished = NewSignal();
    private int _running;

    public MemoryFloor(long floorBytes, Func<long?>? available = null, TimeSpan? poll = null)
    {
        _floorBytes = floorBytes;
        _available = available ?? MemoryBudget.Available;
        _poll = poll ?? TimeSpan.FromSeconds(2);
    }

    /// <summary>How many times a module was held back, for the manifest.</summary>
    public int Waits { get; private set; }

    /// <summary>Returns once the module may start; pair with <see cref="Release"/>.</summary>
    public async Task WaitAsync(CancellationToken cancellationToken)
    {
        var counted = false;
        while (true)
        {
            Task finished;
            lock (_gate)
            {
                // Unreadable memory does not hold anything back: the old behaviour.
                if (_floorBytes <= 0 || _running == 0 || !(_available() < _floorBytes))
                {
                    _running++;
                    return;
                }
                if (!counted) Waits++;
                counted = true;
                finished = _finished.Task;
            }
            await Task.WhenAny(finished, Task.Delay(_poll, cancellationToken));
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    public void Release()
    {
        TaskCompletionSource finished;
        lock (_gate)
        {
            _running--;
            finished = _finished;
            _finished = NewSignal();
        }
        finished.TrySetResult();
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}
