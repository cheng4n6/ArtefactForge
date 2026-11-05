namespace ArtefactForge.Core.Ioc;

/// <summary>One batch the queue swept: the IOCs, and the sweep's result or why it failed.</summary>
public sealed record IocSweepBatch(IReadOnlyList<IocEntry> Iocs, IocSweepResult? Result, string? Error);

/// <summary>
/// Sweeps IOCs as they are added to a case's list, without making the analyst wait for one sweep
/// before adding the next IOC. An IOC added while a sweep runs waits, and everything that waited
/// is swept together once that sweep is done: five IOCs typed in during one sweep cost one more
/// sweep, not five. Each batch starts a moment after the last add (<see cref="DefaultSettle"/>),
/// so IOCs added in quick succession go in one batch from the start.
///
/// The IOCs are on the list (<see cref="IocList.Add"/>) before they are queued; the queue only
/// decides when they are searched for. Nothing is swept in the background on its own: only what
/// the analyst added.
/// </summary>
public sealed class IocSweepQueue
{
    /// <summary>How long a batch waits after the last add before it starts.</summary>
    public static readonly TimeSpan DefaultSettle = TimeSpan.FromSeconds(1);

    private readonly object _gate = new();
    private readonly TimeSpan _settle;
    private readonly Func<IReadOnlyCollection<IocEntry>, IProgress<string>?, Task<IocSweepResult>> _sweep;
    private List<IocEntry> _waiting = [];
    private int _sweeping;
    private bool _busy;
    private Task _worker = Task.CompletedTask;

    /// <param name="sweep">The sweep of one batch; <see cref="IocSweep.SweepAsync"/> unless a test says otherwise.</param>
    public IocSweepQueue(
        string caseDirectory, TimeSpan? settle = null,
        Func<IReadOnlyCollection<IocEntry>, IProgress<string>?, Task<IocSweepResult>>? sweep = null)
    {
        CaseDirectory = caseDirectory;
        _settle = settle ?? DefaultSettle;
        _sweep = sweep ?? ((iocs, progress) => IocSweep.SweepAsync(caseDirectory, iocs, progress));
    }

    public string CaseDirectory { get; }

    /// <summary>Progress of the batch being swept.</summary>
    public IProgress<string>? Progress { get; set; }

    /// <summary>Raised on a worker thread after each batch, with the queue already updated.</summary>
    public event Action<IocSweepBatch>? BatchFinished;

    /// <summary>IOCs added and not yet being swept.</summary>
    public int Waiting
    {
        get { lock (_gate) return _waiting.Count; }
    }

    /// <summary>IOCs in the batch being swept now; 0 between batches.</summary>
    public int Sweeping
    {
        get { lock (_gate) return _sweeping; }
    }

    /// <summary>True from the first add until the last batch has finished.</summary>
    public bool IsBusy
    {
        get { lock (_gate) return _busy; }
    }

    /// <summary>Completes once everything added so far has been swept.</summary>
    public Task WhenIdleAsync()
    {
        lock (_gate) return _worker;
    }

    /// <summary>
    /// Queues IOCs just added to the list. One already waiting is not queued twice; one being
    /// swept now is queued again, as the sweep running may have begun before the analyst re-added it.
    /// </summary>
    public void Add(IEnumerable<IocEntry> added)
    {
        lock (_gate)
        {
            var known = _waiting.Select(e => e.Key).ToHashSet(StringComparer.Ordinal);
            _waiting.AddRange(added.Where(e => known.Add(e.Key)));
            if (_busy || _waiting.Count == 0) return;
            _busy = true;
            _worker = Task.Run(SweepWaitingAsync);
        }
    }

    private async Task SweepWaitingAsync()
    {
        while (true)
        {
            await Task.Delay(_settle);

            List<IocEntry> batch;
            lock (_gate)
            {
                batch = _waiting;
                _waiting = [];
                _sweeping = batch.Count;
            }

            IocSweepBatch outcome;
            try
            {
                outcome = new IocSweepBatch(batch, await _sweep(batch, Progress), null);
            }
            catch (Exception ex)
            {
                // The boundary of a background batch: a failure is reported with the batch rather
                // than lost with the task, and the IOCs that wait behind it still get their sweep.
                outcome = new IocSweepBatch(batch, null, ex.Message);
            }

            bool more;
            lock (_gate)
            {
                _sweeping = 0;
                more = _waiting.Count > 0;
                if (!more) _busy = false;
            }
            BatchFinished?.Invoke(outcome);
            if (!more) return;
        }
    }
}
