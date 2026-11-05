using ArtefactForge.Core.Ioc;

namespace ArtefactForge.Tests;

/// <summary>
/// IOCs added while a sweep runs wait for it and are then swept together, and the files that
/// sweeps scan at once are shared out by CPU and free memory less Keep free.
/// </summary>
public class IocSweepQueueTests
{
    private static readonly TimeSpan Settle = TimeSpan.FromMilliseconds(20);
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    /// <summary>A sweep the test lets finish, recording each batch it was given.</summary>
    private sealed class FakeSweep
    {
        private readonly object _gate = new();
        private TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<List<string>> Batches { get; } = [];
        public TaskCompletionSource Started { get; private set; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Exception? Throw { get; set; }

        public async Task<IocSweepResult> SweepAsync(IReadOnlyCollection<IocEntry> iocs, IProgress<string>? progress)
        {
            Task release;
            lock (_gate)
            {
                Batches.Add(iocs.Select(i => i.Value).ToList());
                release = _release.Task;
                Started.TrySetResult();
            }
            await release;
            if (Throw is { } ex) { Throw = null; throw ex; }
            return new IocSweepResult { Iocs = iocs.Count };
        }

        /// <summary>Lets the batch running now finish and holds the next one until called again.</summary>
        public void Finish()
        {
            lock (_gate)
            {
                Started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var release = _release;
                _release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                release.TrySetResult();
            }
        }

        public void FinishAll()
        {
            lock (_gate) _release.TrySetResult();
        }
    }

    private static IocEntry Ioc(string name) => IocEntry.Create(IocType.FileName, name);

    [Fact]
    public async Task IOCs_added_during_a_sweep_are_swept_together_in_the_next_batch()
    {
        var sweep = new FakeSweep();
        var queue = new IocSweepQueue("case", Settle, sweep.SweepAsync);

        queue.Add([Ioc("a.exe")]);
        await sweep.Started.Task.WaitAsync(Wait);
        Assert.Equal(1, queue.Sweeping);

        queue.Add([Ioc("b.exe")]);
        queue.Add([Ioc("c.exe"), Ioc("b.exe")]);   // b.exe already waits: not queued twice
        Assert.Equal(2, queue.Waiting);

        sweep.Finish();
        await sweep.Started.Task.WaitAsync(Wait);
        sweep.FinishAll();
        await queue.WhenIdleAsync().WaitAsync(Wait);

        Assert.Equal([["a.exe"], ["b.exe", "c.exe"]], sweep.Batches);
        Assert.False(queue.IsBusy);
        Assert.Equal(0, queue.Waiting);
    }

    [Fact]
    public async Task IOCs_added_in_quick_succession_go_in_one_batch()
    {
        var sweep = new FakeSweep();
        sweep.FinishAll();
        var queue = new IocSweepQueue("case", TimeSpan.FromMilliseconds(500), sweep.SweepAsync);

        queue.Add([Ioc("a.exe")]);
        queue.Add([Ioc("b.exe")]);
        Assert.True(queue.IsBusy);
        await queue.WhenIdleAsync().WaitAsync(Wait);

        Assert.Equal([["a.exe", "b.exe"]], sweep.Batches);
    }

    [Fact]
    public async Task A_failed_batch_is_reported_and_the_IOCs_behind_it_are_still_swept()
    {
        var sweep = new FakeSweep { Throw = new IOException("IocHits.csv is open in another program") };
        var queue = new IocSweepQueue("case", Settle, sweep.SweepAsync);
        var batches = new List<IocSweepBatch>();
        queue.BatchFinished += b => { lock (batches) batches.Add(b); };

        queue.Add([Ioc("a.exe")]);
        await sweep.Started.Task.WaitAsync(Wait);
        queue.Add([Ioc("b.exe")]);
        sweep.FinishAll();
        await queue.WhenIdleAsync().WaitAsync(Wait);

        Assert.Equal(2, batches.Count);
        Assert.Contains("open in another program", batches[0].Error);
        Assert.Null(batches[0].Result);
        Assert.Null(batches[1].Error);
        Assert.Equal("b.exe", Assert.Single(batches[1].Iocs).Value);
    }

    [Fact]
    public async Task Adding_after_the_queue_went_idle_starts_a_new_batch()
    {
        var sweep = new FakeSweep();
        sweep.FinishAll();
        var queue = new IocSweepQueue("case", Settle, sweep.SweepAsync);

        queue.Add([Ioc("a.exe")]);
        await queue.WhenIdleAsync().WaitAsync(Wait);
        queue.Add([Ioc("a.exe")]);   // re-added after its sweep: searched for again
        await queue.WhenIdleAsync().WaitAsync(Wait);

        Assert.Equal([["a.exe"], ["a.exe"]], sweep.Batches);
    }

    // ------------------------------------------------------------------ scan slots

    private const long GB = 1L << 30;

    [Fact]
    public async Task One_scan_always_runs_even_with_no_memory_free()
    {
        var slots = new SweepSlots(4, () => 0, TimeSpan.FromMilliseconds(20));

        await slots.WaitAsync(CancellationToken.None).WaitAsync(Wait);
        var second = slots.WaitAsync(CancellationToken.None);
        await Task.Delay(100);
        Assert.False(second.IsCompleted);

        slots.Release();
        await second.WaitAsync(Wait);
        Assert.Equal(1, slots.Peak);
    }

    [Fact]
    public async Task With_memory_to_spare_scans_run_up_to_the_limit()
    {
        var slots = new SweepSlots(3, () => 64 * GB, TimeSpan.FromMilliseconds(20));

        for (var i = 0; i < 3; i++) await slots.WaitAsync(CancellationToken.None).WaitAsync(Wait);
        var fourth = slots.WaitAsync(CancellationToken.None);
        await Task.Delay(100);

        Assert.False(fourth.IsCompleted);
        slots.Release();
        await fourth.WaitAsync(Wait);
        Assert.Equal(3, slots.Peak);
    }

    [Fact]
    public async Task Keep_free_is_left_free()
    {
        // Room for one more scan on top of 2 GB, not on top of Keep free's 4 GB.
        var free = 2 * GB + SweepSlots.ScanEstimateBytes;
        var slots = new SweepSlots(4, () => free, TimeSpan.FromMilliseconds(20)) { KeepFreeBytes = 4 * GB };

        await slots.WaitAsync(CancellationToken.None).WaitAsync(Wait);
        var second = slots.WaitAsync(CancellationToken.None);
        await Task.Delay(100);
        Assert.False(second.IsCompleted);

        // Keep free lowered, as a run or the app sets it: the poll lets the waiting scan in.
        slots.KeepFreeBytes = 2 * GB;
        await second.WaitAsync(Wait);
        Assert.Equal(2, slots.Peak);
    }

    [Fact]
    public async Task Scans_run_one_at_a_time_when_free_memory_cannot_be_read()
    {
        var slots = new SweepSlots(4, () => null, TimeSpan.FromMilliseconds(20));

        await slots.WaitAsync(CancellationToken.None).WaitAsync(Wait);
        var second = slots.WaitAsync(CancellationToken.None);
        await Task.Delay(100);

        Assert.False(second.IsCompleted);
        Assert.Equal(1, slots.Peak);
    }

    [Fact]
    public async Task A_scan_waiting_for_a_slot_stops_when_cancelled()
    {
        var slots = new SweepSlots(1, () => 64 * GB, TimeSpan.FromSeconds(30));
        await slots.WaitAsync(CancellationToken.None);
        using var cancel = new CancellationTokenSource();

        var waiting = slots.WaitAsync(cancel.Token);
        cancel.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(Wait));
    }
}
