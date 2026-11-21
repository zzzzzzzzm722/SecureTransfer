using System.Threading.Channels;
namespace SecureTransfer.Protocol;

public sealed record ConnectionSettings(string Host, int Port, string CaPath, string User, string Password,
    string ClientPfx, string PfxPassword, int Connections = 3);

/// <summary>A bounded pool of long-lived authenticated sessions. A canceled job retires only its own session.</summary>
public sealed class TransferPool : IAsyncDisposable
{
    private sealed class Slot { public TransferClient Client = new(); }
    private readonly Channel<Slot> available;
    private readonly Slot[] slots;
    private readonly CancellationTokenSource lifetime = new();
    private ConnectionSettings? settings;
    private readonly object sync = new();
    private Task? disposal;
    private TransferPool(ConnectionSettings settings)
    {
        if (settings.Connections is < 1 or > 3) throw new ArgumentOutOfRangeException(nameof(settings), "连接池范围为 1–3");
        this.settings = settings;
        slots = Enumerable.Range(0, settings.Connections).Select(_ => new Slot()).ToArray();
        foreach (var slot in slots) Observe(slot.Client);
        available = Channel.CreateBounded<Slot>(settings.Connections);
    }
    public bool IsOpen => !lifetime.IsCancellationRequested && settings is not null;
    public event Action? ConnectionChanged;
    private void Observe(TransferClient client) => client.ConnectionChanged += () => ConnectionChanged?.Invoke();
    public int ConnectedCount => slots.Count(s => s.Client.Connected);
    public string[] ConnectionIds => slots.Select(s => s.Client.Session?.ConnectionId).OfType<string>().ToArray();
    public static async Task<TransferPool> ConnectAsync(ConnectionSettings settings, CancellationToken ct = default)
    {
        var pool = new TransferPool(settings);
        try
        {
            foreach (var slot in pool.slots)
            {
                await pool.ConnectSlot(slot, ct);
                await pool.available.Writer.WriteAsync(slot, ct);
            }
            return pool;
        }
        catch { await pool.DisposeAsync(); throw; }
    }
    private Task ConnectSlot(Slot slot, CancellationToken ct)
    {
        var s = settings ?? throw new ObjectDisposedException(nameof(TransferPool));
        return slot.Client.ConnectAsync(s.Host, s.Port, s.CaPath, s.User, s.Password, s.ClientPfx, s.PfxPassword, cancellationToken: ct);
    }
    public async Task<T> ExecuteAsync<T>(Func<TransferClient, CancellationToken, Task<T>> action, CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, lifetime.Token);
        var slot = await available.Reader.ReadAsync(linked.Token);
        try
        {
            if (!slot.Client.Connected)
            {
                await slot.Client.DisposeAsync();
                lock (sync) { linked.Token.ThrowIfCancellationRequested(); slot.Client = new TransferClient(); Observe(slot.Client); }
                await ConnectSlot(slot, linked.Token);
            }
            return await action(slot.Client, linked.Token);
        }
        finally { if (!lifetime.IsCancellationRequested) available.Writer.TryWrite(slot); }
    }
    public Task<FileMeta[]> ListAsync(CancellationToken ct = default) => ExecuteAsync((c, t) => c.ListAsync(t), ct);
    public ValueTask DisposeAsync() { lock (sync) return new ValueTask(disposal ??= DisposeCore()); }
    private async Task DisposeCore()
    {
        lock (sync) { lifetime.Cancel(); settings = null; available.Writer.TryComplete(); }
        foreach (var slot in slots) slot.Client.Abort();
        await Task.WhenAll(slots.Select(async slot => await slot.Client.DisposeAsync()));
    }
}

public sealed record JobPlan(string Id, string Direction, string Source, string Destination, string Checkpoint);
public sealed class TransferJob(JobPlan plan)
{
    public JobPlan Plan { get; } = plan;
    public string State { get; internal set; } = "等待";
    public TransferProgress? Progress { get; internal set; }
    public EndInfo? Result { get; internal set; }
    public string? Error { get; internal set; }
    public DateTimeOffset? StartedAt { get; internal set; }
    public DateTimeOffset? FinishedAt { get; internal set; }
    public Task Completion { get; internal set; } = Task.CompletedTask;
    internal CancellationTokenSource? Cancellation;
}

/// <summary>Shared GUI/test task controller; the queue contains paths and IDs, never credentials.</summary>
public sealed class TransferWorkspace : IAsyncDisposable
{
    private readonly TransferPool pool;
    private readonly string directory;
    private readonly object sync = new();
    private readonly List<TransferJob> jobs = [];
    private bool closed;
    private Task? disposal;
    public event Action<TransferJob>? Changed;
    public TransferWorkspace(TransferPool pool, string directory)
    {
        this.pool = pool; this.directory = Path.GetFullPath(directory); SafeFiles.NoReparse(directory); Directory.CreateDirectory(directory);
        string queue = Path.Combine(directory, "queue.json");
        if (File.Exists(queue))
        {
            if (new FileInfo(queue).Length > 262144) throw new IOException("任务队列超限");
            var plans = System.Text.Json.JsonSerializer.Deserialize<JobPlan[]>(File.ReadAllBytes(queue)) ?? [];
            foreach (var plan in plans.Take(128))
            {
                ResumeFiles.ValidateId(plan.Id);
                if (plan.Direction is not ("upload" or "download") || plan.Checkpoint != Path.Combine(this.directory, plan.Id + ".json"))
                    throw new ProtocolException("任务队列字段不合法");
                jobs.Add(new TransferJob(plan) { State = "可恢复" });
            }
        }
    }
    public TransferJob[] Jobs { get { lock (sync) return jobs.ToArray(); } }
    public TransferJob Add(string direction, string source, string destination = "")
    {
        if (direction is not ("upload" or "download")) throw new ArgumentException("任务类型错误");
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(closed, this);
            if (jobs.Count >= 128) throw new IOException("任务队列最多 128 项；请使用新的恢复目录");
            string id = Guid.NewGuid().ToString("N");
            var job = new TransferJob(new JobPlan(id, direction, source, destination, Path.Combine(directory, id + ".json")));
            jobs.Add(job); SaveQueue(); return job;
        }
    }
    private void SaveQueue()
    {
        string path = Path.Combine(directory, "queue.json"), temp = path + ".new";
        File.WriteAllBytes(temp, System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(jobs.Select(j => j.Plan)));
        File.Move(temp, path, true);
    }
    public Task Start(TransferJob job)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(closed, this);
            if (!jobs.Contains(job)) throw new ArgumentException("任务不属于此队列");
            if (!job.Completion.IsCompleted) return job.Completion;
            job.Cancellation?.Dispose(); job.Cancellation = new CancellationTokenSource();
            job.Error = null; job.State = "等待连接"; job.Result = null; job.FinishedAt = null;
            job.Completion = Task.Run(() => Run(job, job.Cancellation.Token)); return job.Completion;
        }
    }
    public void Cancel(TransferJob job) { lock (sync) job.Cancellation?.Cancel(); }
    private async Task Run(TransferJob job, CancellationToken ct)
    {
        try
        {
            await pool.ExecuteAsync(async (client, token) =>
            {
                job.StartedAt = DateTimeOffset.UtcNow; job.State = "传输中"; Changed?.Invoke(job);
                var progress = new InlineProgress(value => { job.Progress = value; job.State = value.ResumedFrom > 0 ? "续传中" : "传输中"; Changed?.Invoke(job); });
                job.Result = job.Plan.Direction == "upload"
                    ? await client.ResumeUploadAsync(job.Plan.Source, job.Plan.Checkpoint, progress, token)
                    : await client.ResumeDownloadAsync(job.Plan.Source, job.Plan.Destination, job.Plan.Checkpoint, progress, token);
                return true;
            }, ct);
            job.State = "已完成";
        }
        catch (Exception) when (ct.IsCancellationRequested || !pool.IsOpen) { job.State = "已中断，可恢复"; }
        catch (OperationCanceledException) { job.State = "已中断，可恢复"; }
        catch (Exception ex) { job.State = "失败，可重试"; job.Error = ex.Message; }
        finally { job.FinishedAt = DateTimeOffset.UtcNow; Changed?.Invoke(job); }
    }
    private sealed class InlineProgress(Action<TransferProgress> action) : IProgress<TransferProgress>
    { public void Report(TransferProgress value) => action(value); }
    public ValueTask DisposeAsync() { lock (sync) return new ValueTask(disposal ??= DisposeCore()); }
    private async Task DisposeCore()
    {
        TransferJob[] snapshot;
        lock (sync) { closed = true; snapshot = jobs.ToArray(); foreach (var job in snapshot) job.Cancellation?.Cancel(); }
        await pool.DisposeAsync();
        await Task.WhenAll(snapshot.Select(j => j.Completion));
    }
}
