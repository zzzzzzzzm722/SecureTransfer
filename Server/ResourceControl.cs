using System.Diagnostics;
namespace SecureTransfer.Server;

public sealed record UserRate(long UploadBytesPerSecond = 2097152, long DownloadBytesPerSecond = 2097152);

/// <summary>Strict asynchronous pacing shared by all sessions of one authenticated account and direction.</summary>
internal sealed class BytePacer(long bytesPerSecond)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    public long Rate { get; } = bytesPerSecond;
    public async Task WaitAsync(int bytes, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try { await Task.Delay(TimeSpan.FromSeconds(bytes / (double)Rate), ct); }
        finally { gate.Release(); }
    }
}
internal sealed class UserRuntime(UserRate rate)
{
    public BytePacer Upload { get; } = new(rate.UploadBytesPerSecond);
    public BytePacer Download { get; } = new(rate.DownloadBytesPerSecond);
    public int Connections, Requests;
    public long Window = Environment.TickCount64;
}

/// <summary>Both rolling progress and total duration count network time, excluding server-imposed throttle waits.</summary>
internal sealed class ProgressGuard : IAsyncDisposable
{
    private readonly CancellationTokenSource cancellation;
    private readonly Stopwatch watch = Stopwatch.StartNew();
    private readonly Task monitor;
    private readonly double grace, window, minimum, maximum;
    private long bytes, excludedTicks, throttleStarted;
    public bool Violated { get; private set; }
    public CancellationToken Token => cancellation.Token;
    public ProgressGuard(ServerOptions options, long remaining, long rate, CancellationToken ct)
    {
        cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        grace = options.ProgressGraceSeconds; window = options.ProgressWindowSeconds;
        minimum = Math.Min(options.MinTransferBytesPerSecond, rate / (double)(options.MaxPerUserConnections * 8));
        minimum = Math.Max(1, minimum);
        maximum = Math.Min(options.MaxTransferSeconds, grace + window + remaining / minimum * 2);
        monitor = Monitor();
    }
    public void Advance(int count) => Interlocked.Add(ref bytes, count);
    public async Task Throttle(BytePacer limiter, int count)
    {
        long start = Stopwatch.GetTimestamp();
        Interlocked.Exchange(ref throttleStarted, start);
        try { await limiter.WaitAsync(count, Token); }
        finally { Interlocked.Add(ref excludedTicks, Stopwatch.GetTimestamp() - start); Interlocked.Exchange(ref throttleStarted, 0); }
    }
    private async Task Monitor()
    {
        double lastTime = grace; long lastBytes = 0;
        try
        {
            while (!Token.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(.25, window / 4)), Token);
                double elapsed = watch.Elapsed.TotalSeconds - Interlocked.Read(ref excludedTicks) / (double)Stopwatch.Frequency;
                long waiting = Interlocked.Read(ref throttleStarted);
                if (waiting != 0) elapsed -= (Stopwatch.GetTimestamp() - waiting) / (double)Stopwatch.Frequency;
                if (elapsed > maximum) { Violated = true; cancellation.Cancel(); break; }
                if (elapsed < lastTime + window) continue;
                long nowBytes = Interlocked.Read(ref bytes);
                if (nowBytes - lastBytes < minimum * (elapsed - lastTime))
                { Violated = true; cancellation.Cancel(); break; }
                lastTime = elapsed; lastBytes = nowBytes;
            }
        }
        catch (OperationCanceledException) { }
    }
    public async ValueTask DisposeAsync() { cancellation.Cancel(); await monitor; cancellation.Dispose(); }
}

public sealed class RotatingLog : IDisposable
{
    private readonly string directory;
    private readonly long limit;
    private readonly int archives;
    private readonly object sync = new();
    private StreamWriter writer;
    public RotatingLog(string directory, long limit = 2097152, int archives = 3)
    {
        this.directory = Path.GetFullPath(directory); this.limit = Math.Max(4096, limit); this.archives = Math.Clamp(archives, 1, 10);
        SecureTransfer.Protocol.SafeFiles.NoReparse(directory); Directory.CreateDirectory(directory); writer = Open();
    }
    private StreamWriter Open()
    {
        string path = Path.Combine(directory, "server.log"); SecureTransfer.Protocol.SafeFiles.NoReparse(path);
        return new(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
    }
    public void Write(string line)
    {
        lock (sync)
        {
            if (writer.BaseStream.Length >= limit)
            {
                writer.Dispose();
                for (int n = archives; n >= 1; n--)
                {
                    string from = Path.Combine(directory, n == 1 ? "server.log" : $"server.{n - 1}.log");
                    string to = Path.Combine(directory, $"server.{n}.log");
                    SecureTransfer.Protocol.SafeFiles.NoReparse(from); SecureTransfer.Protocol.SafeFiles.NoReparse(to);
                    if (File.Exists(from)) File.Move(from, to, true);
                }
                writer = Open();
            }
            writer.WriteLine($"{DateTimeOffset.Now:O} {line[..Math.Min(line.Length, 512)]}");
        }
    }
    public void Dispose() { lock (sync) writer.Dispose(); }
}
