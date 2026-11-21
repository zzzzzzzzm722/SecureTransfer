using System.Security.Cryptography;
using System.Text.Json;

namespace SecureTransfer.Protocol;

public sealed record Checkpoint
{
    public int Schema { get; init; } = 1;
    public required string TransferId { get; init; }
    public required string Owner { get; init; }
    public required string Direction { get; init; }
    public required string Name { get; init; }
    public required long Length { get; init; }
    public required string Sha256 { get; init; }
    public long Offset { get; init; }
    public string PrefixSha256 { get; init; } = ResumeFiles.EmptyHash;
    public DateTimeOffset UpdatedUtc { get; init; } = DateTimeOffset.UtcNow;
    public bool RemoteCreated { get; init; }
    public bool Completed { get; init; }
    public string SourceIdentity { get; init; } = "";
}

public static class ResumeFiles
{
    // Fixed-size stripes avoid an unbounded lock registry. Both scans and publication
    // participate, so Windows metadata handles cannot overlap a replacing rename.
    private static readonly object[] MetadataGates = Enumerable.Range(0, 64).Select(_ => new object()).ToArray();
    private static object MetadataGate(string path) => MetadataGates[StringComparer.OrdinalIgnoreCase.GetHashCode(Path.GetFullPath(path)) & 63];
    public static string EmptyHash { get; } = Convert.ToHexString(SHA256.HashData([]));
    public static void ValidateId(string id)
    {
        if (!Guid.TryParseExact(id, "N", out var parsed) || parsed.ToString("N") != id)
            throw new ProtocolException("非法传输标识");
    }
    public static void Validate(Checkpoint state)
    {
        ValidateId(state.TransferId); SafeFiles.ValidateName(state.Name);
        if (state.Schema != 1 || string.IsNullOrEmpty(state.Owner) || state.Direction is not ("upload" or "download") ||
            state.Length < 0 || state.Length > SafeFiles.MaxFileSize || state.Offset < 0 || state.Offset > state.Length ||
            !SafeFiles.HashEquals(state.Sha256, state.Sha256) || !SafeFiles.HashEquals(state.PrefixSha256, state.PrefixSha256))
            throw new ProtocolException("断点元数据损坏");
    }
    public static Checkpoint Load(string path)
    {
        lock (MetadataGate(path)) return LoadCore(path);
    }
    private static Checkpoint LoadCore(string path)
    {
        SafeFiles.NoReparse(path);
        // Metadata is immutable until atomic replacement. Readers must permit rename on
        // Windows, otherwise a concurrent quota scan can prevent another job's commit.
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (input.Length > 8192) throw new ProtocolException("断点元数据超限");
        var state = JsonSerializer.Deserialize<Checkpoint>(input) ?? throw new ProtocolException("断点元数据缺失");
        Validate(state); return state;
    }
    public static void Save(string path, Checkpoint state)
    {
        lock (MetadataGate(path)) SaveCore(path, state);
    }
    private static void SaveCore(string path, Checkpoint state)
    {
        Validate(state); SafeFiles.NoReparse(path);
        string temp = path + ".new"; SafeFiles.NoReparse(temp);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(state);
        using (var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        { file.Write(json); file.Flush(true); }
        File.Move(temp, path, true);
    }
    public static FileStream Claim(string path)
    {
        SafeFiles.NoReparse(path);
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
    }
    public static async Task<string> HashAsync(Stream input, long length, CancellationToken ct)
    {
        if (length < 0 || length > input.Length) throw new ProtocolException("非法断点偏移");
        long position = input.Position; input.Position = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[Wire.ChunkSize]; long remaining = length;
        try
        {
            while (remaining > 0)
            {
                int n = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), ct);
                if (n == 0) throw new EndOfStreamException();
                hash.AppendData(buffer, 0, n); remaining -= n;
            }
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        finally { input.Position = position; }
    }
}

/// <summary>Persist data before publishing its acknowledged offset. Disposal preserves recoverable data.</summary>
public sealed class DurableReceiver : IAsyncDisposable
{
    private readonly string metadata, data;
    private readonly FileStream stream;
    private readonly IncrementalHash hash;
    public Checkpoint State { get; private set; }
    private DurableReceiver(string metadata, string data, Checkpoint state, FileStream stream, IncrementalHash hash)
    { this.metadata = metadata; this.data = data; State = state; this.stream = stream; this.hash = hash; }
    public static async Task<DurableReceiver> OpenAsync(string metadata, string data, Checkpoint state, CancellationToken ct)
    {
        ResumeFiles.Validate(state); SafeFiles.NoReparse(data);
        var stream = new FileStream(data, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, Wire.ChunkSize, FileOptions.Asynchronous);
        var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            if (stream.Length < state.Offset) throw new ProtocolException("断点数据短于已确认偏移");
            byte[] buffer = new byte[Wire.ChunkSize]; long left = state.Offset;
            while (left > 0)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(left, buffer.Length)), ct);
                if (n == 0) throw new EndOfStreamException();
                hash.AppendData(buffer, 0, n); left -= n;
            }
            if (!SafeFiles.HashEquals(Convert.ToHexString(hash.GetCurrentHash()), state.PrefixSha256))
                throw new ProtocolException("断点内容摘要不匹配");
            // A crash may leave unacknowledged tail bytes. Only this transfer's data is truncated.
            stream.SetLength(state.Offset); stream.Position = state.Offset;
            return new DurableReceiver(metadata, data, state, stream, hash);
        }
        catch { stream.Dispose(); hash.Dispose(); throw; }
    }
    public async Task AppendAsync(byte[] bytes, CancellationToken ct)
    {
        if (bytes.Length == 0 || bytes.Length > State.Length - State.Offset) throw new ProtocolException("数据超出申报长度");
        await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(true);
        hash.AppendData(bytes);
        var next = State with { Offset = State.Offset + bytes.Length, PrefixSha256 = Convert.ToHexString(hash.GetCurrentHash()), UpdatedUtc = DateTimeOffset.UtcNow };
        ResumeFiles.Save(metadata, next); State = next;
    }
    public Task<EndInfo> CommitAsync(string target, EndInfo end)
    {
        if (State.Offset != State.Length || end.Length != State.Length ||
            !SafeFiles.HashEquals(State.PrefixSha256, State.Sha256) || !SafeFiles.HashEquals(end.Sha256, State.Sha256))
            throw new ProtocolException("完整长度或 SHA-256 校验失败");
        stream.Flush(true); stream.Dispose(); SafeFiles.NoReparse(target);
        File.Move(data, target, false);
        State = State with { Completed = true, UpdatedUtc = DateTimeOffset.UtcNow };
        ResumeFiles.Save(metadata, State);
        return Task.FromResult(new EndInfo(State.Length, State.Sha256));
    }
    public ValueTask DisposeAsync() { stream.Dispose(); hash.Dispose(); return ValueTask.CompletedTask; }
}
