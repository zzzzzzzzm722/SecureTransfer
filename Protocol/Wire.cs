using System.Buffers.Binary;
using System.Text.Json;

namespace SecureTransfer.Protocol;

public enum MessageType : byte
{
    Login = 1, LoginResult = 2, List = 3, ListResult = 4, UploadBegin = 5, Ready = 6,
    DownloadRequest = 7, TransferMeta = 8, Data = 9, TransferEnd = 10, TransferResult = 11,
    Ping = 12, Pong = 13, Error = 14, Disconnect = 15,
    ResumeUpload = 16, ResumeDownload = 17, ResumeReady = 18, ChunkAck = 19
}
public record Login(string User, string Password);
public record LoginResult(string ConnectionId, string User, string Tls);
public record FileMeta(string Name, long Length);
public record EndInfo(long Length, string Sha256);
// Missing termination information is treated conservatively as fatal.
public record Result(bool Success, string Code, string Message, bool Fatal = true);
public record ResumeRequest(string TransferId, string Name, long Length, string Sha256,
    long Offset, string PrefixSha256, bool Create);
public record ResumeInfo(string TransferId, string Name, long Length, string Sha256,
    long Offset, string PrefixSha256, int ChunkBytes, bool Completed = false);
public record ChunkReceipt(long Offset, string PrefixSha256);
public record TransferProgress(long Bytes, long Total, long ResumedFrom, string ConnectionId)
{
    public int Percent => (int)(Bytes * 100 / Math.Max(1, Total));
}
public record FileList(FileMeta[] Files);
public sealed class ProtocolException(string message, uint? requestId = null) : IOException(message)
{
    public uint? RequestId { get; } = requestId;
}
public sealed class RemoteException(Result result) : Exception($"{result.Code}: {result.Message}")
{
    public string Code { get; } = result.Code;
    public bool Fatal { get; } = result.Fatal;
}
public record Frame(MessageType Type, uint RequestId, byte[] Payload)
{
    public T Json<T>() => JsonSerializer.Deserialize<T>(Payload) ?? throw new ProtocolException("空 JSON");
}

// Exactly one reader per connection. All writes pass through this gate, including heartbeat.
public sealed class Wire(Stream stream, int timeoutSeconds = 30) : IDisposable
{
    public const int HeaderSize = 16, ChunkSize = 65536, ControlLimit = 16384;
    public const uint Magic = 0x53465431; // SFT1
    private readonly SemaphoreSlim writeGate = new(1, 1);
    public async Task<Frame> ReadAsync(CancellationToken ct = default, Func<MessageType, uint, bool>? allowed = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        byte[] header = new byte[HeaderSize];
        await stream.ReadExactlyAsync(header, deadline.Token);
        var type = (MessageType)header[5];
        uint id = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8));
        uint length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(12));
        if (BinaryPrimitives.ReadUInt32BigEndian(header) != Magic || header[4] != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(6)) != 0 || !Enum.IsDefined(type) || id == 0)
            throw new ProtocolException("非法报头、版本、标志或请求 ID", id);
        if (length > (type == MessageType.Data ? ChunkSize : ControlLimit) ||
            (type == MessageType.Data && length == 0) ||
            (type is MessageType.Ping or MessageType.Pong or MessageType.Disconnect or MessageType.List && length != 0))
            throw new ProtocolException("非法载荷长度", id);
        if (allowed is not null && !allowed(type, id))
            throw new ProtocolException("当前状态不接受此报文", id);
        byte[] payload = new byte[(int)length]; // only after header, size and state validation
        await stream.ReadExactlyAsync(payload, deadline.Token);
        return new Frame(type, id, payload);
    }
    public Task SendJsonAsync<T>(MessageType type, uint id, T value, CancellationToken ct = default) =>
        SendAsync(type, id, JsonSerializer.SerializeToUtf8Bytes(value), ct);
    public async Task SendAsync(MessageType type, uint id, ReadOnlyMemory<byte> data = default, CancellationToken ct = default)
    {
        if (id == 0 || data.Length > (type == MessageType.Data ? ChunkSize : ControlLimit))
            throw new ProtocolException("发送帧超限");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        await writeGate.WaitAsync(deadline.Token);
        try
        {
            byte[] header = new byte[HeaderSize];
            BinaryPrimitives.WriteUInt32BigEndian(header, Magic);
            header[4] = 1;
            header[5] = (byte)type;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), id);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), (uint)data.Length);
            await stream.WriteAsync(header, deadline.Token);
            await stream.WriteAsync(data, deadline.Token);
            await stream.FlushAsync(deadline.Token);
        }
        finally { writeGate.Release(); }
    }
    public void Dispose() => writeGate.Dispose();
}
