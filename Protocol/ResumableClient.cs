using System.Security.Cryptography;
namespace SecureTransfer.Protocol;

public sealed partial class TransferClient
{
    public Task<EndInfo> ResumeUploadAsync(string local, string checkpointPath,
        IProgress<TransferProgress>? progress = null, CancellationToken ct = default) => RunAsync(async context =>
    {
        string source = Path.GetFullPath(local), name = Path.GetFileName(source);
        SafeFiles.ValidateName(name);
        await using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, Wire.ChunkSize, FileOptions.Asynchronous);
        if (input.Length > SafeFiles.MaxFileSize) throw new ProtocolException("文件超限");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(checkpointPath))!);
        using var claim = ResumeFiles.Claim(checkpointPath + ".lock");
        string digest = await ResumeFiles.HashAsync(input, input.Length, context.Token);
        var state = File.Exists(checkpointPath) ? ResumeFiles.Load(checkpointPath) : new Checkpoint
        {
            TransferId = Guid.NewGuid().ToString("N"), Owner = endpointIdentity, Direction = "upload",
            Name = name, Length = input.Length, Sha256 = digest, SourceIdentity = source
        };
        if (state.Owner != endpointIdentity || state.Direction != "upload" || state.Name != name || state.SourceIdentity != source ||
            state.Length != input.Length || !SafeFiles.HashEquals(digest, state.Sha256))
            throw new ProtocolException("源文件变化或断点不属于当前账号/服务器/文件");
        if (!SafeFiles.HashEquals(await ResumeFiles.HashAsync(input, state.Offset, context.Token), state.PrefixSha256))
            throw new ProtocolException("本地断点摘要不匹配");
        ResumeFiles.Save(checkpointPath, state);
        uint id = Next(); context.StartRequest();
        await wire!.SendJsonAsync(MessageType.ResumeUpload, id,
            new ResumeRequest(state.TransferId, name, state.Length, digest, state.Offset, state.PrefixSha256, !state.RemoteCreated), context.Token);
        var ready = (await ExpectAsync(id, MessageType.ResumeReady, context.Token)).Json<ResumeInfo>();
        ValidateResumeInfo(state, ready, true);
        if (!SafeFiles.HashEquals(await ResumeFiles.HashAsync(input, ready.Offset, context.Token), ready.PrefixSha256))
            throw new ProtocolException("服务端断点不匹配源文件");
        state = state with { Offset = ready.Offset, PrefixSha256 = ready.PrefixSha256, RemoteCreated = true, Completed = ready.Completed };
        ResumeFiles.Save(checkpointPath, state);
        long resumed = ready.Offset;
        progress?.Report(new(state.Offset, state.Length, resumed, Session!.ConnectionId));
        if (ready.Completed) return new EndInfo(state.Length, digest);
        using var hash = await SeedHash(input, state.Offset, context.Token);
        byte[] buffer = new byte[ready.ChunkBytes]; int count;
        while ((count = await input.ReadAsync(buffer, context.Token)) != 0)
        {
            await wire.SendAsync(MessageType.Data, id, buffer.AsMemory(0, count), context.Token);
            hash.AppendData(buffer, 0, count);
            var ack = (await ExpectAsync(id, MessageType.ChunkAck, context.Token)).Json<ChunkReceipt>();
            string prefix = Convert.ToHexString(hash.GetCurrentHash());
            if (ack.Offset != state.Offset + count || !SafeFiles.HashEquals(prefix, ack.PrefixSha256))
                throw new ProtocolException("上传分块确认不匹配");
            state = state with { Offset = ack.Offset, PrefixSha256 = prefix, UpdatedUtc = DateTimeOffset.UtcNow };
            ResumeFiles.Save(checkpointPath, state);
            progress?.Report(new(state.Offset, state.Length, resumed, Session!.ConnectionId));
        }
        var end = new EndInfo(state.Length, digest);
        await wire.SendJsonAsync(MessageType.TransferEnd, id, end, context.Token);
        var result = (await ExpectAsync(id, MessageType.TransferResult, context.Token)).Json<EndInfo>();
        ValidateEnd(end, result);
        ResumeFiles.Save(checkpointPath, state with { Completed = true });
        return result;
    }, ct);

    public Task<EndInfo> ResumeDownloadAsync(string name, string directory, string checkpointPath,
        IProgress<TransferProgress>? progress = null, CancellationToken ct = default) => RunAsync(async context =>
    {
        string target = SafeFiles.Target(directory, name);
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(checkpointPath))!);
        using var claim = ResumeFiles.Claim(checkpointPath + ".lock");
        bool existed = File.Exists(checkpointPath);
        var state = existed ? ResumeFiles.Load(checkpointPath) : new Checkpoint
        {
            TransferId = Guid.NewGuid().ToString("N"), Owner = endpointIdentity, Direction = "download",
            Name = name, Length = 0, Sha256 = ResumeFiles.EmptyHash, SourceIdentity = target
        };
        if (state.Owner != endpointIdentity || state.Direction != "download" || state.Name != name || state.SourceIdentity != target)
            throw new ProtocolException("下载断点不属于当前账号/服务器/路径");
        string data = Path.Combine(directory, ".sft-resume-" + state.TransferId + ".data");
        bool committed = File.Exists(target);
        if (committed)
        {
            if (!existed || state.Offset != state.Length || !state.RemoteCreated)
                throw new RemoteException(new Result(false, "Conflict", "本地文件已存在，拒绝覆盖", false));
            await using var existing = File.OpenRead(target);
            if (existing.Length != state.Length || !SafeFiles.HashEquals(await ResumeFiles.HashAsync(existing, existing.Length, context.Token), state.Sha256))
                throw new ProtocolException("本地正式文件与断点身份不匹配");
        }
        else
        {
            // Verify persisted bytes before requesting server data. A corrupt checkpoint keeps the healthy connection.
            await using var check = await DurableReceiver.OpenAsync(checkpointPath, data, state, context.Token);
        }
        ResumeFiles.Save(checkpointPath, state);
        uint id = Next(); context.StartRequest();
        await wire!.SendJsonAsync(MessageType.ResumeDownload, id,
            new ResumeRequest(state.TransferId, name, state.Length, state.Sha256, state.Offset, state.PrefixSha256, !state.RemoteCreated), context.Token);
        var ready = (await ExpectAsync(id, MessageType.ResumeReady, context.Token)).Json<ResumeInfo>();
        ValidateResumeInfo(state, ready, state.RemoteCreated);
        if (ready.Offset != state.Offset || !SafeFiles.HashEquals(ready.PrefixSha256, state.PrefixSha256))
            throw new ProtocolException("下载恢复偏移不匹配");
        state = state with { Length = ready.Length, Sha256 = ready.Sha256, RemoteCreated = true };
        ResumeFiles.Save(checkpointPath, state);
        long resumed = state.Offset;
        await using var receiver = committed ? null : await DurableReceiver.OpenAsync(checkpointPath, data, state, context.Token);
        await wire.SendJsonAsync(MessageType.Ready, id, new Result(true, "Ready", "恢复接收", false), context.Token);
        progress?.Report(new(state.Offset, state.Length, resumed, Session!.ConnectionId));
        while (true)
        {
            var f = await wire.ReadAsync(context.Token, (t, r) => r == id && t is MessageType.Data or MessageType.TransferEnd or MessageType.Error);
            if (f.Type == MessageType.Error) ThrowRemote(f);
            if (f.Type == MessageType.Data)
            {
                if (receiver is null || f.Payload.Length > ready.ChunkBytes) throw new ProtocolException("下载数据不符合协商状态");
                await receiver.AppendAsync(f.Payload, context.Token); state = receiver.State;
                await wire.SendJsonAsync(MessageType.ChunkAck, id, new ChunkReceipt(state.Offset, state.PrefixSha256), context.Token);
                progress?.Report(new(state.Offset, state.Length, resumed, Session!.ConnectionId)); continue;
            }
            var end = f.Json<EndInfo>(); ValidateEnd(new EndInfo(state.Length, state.Sha256), end);
            if (receiver is not null) await receiver.CommitAsync(target, end);
            await wire.SendJsonAsync(MessageType.TransferResult, id, end, context.Token);
            await ExpectAsync(id, MessageType.Ready, context.Token);
            ResumeFiles.Save(checkpointPath, state with { Completed = true, UpdatedUtc = DateTimeOffset.UtcNow });
            return end;
        }
    }, ct);
    private static void ValidateResumeInfo(Checkpoint state, ResumeInfo info, bool checkIdentity)
    {
        if (info.TransferId != state.TransferId || info.Name != state.Name || info.Offset < 0 || info.Offset > info.Length ||
            info.Length < 0 || info.Length > SafeFiles.MaxFileSize || info.ChunkBytes < 1 || info.ChunkBytes > Wire.ChunkSize ||
            !SafeFiles.HashEquals(info.Sha256, info.Sha256) ||
            (checkIdentity && (info.Length != state.Length || !SafeFiles.HashEquals(info.Sha256, state.Sha256))) ||
            (info.Completed && info.Offset != info.Length)) throw new ProtocolException("恢复响应无效");
    }
    private static async Task<IncrementalHash> SeedHash(Stream input, long length, CancellationToken ct)
    {
        input.Position = 0; var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[Wire.ChunkSize]; long left = length;
        try
        {
            while (left > 0)
            {
                int n = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(left, buffer.Length)), ct);
                if (n == 0) throw new EndOfStreamException();
                hash.AppendData(buffer, 0, n); left -= n;
            }
            return hash;
        }
        catch { hash.Dispose(); throw; }
    }
}
