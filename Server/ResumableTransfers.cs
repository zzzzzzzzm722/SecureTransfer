using System.Security.Cryptography;
using SecureTransfer.Protocol;
namespace SecureTransfer.Server;

public sealed partial class TransferServer
{
    private static string StateDirectory(string directory)
    {
        string path = Path.Combine(directory, ".resumes"); SafeFiles.NoReparse(path);
        Directory.CreateDirectory(path); return path;
    }
    private IEnumerable<string> StatePaths(string directory)
    {
        string path = Path.Combine(directory, ".resumes"); SafeFiles.NoReparse(path);
        return Directory.Exists(path) ? Directory.EnumerateFiles(path, "*.json") : [];
    }
    private bool HasPendingUpload(string directory, string name, string? exceptId = null)
    {
        foreach (string path in StatePaths(directory))
        {
            var state = ResumeFiles.Load(path);
            if (!state.Completed && state.Direction == "upload" && state.TransferId != exceptId &&
                string.Equals(state.Name, name, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
    private void CleanupResumes(string directory)
    {
        lock (admission)
        {
            foreach (string path in StatePaths(directory).ToArray())
            {
                if (activeResumes.ContainsKey(path)) continue;
                string id = Path.GetFileNameWithoutExtension(path);
                if (!Guid.TryParseExact(id, "N", out _)) continue;
                SafeFiles.NoReparse(path);
                // Persisted file mtime is a recovery fallback if JSON itself is corrupt.
                if (DateTime.UtcNow - File.GetLastWriteTimeUtc(path) < TimeSpan.FromSeconds(options.ResumeRetentionSeconds)) continue;
                string data = Path.Combine(Path.GetDirectoryName(path)!, id + ".data"); SafeFiles.NoReparse(data);
                if (File.Exists(data)) File.Delete(data);
                File.Delete(path);
                string pending = path + ".new"; SafeFiles.NoReparse(pending);
                if (File.Exists(pending)) File.Delete(pending);
                Emit($"EXPIRE transfer={id}");
            }
            // Initial metadata publication can crash before the first rename. Reclaim only
            // expired, inactive artifacts in our reserved GUID namespace with no metadata.
            string folder = Path.Combine(directory, ".resumes");
            if (!Directory.Exists(folder)) return;
            foreach (string artifact in Directory.EnumerateFiles(folder).ToArray())
            {
                string name = Path.GetFileName(artifact);
                string? id = name.EndsWith(".json.new", StringComparison.Ordinal) ? name[..^9] : name.EndsWith(".data", StringComparison.Ordinal) ? name[..^5] : null;
                if (id is null || !Guid.TryParseExact(id, "N", out _)) continue;
                string metadata = Path.Combine(folder, id + ".json");
                if (File.Exists(metadata) || activeResumes.ContainsKey(metadata)) continue;
                SafeFiles.NoReparse(artifact);
                if (DateTime.UtcNow - File.GetLastWriteTimeUtc(artifact) >= TimeSpan.FromSeconds(options.ResumeRetentionSeconds)) File.Delete(artifact);
            }
        }
    }
    private int ChunkBytes(BytePacer limiter) => (int)Math.Clamp(limiter.Rate / (options.MaxPerUserConnections * 4), 256, Wire.ChunkSize);
    private static void CheckRequest(ResumeRequest request)
    {
        ResumeFiles.ValidateId(request.TransferId); SafeFiles.ValidateName(request.Name);
        if (request.Length < 0 || request.Length > SafeFiles.MaxFileSize || request.Offset < 0 ||
            request.Offset > request.Length || !SafeFiles.HashEquals(request.Sha256, request.Sha256) ||
            !SafeFiles.HashEquals(request.PrefixSha256, request.PrefixSha256)) throw new ProtocolException("续传字段不合法");
    }
    private async Task ResumeUpload(Wire wire, Frame frame, string directory, string owner, UserRuntime user)
    {
        var request = frame.Json<ResumeRequest>(); CheckRequest(request);
        string target = SafeFiles.Target(directory, request.Name);
        string metadata = Path.Combine(StateDirectory(directory), request.TransferId + ".json");
        string data = Path.ChangeExtension(metadata, ".data");
        if (!writers.TryAdd(target, 0)) { await Error(wire, frame.RequestId, "Conflict", "目标有活动传输"); return; }
        if (!activeResumes.TryAdd(metadata, 0))
        { writers.TryRemove(target, out _); await Error(wire, frame.RequestId, "Conflict", "此断点正被使用"); return; }
        try
        {
            Checkpoint state;
            try
            {
                lock (admission)
                {
                    CleanupResumes(directory);
                    if (File.Exists(metadata)) state = ResumeFiles.Load(metadata);
                    else
                    {
                        if (!request.Create) throw new ResumeRejected("ResumeNotFound", "断点不存在、已过期或不属于此账号");
                        if (request.Offset != 0) throw new ResumeRejected("ResumeOffset", "新传输偏移必须为零");
                        if (File.Exists(target) || HasPendingUpload(directory, request.Name)) throw new ResumeRejected("Conflict", "同名文件或断点已存在");
                        if (StatePaths(directory).Count() >= options.MaxResumeStates ||
                            Directory.EnumerateFiles(directory).Count() + StatePaths(directory).Select(ResumeFiles.Load).Count(s => s.Direction == "upload" && !s.Completed) >= 16)
                            throw new ResumeRejected("Quota", "账号文件或断点配额已用尽");
                        state = new Checkpoint { TransferId = request.TransferId, Owner = owner, Direction = "upload", Name = request.Name, Length = request.Length, Sha256 = request.Sha256, RemoteCreated = true };
                        ResumeFiles.Save(metadata, state);
                    }
                }
                if (state.Owner != owner || state.Direction != "upload" || state.TransferId != request.TransferId || state.Name != request.Name ||
                    state.Length != request.Length || !SafeFiles.HashEquals(state.Sha256, request.Sha256))
                    throw new ResumeRejected("ResumeIdentity", "续传文件身份不匹配");
                if (request.Offset > state.Offset) throw new ResumeRejected("ResumeOffset", "偏移超过服务端已确认位置");
                // Reconcile a crash between Move and the completion metadata write.
                if (File.Exists(target))
                {
                    await using var existing = File.OpenRead(target);
                    if (state.Offset != state.Length || existing.Length != state.Length ||
                        !SafeFiles.HashEquals(await ResumeFiles.HashAsync(existing, existing.Length, stop.Token), state.Sha256))
                        throw new ResumeRejected("Conflict", "目标正式文件与断点不匹配");
                    if (!SafeFiles.HashEquals(await ResumeFiles.HashAsync(existing, request.Offset, stop.Token), request.PrefixSha256))
                        throw new ResumeRejected("ResumeCorrupt", "申请的前缀摘要错误");
                    state = state with { Completed = true, UpdatedUtc = DateTimeOffset.UtcNow };
                    ResumeFiles.Save(metadata, state);
                    await wire.SendJsonAsync(MessageType.ResumeReady, frame.RequestId, Info(state, ChunkBytes(user.Upload)), stop.Token); return;
                }
                await using var prefix = new FileStream(data, FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read, Wire.ChunkSize, FileOptions.Asynchronous);
                if (request.Offset > prefix.Length || !SafeFiles.HashEquals(await ResumeFiles.HashAsync(prefix, request.Offset, stop.Token), request.PrefixSha256))
                    throw new ResumeRejected("ResumeCorrupt", "申请的前缀摘要错误");
            }
            catch (ResumeRejected ex) { await Error(wire, frame.RequestId, ex.Code, ex.Message); return; }
            catch (Exception ex) when (ex is ProtocolException or System.Text.Json.JsonException or IOException)
            { await Error(wire, frame.RequestId, "ResumeCorrupt", "断点文件损坏或不可读取"); return; }
            DurableReceiver receiver;
            try { receiver = await DurableReceiver.OpenAsync(metadata, data, state, stop.Token); }
            catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException)
            { await Error(wire, frame.RequestId, "ResumeCorrupt", "断点内容校验失败"); return; }
            await using (receiver)
            await using (var guard = new ProgressGuard(options, state.Length - state.Offset, user.Upload.Rate, stop.Token))
            {
                int chunk = ChunkBytes(user.Upload);
                await wire.SendJsonAsync(MessageType.ResumeReady, frame.RequestId, Info(state, chunk), guard.Token);
                Emit($"RESUME upload transfer={state.TransferId} offset={state.Offset} length={state.Length}");
                while (true)
                {
                    var f = await wire.ReadAsync(guard.Token, (t, r) => r == frame.RequestId && t is MessageType.Data or MessageType.TransferEnd);
                    if (f.Type == MessageType.Data)
                    {
                        if (f.Payload.Length > chunk) throw new ProtocolException("数据块超出协商长度");
                        await guard.Throttle(user.Upload, f.Payload.Length);
                        await receiver.AppendAsync(f.Payload, guard.Token); guard.Advance(f.Payload.Length);
                        await wire.SendJsonAsync(MessageType.ChunkAck, frame.RequestId, new ChunkReceipt(receiver.State.Offset, receiver.State.PrefixSha256), guard.Token);
                        continue;
                    }
                    try
                    {
                        var end = await receiver.CommitAsync(target, f.Json<EndInfo>());
                        await wire.SendJsonAsync(MessageType.TransferResult, frame.RequestId, end, guard.Token);
                        Emit($"COMMIT resume-upload transfer={state.TransferId} bytes={end.Length} sha256={end.Sha256}");
                    }
                    catch (ProtocolException) { await Error(wire, frame.RequestId, "Integrity", "完整性校验失败，未提交"); }
                    return;
                }
            }
        }
        finally { activeResumes.TryRemove(metadata, out _); writers.TryRemove(target, out _); }
    }
    private async Task ResumeDownload(Wire wire, Frame frame, string directory, string owner, UserRuntime user)
    {
        var request = frame.Json<ResumeRequest>(); CheckRequest(request);
        string target = SafeFiles.Target(directory, request.Name);
        string metadata = Path.Combine(StateDirectory(directory), request.TransferId + ".json");
        if (!activeResumes.TryAdd(metadata, 0)) { await Error(wire, frame.RequestId, "Conflict", "此断点正被使用"); return; }
        try
        {
            if (!File.Exists(target)) { await Error(wire, frame.RequestId, "NotFound", "当前账号无此文件"); return; }
            await using var input = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read, Wire.ChunkSize, FileOptions.Asynchronous);
            if (input.Length > SafeFiles.MaxFileSize) { await Error(wire, frame.RequestId, "Size", "文件超限"); return; }
            Checkpoint state;
            try
            {
                string digest = await ResumeFiles.HashAsync(input, input.Length, stop.Token);
                lock (admission)
                {
                    CleanupResumes(directory);
                    if (File.Exists(metadata)) state = ResumeFiles.Load(metadata);
                    else
                    {
                        if (!request.Create) throw new ResumeRejected("ResumeNotFound", "断点不存在、已过期或不属于此账号");
                        if (request.Offset != 0) throw new ResumeRejected("ResumeOffset", "新下载偏移必须为零");
                        if (StatePaths(directory).Count() >= options.MaxResumeStates) throw new ResumeRejected("Quota", "断点配额已用尽");
                        state = new Checkpoint { TransferId = request.TransferId, Owner = owner, Direction = "download", Name = request.Name, Length = input.Length, Sha256 = digest, RemoteCreated = true };
                        ResumeFiles.Save(metadata, state);
                    }
                }
                if (state.Owner != owner || state.Direction != "download" || state.Name != request.Name || state.TransferId != request.TransferId ||
                    state.Length != input.Length || !SafeFiles.HashEquals(state.Sha256, digest) ||
                    (!request.Create && (request.Length != state.Length || !SafeFiles.HashEquals(request.Sha256, digest))))
                    throw new ResumeRejected("ResumeIdentity", "文件变化或续传身份不匹配");
                if (request.Offset > state.Length || request.Offset > state.Offset + ChunkBytes(user.Download))
                    throw new ResumeRejected("ResumeOffset", "偏移超出已发送范围");
                string prefix = await ResumeFiles.HashAsync(input, request.Offset, stop.Token);
                if (!SafeFiles.HashEquals(prefix, request.PrefixSha256)) throw new ResumeRejected("ResumeCorrupt", "接收方断点摘要不匹配");
                state = state with { Offset = request.Offset, PrefixSha256 = prefix, UpdatedUtc = DateTimeOffset.UtcNow, Completed = false };
                ResumeFiles.Save(metadata, state);
            }
            catch (ResumeRejected ex) { await Error(wire, frame.RequestId, ex.Code, ex.Message); return; }
            catch (Exception ex) when (ex is ProtocolException or System.Text.Json.JsonException)
            { await Error(wire, frame.RequestId, "ResumeCorrupt", "断点元数据损坏"); return; }
            int chunk = ChunkBytes(user.Download);
            await using var guard = new ProgressGuard(options, state.Length - state.Offset, user.Download.Rate, stop.Token);
            await wire.SendJsonAsync(MessageType.ResumeReady, frame.RequestId, Info(state, chunk), guard.Token);
            await wire.ReadAsync(guard.Token, (t, r) => r == frame.RequestId && t == MessageType.Ready);
            Emit($"RESUME download transfer={state.TransferId} offset={state.Offset} length={state.Length}");
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = new byte[chunk]; input.Position = 0; long prefixLeft = state.Offset;
            while (prefixLeft > 0)
            {
                int n = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, prefixLeft)), guard.Token);
                if (n == 0) throw new EndOfStreamException(); hash.AppendData(buffer, 0, n); prefixLeft -= n;
            }
            int count;
            while ((count = await input.ReadAsync(buffer, guard.Token)) != 0)
            {
                await guard.Throttle(user.Download, count);
                await wire.SendAsync(MessageType.Data, frame.RequestId, buffer.AsMemory(0, count), guard.Token);
                hash.AppendData(buffer, 0, count);
                var ack = (await wire.ReadAsync(guard.Token, (t, r) => r == frame.RequestId && t == MessageType.ChunkAck)).Json<ChunkReceipt>();
                if (ack.Offset != state.Offset + count || !SafeFiles.HashEquals(ack.PrefixSha256, Convert.ToHexString(hash.GetCurrentHash())))
                    throw new ProtocolException("接收方分块确认错误");
                state = state with { Offset = ack.Offset, PrefixSha256 = ack.PrefixSha256, UpdatedUtc = DateTimeOffset.UtcNow };
                ResumeFiles.Save(metadata, state); guard.Advance(count);
            }
            var end = new EndInfo(state.Length, state.Sha256);
            await wire.SendJsonAsync(MessageType.TransferEnd, frame.RequestId, end, guard.Token);
            var result = (await wire.ReadAsync(guard.Token, (t, r) => r == frame.RequestId && t == MessageType.TransferResult)).Json<EndInfo>();
            if (result.Length != state.Length || !SafeFiles.HashEquals(result.Sha256, state.Sha256)) throw new ProtocolException("完整提交确认错误");
            ResumeFiles.Save(metadata, state with { Completed = true, UpdatedUtc = DateTimeOffset.UtcNow });
            await wire.SendJsonAsync(MessageType.Ready, frame.RequestId, new Result(true, "Idle", "下载提交已确认", false), guard.Token);
            Emit($"COMMIT resume-download transfer={state.TransferId} bytes={end.Length} sha256={end.Sha256}");
        }
        finally { activeResumes.TryRemove(metadata, out _); }
    }
    private static ResumeInfo Info(Checkpoint state, int chunk) => new(state.TransferId, state.Name, state.Length, state.Sha256, state.Offset, state.PrefixSha256, chunk, state.Completed);
    private sealed class ResumeRejected(string code, string message) : Exception(message) { public string Code { get; } = code; }
}
