using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecureTransfer.Protocol;

/// <summary>One reader and one business operation per TLS session; parallelism belongs to TransferPool.</summary>
public sealed partial class TransferClient : IAsyncDisposable
{
    private readonly TcpClient tcp = new();
    private readonly SemaphoreSlim operation = new(1, 1);
    private readonly CancellationTokenSource lifetime = new();
    private readonly object lifecycle = new();
    private SslStream? tls;
    private Wire? wire;
    private Task? heartbeat, connecting, disposal;
    private int stopped;
    private uint requestId;
    private string endpointIdentity = "";
    public LoginResult? Session { get; private set; }
    public event Action<string>? Status;
    public event Action? ConnectionChanged;
    public bool Connected => Volatile.Read(ref stopped) == 0 && Session is not null;
    public int Heartbeats { get; private set; }
    private uint Next() => checked(++requestId);

    public Task ConnectAsync(string host, int port, string caPath, string user, string password,
        string? clientPfx = null, string? pfxPassword = null, string? targetHost = null,
        CancellationToken cancellationToken = default)
    {
        lock (lifecycle)
        {
            if (connecting is not null || stopped != 0)
                throw new InvalidOperationException("每个会话只能连接一次；重连请创建新会话。");
            connecting = ConnectCore(host, port, caPath, user, password, clientPfx, pfxPassword, targetHost, cancellationToken);
            return connecting;
        }
    }
    private async Task ConnectCore(string host, int port, string caPath, string user, string password,
        string? clientPfx, string? pfxPassword, string? targetHost, CancellationToken ct)
    {
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token, ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            await tcp.ConnectAsync(host, port, deadline.Token);
            tls = new SslStream(tcp.GetStream(), false);
            using var ca = X509CertificateLoader.LoadCertificateFromFile(caPath);
            var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
            policy.CustomTrustStore.Add(ca);
            policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            using var certificate = clientPfx is null ? null : X509CertificateLoader.LoadPkcs12FromFile(clientPfx, pfxPassword, X509KeyStorageFlags.DefaultKeySet);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = targetHost ?? host, CertificateChainPolicy = policy,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                AllowRenegotiation = false,
                ClientCertificates = certificate is null ? null : new X509CertificateCollection { certificate }
            }, deadline.Token);
            endpointIdentity = $"{targetHost ?? host}:{port}/{user}/{ca.GetCertHashString(HashAlgorithmName.SHA256)}";
            wire = new Wire(tls);
            uint id = Next();
            await wire.SendJsonAsync(MessageType.Login, id, new Login(user, password), deadline.Token);
            var login = (await ExpectAsync(id, MessageType.LoginResult, deadline.Token)).Json<LoginResult>();
            lock (lifecycle)
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (stopped != 0) throw new OperationCanceledException();
                Session = login;
                heartbeat = HeartbeatAsync();
            }
            Notify($"已连接 {login.ConnectionId} / {login.Tls}");
            ConnectionChanged?.Invoke();
        }
        catch { Abort(); throw; }
    }
    private async Task<Frame> ExpectAsync(uint id, MessageType type, CancellationToken ct)
    {
        var f = await wire!.ReadAsync(ct, (t, r) => r == id && (t == type || t == MessageType.Error));
        if (f.Type == MessageType.Error) ThrowRemote(f);
        return f;
    }
    private void ThrowRemote(Frame f)
    {
        var error = new RemoteException(f.Json<Result>());
        if (error.Fatal) Abort();
        throw error;
    }
    private sealed class OperationContext(CancellationToken token)
    {
        public CancellationToken Token { get; } = token;
        public bool Started { get; private set; }
        // Set before the first write: even a partial request makes stream state uncertain.
        public void StartRequest() => Started = true;
    }
    private async Task<T> RunAsync<T>(Func<OperationContext, Task<T>> action, CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token, ct);
        await operation.WaitAsync(linked.Token);
        var context = new OperationContext(linked.Token);
        try
        {
            if (!Connected) throw new IOException("尚未连接");
            return await action(context);
        }
        catch (RemoteException ex) { if (ex.Fatal) Abort(); throw; }
        catch { if (context.Started) Abort(); throw; }
        finally { operation.Release(); }
    }
    public Task<FileMeta[]> ListAsync(CancellationToken ct = default) => RunAsync(async context =>
    {
        uint id = Next(); context.StartRequest();
        await wire!.SendAsync(MessageType.List, id, ct: context.Token);
        return (await ExpectAsync(id, MessageType.ListResult, context.Token)).Json<FileList>().Files;
    }, ct);

    public Task<EndInfo> UploadAsync(string local, IProgress<int>? progress = null, CancellationToken ct = default) => RunAsync(async context =>
    {
        string name = Path.GetFileName(local); SafeFiles.ValidateName(name);
        await using var input = new FileStream(local, FileMode.Open, FileAccess.Read, FileShare.Read, Wire.ChunkSize, FileOptions.Asynchronous);
        if (input.Length > SafeFiles.MaxFileSize) throw new ProtocolException("文件超限");
        uint id = Next(); context.StartRequest();
        await wire!.SendJsonAsync(MessageType.UploadBegin, id, new FileMeta(name, input.Length), context.Token);
        await ExpectAsync(id, MessageType.Ready, context.Token);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[Wire.ChunkSize]; long sent = 0; int count;
        while ((count = await input.ReadAsync(buffer, context.Token)) != 0)
        {
            hash.AppendData(buffer, 0, count); sent += count;
            await wire.SendAsync(MessageType.Data, id, buffer.AsMemory(0, count), context.Token);
            progress?.Report((int)(sent * 100 / Math.Max(1, input.Length)));
        }
        var end = new EndInfo(sent, Convert.ToHexString(hash.GetHashAndReset()));
        await wire.SendJsonAsync(MessageType.TransferEnd, id, end, context.Token);
        var result = (await ExpectAsync(id, MessageType.TransferResult, context.Token)).Json<EndInfo>();
        ValidateEnd(end, result); progress?.Report(100); return result;
    }, ct);

    public Task<EndInfo> DownloadAsync(string name, string directory, IProgress<int>? progress = null, CancellationToken ct = default) => RunAsync(async context =>
    {
        string target = SafeFiles.Target(directory, name);
        if (File.Exists(target)) throw new RemoteException(new Result(false, "Conflict", "本地文件已存在，拒绝覆盖", false));
        // Probe directory access before sending a request; the staging file is owned by this operation.
        string probe = Path.Combine(directory, ".sft-probe-" + Guid.NewGuid().ToString("N"));
        using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose)) { }
        uint id = Next(); context.StartRequest();
        await wire!.SendJsonAsync(MessageType.DownloadRequest, id, new FileMeta(name, 0), context.Token);
        var meta = (await ExpectAsync(id, MessageType.TransferMeta, context.Token)).Json<FileMeta>();
        if (meta.Name != name) throw new ProtocolException("文件名不匹配");
        using var receiver = new FileReceiver(target, meta.Length);
        await wire.SendJsonAsync(MessageType.Ready, id, new Result(true, "Ready", "准备接收", false), context.Token);
        while (true)
        {
            var f = await wire.ReadAsync(context.Token, (t, r) => r == id && t is MessageType.Data or MessageType.TransferEnd or MessageType.Error);
            if (f.Type == MessageType.Error) ThrowRemote(f);
            if (f.Type == MessageType.Data)
            {
                await receiver.AppendAsync(f.Payload, context.Token);
                progress?.Report((int)(receiver.Received * 100 / Math.Max(1, meta.Length))); continue;
            }
            var end = await receiver.CommitAsync(f.Json<EndInfo>(), context.Token);
            await wire.SendJsonAsync(MessageType.TransferResult, id, end, context.Token);
            await ExpectAsync(id, MessageType.Ready, context.Token);
            progress?.Report(100); return end;
        }
    }, ct);
    private static void ValidateEnd(EndInfo expected, EndInfo actual)
    {
        if (expected.Length != actual.Length || !SafeFiles.HashEquals(expected.Sha256, actual.Sha256))
            throw new ProtocolException("提交确认与完整文件摘要不匹配");
    }
    private void Notify(string text) => Status?.Invoke(text);
    private async Task HeartbeatAsync()
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
            while (await timer.WaitForNextTickAsync(lifetime.Token))
            {
                if (!await operation.WaitAsync(0, lifetime.Token)) continue;
                try
                {
                    uint id = Next(); await wire!.SendAsync(MessageType.Ping, id, ct: lifetime.Token);
                    await ExpectAsync(id, MessageType.Pong, lifetime.Token);
                    var session = Session;
                    if (session is not null && Connected) Notify($"心跳 #{++Heartbeats} / {session.ConnectionId}");
                }
                finally { operation.Release(); }
            }
        }
        catch (Exception ex)
        {
            bool report = Connected; Abort();
            if (report) Notify("连接失效：" + ex.Message);
        }
    }
    public void Abort()
    {
        lock (lifecycle)
        {
            if (Interlocked.Exchange(ref stopped, 1) != 0) return;
            Session = null;
            lifetime.Cancel(); tcp.Dispose();
        }
        ConnectionChanged?.Invoke();
    }
    public ValueTask DisposeAsync()
    {
        lock (lifecycle) return new ValueTask(disposal ??= DisposeCore());
    }
    private async Task DisposeCore()
    {
        // Cancellation closes only this session; wait for owners before disposing the wire gate.
        Abort();
        if (connecting is not null) { try { await connecting; } catch { /* Observed by ConnectAsync caller. */ } }
        if (heartbeat is not null) await heartbeat;
        await operation.WaitAsync();
        try { tls?.Dispose(); wire?.Dispose(); }
        finally { operation.Release(); }
        // CTS and gate remain valid for late canceled callers; no socket or file handle remains.
    }
}
