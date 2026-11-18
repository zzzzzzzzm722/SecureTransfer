using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecureTransfer.Protocol;
public sealed class TransferClient : IAsyncDisposable
{
    private readonly TcpClient tcp = new();
    private readonly SemaphoreSlim operation = new(1, 1);
    private readonly CancellationTokenSource lifetime = new();
    private SslStream? tls;
    private Wire? wire;
    private Task? heartbeat;
    private uint requestId;
    public LoginResult? Session
    {
        get; private set;
    }
    public event Action<string>? Status;
    public bool Connected => Session is not null && !lifetime.IsCancellationRequested;
    public int Heartbeats
    {
        get; private set;
    }
    private uint Next() => checked(++requestId);
    public async Task ConnectAsync(string host, int port, string caPath, string user, string password, string? clientPfx = null, string? pfxPassword = null, string? targetHost = null)
    {
        try
        {
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await tcp.ConnectAsync(host, port, deadline.Token);
            tls = new SslStream(tcp.GetStream(), false);
            using var ca = X509CertificateLoader.LoadCertificateFromFile(caPath);
            var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
            policy.CustomTrustStore.Add(ca);
            policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            using var certificate = clientPfx is null ? null : X509CertificateLoader.LoadPkcs12FromFile(clientPfx, pfxPassword, X509KeyStorageFlags.DefaultKeySet);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = targetHost ?? host,
                CertificateChainPolicy = policy,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificates = certificate is null ? null : new X509CertificateCollection { certificate }
            }, deadline.Token);
            wire = new Wire(tls);
            uint id = Next();
            await wire.SendJsonAsync(MessageType.Login, id, new Login(user, password), deadline.Token);
            Session = (await ExpectAsync(id, MessageType.LoginResult)).Json<LoginResult>();
            Status?.Invoke($"已连接 {Session.ConnectionId} / {Session.Tls}");
            heartbeat = HeartbeatAsync();
        }
        catch { Abort(); throw; }
    }
    private async Task<Frame> ExpectAsync(uint id, MessageType type)
    {
        var f = await wire!.ReadAsync(lifetime.Token, (t, r) => r == id && (t == type || t == MessageType.Error));
        if (f.Type == MessageType.Error)
            throw new RemoteException(f.Json<Result>());
        return f;
    }
    private async Task<T> RunAsync<T>(Func<Task<T>> action)
    {
        await operation.WaitAsync(lifetime.Token);
        try
        {
            if (!Connected)
                throw new IOException("尚未连接");
            return await action();
        }
        catch (RemoteException) { throw; }
        catch { Abort(); throw; }
        finally { operation.Release(); }
    }
    public Task<FileMeta[]> ListAsync() => RunAsync(async () =>
    {
        uint id = Next();
        await wire!.SendAsync(MessageType.List, id, ct: lifetime.Token);
        return (await ExpectAsync(id, MessageType.ListResult)).Json<FileList>().Files;
    });
    public Task<EndInfo> UploadAsync(string local, IProgress<int>? progress = null) => RunAsync(async () =>
    {
        string name = Path.GetFileName(local);
        SafeFiles.ValidateName(name);
        await using var input = new FileStream(local, FileMode.Open, FileAccess.Read, FileShare.Read, Wire.ChunkSize, FileOptions.Asynchronous);
        if (input.Length > SafeFiles.MaxFileSize)
            throw new ProtocolException("文件超限");
        uint id = Next();
        await wire!.SendJsonAsync(MessageType.UploadBegin, id, new FileMeta(name, input.Length), lifetime.Token);
        await ExpectAsync(id, MessageType.Ready);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[Wire.ChunkSize];
        long sent = 0;
        int count;
        while ((count = await input.ReadAsync(buffer, lifetime.Token)) != 0)
        {
            hash.AppendData(buffer, 0, count);
            sent += count;
            await wire.SendAsync(MessageType.Data, id, buffer.AsMemory(0, count), lifetime.Token);
            progress?.Report((int)(sent * 100 / Math.Max(1, input.Length)));
        }
        var end = new EndInfo(sent, Convert.ToHexString(hash.GetHashAndReset()));
        await wire.SendJsonAsync(MessageType.TransferEnd, id, end, lifetime.Token);
        var result = (await ExpectAsync(id, MessageType.TransferResult)).Json<EndInfo>();
        if (result.Length != end.Length || !SafeFiles.HashEquals(end.Sha256, result.Sha256))
            throw new ProtocolException("服务端确认不匹配");
        progress?.Report(100);
        return result;
    });
    public Task<EndInfo> DownloadAsync(string name, string directory, IProgress<int>? progress = null) => RunAsync(async () =>
    {
        string target = SafeFiles.Target(directory, name);
        if (File.Exists(target))
            throw new RemoteException(new Result(false, "Conflict", "本地文件已存在，拒绝覆盖"));
        uint id = Next();
        await wire!.SendJsonAsync(MessageType.DownloadRequest, id, new FileMeta(name, 0), lifetime.Token);
        var meta = (await ExpectAsync(id, MessageType.TransferMeta)).Json<FileMeta>();
        if (meta.Name != name)
            throw new ProtocolException("文件名不匹配");
        using var receiver = new FileReceiver(target, meta.Length);
        await wire.SendJsonAsync(MessageType.Ready, id, new Result(true, "Ready", "准备接收"), lifetime.Token);
        while (true)
        {
            var f = await wire.ReadAsync(lifetime.Token, (t, r) => r == id && t is MessageType.Data or MessageType.TransferEnd or MessageType.Error);
            if (f.Type == MessageType.Error)
                throw new RemoteException(f.Json<Result>());
            if (f.Type == MessageType.Data)
            {
                await receiver.AppendAsync(f.Payload, lifetime.Token);
                progress?.Report((int)(receiver.Received * 100 / Math.Max(1, meta.Length)));
                continue;
            }
            var end = await receiver.CommitAsync(f.Json<EndInfo>(), lifetime.Token);
            await wire.SendJsonAsync(MessageType.TransferResult, id, end, lifetime.Token);
            await ExpectAsync(id, MessageType.Ready); // server has returned to idle
            progress?.Report(100);
            return end;
        }
    });
    private async Task HeartbeatAsync()
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
            while (await timer.WaitForNextTickAsync(lifetime.Token))
            {
                if (!await operation.WaitAsync(0, lifetime.Token))
                    continue;
                try
                {
                    uint id = Next();
                    await wire!.SendAsync(MessageType.Ping, id, ct: lifetime.Token);
                    await ExpectAsync(id, MessageType.Pong);
                    Heartbeats++;
                    Status?.Invoke($"心跳 #{Heartbeats} / {Session!.ConnectionId}");
                }
                finally { operation.Release(); }
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or RemoteException or ObjectDisposedException)
        {
            if (!lifetime.IsCancellationRequested)
                Status?.Invoke("连接失效：" + ex.Message);
            Abort();
        }
    }
    public void Abort()
    {
        lifetime.Cancel();
        tcp.Dispose();
        Session = null;
    }
    public async ValueTask DisposeAsync()
    {
        if (Connected && await operation.WaitAsync(0))
        {
            try
            {
                await wire!.SendAsync(MessageType.Disconnect, Next());
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException) { }
            finally { operation.Release(); }
        }
        Abort();
        if (heartbeat is not null)
            await heartbeat;
        tls?.Dispose();
        wire?.Dispose();
    }
}
