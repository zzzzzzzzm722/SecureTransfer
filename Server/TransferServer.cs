using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureTransfer.Protocol;
namespace SecureTransfer.Server;
public sealed record ServerOptions
{
    public string Address { get; init; } = "127.0.0.1";
    public int Port { get; init; } = 7443;
    public string Root { get; init; } = ".local/data";
    public string Database { get; init; } = ".local/accounts.db";
    public string Certificate { get; init; } = ".local/certs/server.pfx";
    public string Ca { get; init; } = ".local/certs/ca.cer";
    public bool MutualTls
    {
        get; init;
    }
    public int MaxConnections { get; init; } = 32;
    public int MaxPerIp { get; init; } = 8;
    public int FailuresPerMinute { get; init; } = 5;
    public int ConnectionsPerMinute { get; init; } = 60;
    public int HandshakeSeconds { get; init; } = 8;
    public int LoginSeconds { get; init; } = 15;
    public int IoSeconds { get; init; } = 30;
}
public sealed class TransferServer : IAsyncDisposable
{
    private sealed class Peer
    {
        public int Active, Attempts, Failures; public DateTime Window = DateTime.UtcNow;
    }
    private readonly ServerOptions options;
    private readonly Accounts accounts;
    private readonly X509Certificate2 certificate, ca;
    private readonly TcpListener listener;
    private readonly CancellationTokenSource stop = new();
    private readonly object admission = new();
    private readonly Dictionary<string, Peer> peers = [];
    private readonly ConcurrentDictionary<long, Task> tasks = new();
    private readonly ConcurrentDictionary<string, byte> writers = new(StringComparer.OrdinalIgnoreCase);
    private Task? acceptTask;
    private int active;
    private long sequence;
    public Action<string>? Log { get; set; } = Console.WriteLine;
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    public int ActiveConnections
    {
        get
        {
            lock (admission)
                return active;
        }
    }
    public TransferServer(ServerOptions options, string password)
    {
        this.options = options;
        SafeFiles.NoReparse(options.Root);
        Directory.CreateDirectory(options.Root);
        // Reclaim only our own staging names before accepting connections.
        foreach (string dir in Directory.EnumerateDirectories(options.Root))
        {
            SafeFiles.NoReparse(dir);
            foreach (string part in Directory.EnumerateFiles(dir, ".sft-*.part"))
            {
                SafeFiles.NoReparse(part);
                File.Delete(part);
            }
        }
        accounts = new Accounts(options.Database, readOnly: true);
        certificate = X509CertificateLoader.LoadPkcs12FromFile(options.Certificate, password, X509KeyStorageFlags.DefaultKeySet);
        ca = X509CertificateLoader.LoadCertificateFromFile(options.Ca);
        listener = new TcpListener(IPAddress.Parse(options.Address), options.Port);
    }
    public void Start()
    {
        listener.Start(options.MaxConnections);
        acceptTask = AcceptAsync();
        Log?.Invoke($"LISTEN {options.Address}:{Port} mTLS={options.MutualTls}");
    }
    private bool Admit(string ip)
    {
        lock (admission)
        {
            foreach (var key in peers.Where(p => p.Value.Active == 0 && DateTime.UtcNow - p.Value.Window > TimeSpan.FromMinutes(1)).Select(p => p.Key).ToArray())
                peers.Remove(key);
            if (!peers.TryGetValue(ip, out var peer))
            {
                if (peers.Count >= 4096)
                    return false;
                peers[ip] = peer = new Peer();
            }
            if (DateTime.UtcNow - peer.Window > TimeSpan.FromMinutes(1))
            {
                peer.Window = DateTime.UtcNow;
                peer.Failures = peer.Attempts = 0;
            }
            if (active >= options.MaxConnections || peer.Active >= options.MaxPerIp || peer.Failures >= options.FailuresPerMinute || peer.Attempts >= options.ConnectionsPerMinute)
                return false;
            peer.Attempts++;
            peer.Active++;
            active++;
            return true;
        }
    }
    private async Task AcceptAsync()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(stop.Token);
                string ip = ((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString();
                if (!Admit(ip))
                {
                    Log?.Invoke($"LIMIT {ip}");
                    client.Dispose();
                    continue;
                }
                long n = Interlocked.Increment(ref sequence);
                var task = Task.Run(async () => { try { await SessionAsync(client, ip); } finally { lock (admission) { active--; peers[ip].Active--; } client.Dispose(); } }, CancellationToken.None);
                tasks[n] = task;
                _ = task.ContinueWith(completed => { tasks.TryRemove(n, out _); }, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) { }
        catch (SocketException) when (stop.IsCancellationRequested) { }
    }
    private async Task SessionAsync(TcpClient client, string ip)
    {
        string connectionId = Guid.NewGuid().ToString("N")[..12];
        uint current = 1;
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        using var tls = new SslStream(client.GetStream(), false);
        using var wire = new Wire(tls, options.IoSeconds);
        bool authenticated = false;
        try
        {
            using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
            {
                handshake.CancelAfter(TimeSpan.FromSeconds(options.HandshakeSeconds));
                var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
                policy.CustomTrustStore.Add(ca);
                policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    ClientCertificateRequired = options.MutualTls,
                    CertificateChainPolicy = policy,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }, handshake.Token);
                if (options.MutualTls && tls.RemoteCertificate is null)
                    throw new AuthenticationException("缺少客户端证书");
            }
            Log?.Invoke($"OPEN {connectionId} {ip} {tls.SslProtocol}");
            Frame login;
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
            {
                deadline.CancelAfter(TimeSpan.FromSeconds(options.LoginSeconds));
                login = await wire.ReadAsync(deadline.Token, (t, r) => t == MessageType.Login);
            }
            current = login.RequestId;
            var credentials = login.Json<Login>();
            string? certHash = tls.RemoteCertificate?.GetCertHashString(HashAlgorithmName.SHA256);
            var account = accounts.Verify(credentials.User, credentials.Password, certHash, options.MutualTls);
            if (account is null)
            {
                lock (admission)
                    peers[ip].Failures++;
                await Error(wire, current, "Authentication", "账号、口令或绑定证书不匹配");
                return;
            }
            authenticated = true;
            string directory = Path.Combine(Path.GetFullPath(options.Root), account.Id);
            SafeFiles.NoReparse(directory);
            Directory.CreateDirectory(directory);
            await wire.SendJsonAsync(MessageType.LoginResult, current, new LoginResult(connectionId, account.Name, tls.SslProtocol.ToString()), stop.Token);
            uint last = current;
            while (!stop.IsCancellationRequested)
            {
                var f = await wire.ReadAsync(stop.Token, (t, r) => r > last && t is MessageType.List or MessageType.UploadBegin or MessageType.DownloadRequest or MessageType.Ping or MessageType.Disconnect);
                last = current = f.RequestId;
                Log?.Invoke($"REQUEST {connectionId} {account.Name} id={current} {f.Type}");
                switch (f.Type)
                {
                    case MessageType.Disconnect:
                        return;
                    case MessageType.Ping:
                        await wire.SendAsync(MessageType.Pong, current, ct: stop.Token);
                        break;
                    case MessageType.List:
                        var files = Directory.EnumerateFiles(directory).Where(p => !Path.GetFileName(p).StartsWith('.')).Select(p =>
                        {
                            SafeFiles.NoReparse(p);
                            return new FileMeta(Path.GetFileName(p), new FileInfo(p).Length);
                        }).Take(17).ToArray();
                        if (files.Length > 16)
                        {
                            await Error(wire, current, "Quota", "文件数超过目录上限");
                            break;
                        }
                        await wire.SendJsonAsync(MessageType.ListResult, current, new FileList(files), stop.Token);
                        break;
                    case MessageType.UploadBegin:
                        await Upload(wire, f, directory);
                        break;
                    case MessageType.DownloadRequest:
                        await Download(wire, f, directory);
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException or OperationCanceledException or JsonException or ArgumentException or UnauthorizedAccessException)
        {
            if (ex is ProtocolException { RequestId: > 0 } protocolError)
                current = protocolError.RequestId.Value;
            Log?.Invoke($"CLOSE {connectionId} {ex.GetType().Name}: {ex.Message}");
            if (!authenticated && ex is AuthenticationException)
            {
                lock (admission)
                    peers[ip].Failures++;
            }
            try
            {
                if (tls.IsAuthenticated)
                    await Error(wire, current, "Protocol", "协议、权限或连接错误，会话关闭");
            }
            catch (Exception sendEx) when (sendEx is IOException or OperationCanceledException or ObjectDisposedException) { }
        }
        finally { Log?.Invoke($"END {connectionId}"); }
    }
    private Task Error(Wire wire, uint id, string code, string message) => wire.SendJsonAsync(MessageType.Error, id, new Result(false, code, message), stop.Token);
    private async Task Upload(Wire wire, Frame f, string directory)
    {
        var meta = f.Json<FileMeta>();
        string target = SafeFiles.Target(directory, meta.Name);
        if (meta.Length < 0 || meta.Length > SafeFiles.MaxFileSize)
        {
            await Error(wire, f.RequestId, "Size", "文件大小超限");
            return;
        }
        if (File.Exists(target) || !writers.TryAdd(target, 0))
        {
            await Error(wire, f.RequestId, "Conflict", "同名目标已存在或正在上传");
            return;
        }
        try
        {
            // Count + creation are atomic across sessions. 16 * 256 MiB bounds each account.
            FileReceiver? staging;
            lock (admission)
                staging = Directory.EnumerateFiles(directory).Count() >= 16 ? null : new FileReceiver(target, meta.Length);
            if (staging is null)
            {
                await Error(wire, f.RequestId, "Quota", "最多 16 个文件（含临时文件）");
                return;
            }
            using var receiver = staging;
            await wire.SendJsonAsync(MessageType.Ready, f.RequestId, new Result(true, "Ready", "开始上传"), stop.Token);
            while (true)
            {
                var next = await wire.ReadAsync(stop.Token, (t, r) => r == f.RequestId && t is MessageType.Data or MessageType.TransferEnd);
                if (next.Type == MessageType.Data)
                {
                    await receiver.AppendAsync(next.Payload, stop.Token);
                    continue;
                }
                try
                {
                    var end = await receiver.CommitAsync(next.Json<EndInfo>(), stop.Token);
                    await wire.SendJsonAsync(MessageType.TransferResult, f.RequestId, end, stop.Token);
                    Log?.Invoke($"COMMIT upload id={f.RequestId} bytes={end.Length} sha256={end.Sha256}");
                }
                catch (ProtocolException) { await Error(wire, f.RequestId, "Integrity", "长度或 SHA-256 不匹配，已取消提交"); }
                return;
            }
        }
        finally { writers.TryRemove(target, out _); }
    }
    private async Task Download(Wire wire, Frame f, string directory)
    {
        string name = f.Json<FileMeta>().Name;
        string target = SafeFiles.Target(directory, name);
        if (!File.Exists(target))
        {
            await Error(wire, f.RequestId, "NotFound", "当前账号无此文件");
            return;
        }
        await using var input = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read, Wire.ChunkSize, FileOptions.Asynchronous);
        if (input.Length > SafeFiles.MaxFileSize)
        {
            await Error(wire, f.RequestId, "Size", "文件大小超限");
            return;
        }
        await wire.SendJsonAsync(MessageType.TransferMeta, f.RequestId, new FileMeta(name, input.Length), stop.Token);
        await wire.ReadAsync(stop.Token, (t, r) => r == f.RequestId && t == MessageType.Ready);
        byte[] buffer = new byte[Wire.ChunkSize];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long sent = 0;
        int count;
        while ((count = await input.ReadAsync(buffer, stop.Token)) != 0)
        {
            hash.AppendData(buffer, 0, count);
            sent += count;
            await wire.SendAsync(MessageType.Data, f.RequestId, buffer.AsMemory(0, count), stop.Token);
        }
        var end = new EndInfo(sent, Convert.ToHexString(hash.GetHashAndReset()));
        await wire.SendJsonAsync(MessageType.TransferEnd, f.RequestId, end, stop.Token);
        var ack = (await wire.ReadAsync(stop.Token, (t, r) => r == f.RequestId && t == MessageType.TransferResult)).Json<EndInfo>();
        if (ack.Length != end.Length || !SafeFiles.HashEquals(end.Sha256, ack.Sha256))
            throw new ProtocolException("接收确认错误");
        await wire.SendJsonAsync(MessageType.Ready, f.RequestId, new Result(true, "Idle", "提交确认已收到"), stop.Token);
        Log?.Invoke($"COMMIT download id={f.RequestId} bytes={end.Length} sha256={end.Sha256}");
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        listener.Stop();
        if (acceptTask is not null)
            await acceptTask;
        await Task.WhenAll(tasks.Values);
        certificate.Dispose();
        ca.Dispose();
        stop.Dispose();
    }
}
