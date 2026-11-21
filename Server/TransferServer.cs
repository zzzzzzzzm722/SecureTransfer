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
    public int MaxPerUserConnections { get; init; } = 4;
    public int RequestsPerMinute { get; init; } = 180;
    public UserRate DefaultRate { get; init; } = new();
    public Dictionary<string, UserRate> UserRates { get; init; } = [];
    public double ProgressGraceSeconds { get; init; } = 5;
    public double ProgressWindowSeconds { get; init; } = 5;
    public int MinTransferBytesPerSecond { get; init; } = 256;
    public int MaxTransferSeconds { get; init; } = 86400;
    public double ResumeRetentionSeconds { get; init; } = 86400;
    public int MaxResumeStates { get; init; } = 32;
    public string LogDirectory { get; init; } = ".local/logs";
    public long LogFileBytes { get; init; } = 2097152;
    public int LogArchives { get; init; } = 3;
}
public sealed partial class TransferServer : IAsyncDisposable
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
    private readonly Dictionary<string, UserRuntime> users = [];
    private readonly ConcurrentDictionary<string, byte> activeResumes = new(StringComparer.OrdinalIgnoreCase);
    private long logWindow = Environment.TickCount64;
    private int logCount;
    private Task? acceptTask, maintenanceTask;
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
        if (options.MaxPerUserConnections < 1 || options.MaxConnections < 1 || options.ProgressWindowSeconds <= 0 || options.ProgressGraceSeconds < 0 || options.MinTransferBytesPerSecond < 1 || options.ResumeRetentionSeconds <= 0)
            throw new ArgumentException("资源控制配置无效");
        foreach (var rate in options.UserRates.Values.Append(options.DefaultRate))
            if (rate.UploadBytesPerSecond < 1024 || rate.DownloadBytesPerSecond < 1024) throw new ArgumentException("带宽下限为 1024 字节/秒");
        SafeFiles.NoReparse(options.Root);
        Directory.CreateDirectory(options.Root);
        // Persistent resume state is validated/reclaimed by age, never unconditionally deleted at startup.
        accounts = new Accounts(options.Database, readOnly: true);
        certificate = X509CertificateLoader.LoadPkcs12FromFile(options.Certificate, password, X509KeyStorageFlags.DefaultKeySet);
        ca = X509CertificateLoader.LoadCertificateFromFile(options.Ca);
        listener = new TcpListener(IPAddress.Parse(options.Address), options.Port);
    }
    public void Start()
    {
        listener.Start(options.MaxConnections);
        acceptTask = AcceptAsync();
        maintenanceTask = MaintainAsync();
        Emit($"LISTEN {options.Address}:{Port} mTLS={options.MutualTls}");
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
                    Emit($"LIMIT {ip}");
                    client.Dispose();
                    continue;
                }
                long n = Interlocked.Increment(ref sequence);
                var task = Task.Run(async () => { try { await SessionAsync(client, ip); } finally { lock (admission) { active--; peers[ip].Active--; } client.Dispose(); } }, CancellationToken.None);
                tasks[n] = task;
                _ = task.ContinueWith(completed => { _ = completed.Exception; tasks.TryRemove(n, out _); }, TaskScheduler.Default);
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
        UserRuntime? user = null;
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
            Emit($"OPEN {connectionId} {ip} {tls.SslProtocol}");
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
                await Error(wire, current, "Authentication", "账号、口令或绑定证书不匹配", true);
                return;
            }
            lock (admission)
            {
                if (!users.TryGetValue(account.Id, out var runtime))
                    users[account.Id] = runtime = new UserRuntime(options.UserRates.GetValueOrDefault(account.Name, options.DefaultRate));
                int limit = Math.Min(options.MaxPerUserConnections, Math.Max(1, options.MaxConnections / 2));
                if (runtime.Connections < limit) { runtime.Connections++; user = runtime; }
            }
            if (user is null) { await Error(wire, current, "UserLimit", "账号连接配额已用尽", true); return; }
            authenticated = true;
            string directory = Path.Combine(Path.GetFullPath(options.Root), account.Id);
            SafeFiles.NoReparse(directory);
            Directory.CreateDirectory(directory);
            CleanupResumes(directory);
            await wire.SendJsonAsync(MessageType.LoginResult, current, new LoginResult(connectionId, account.Name, tls.SslProtocol.ToString()), stop.Token);
            uint last = current;
            while (!stop.IsCancellationRequested)
            {
                var f = await wire.ReadAsync(stop.Token, (t, r) => r > last && t is MessageType.List or MessageType.UploadBegin or MessageType.DownloadRequest or MessageType.ResumeUpload or MessageType.ResumeDownload or MessageType.Ping or MessageType.Disconnect);
                last = current = f.RequestId;
                if (f.Type is not (MessageType.Ping or MessageType.Disconnect) && !AllowRequest(user))
                { await Error(wire, current, "RequestLimit", "账号业务请求频率超限", true); return; }
                if (f.Type != MessageType.Ping) Emit($"REQUEST {connectionId} {account.Name} id={current} {f.Type}");
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
                        await Upload(wire, f, directory, user);
                        break;
                    case MessageType.DownloadRequest:
                        await Download(wire, f, directory, user);
                        break;
                    case MessageType.ResumeUpload:
                        await ResumeUpload(wire, f, directory, account.Id, user);
                        break;
                    case MessageType.ResumeDownload:
                        await ResumeDownload(wire, f, directory, account.Id, user);
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException or OperationCanceledException or JsonException or ArgumentException or UnauthorizedAccessException)
        {
            if (ex is ProtocolException { RequestId: > 0 } protocolError)
                current = protocolError.RequestId.Value;
            Emit($"CLOSE {connectionId} {ex.GetType().Name}: {ex.Message} | {ex.StackTrace}");
            if (!authenticated && ex is AuthenticationException)
            {
                lock (admission)
                    peers[ip].Failures++;
            }
            try
            {
                if (tls.IsAuthenticated)
                    await Error(wire, current, "Protocol", "协议、权限、进展或连接错误，会话关闭", true);
            }
            catch (Exception sendEx) when (sendEx is IOException or OperationCanceledException or ObjectDisposedException) { }
        }
        finally { if (user is not null) { lock (admission) user.Connections--; } Emit($"END {connectionId}"); }
    }
    private Task Error(Wire wire, uint id, string code, string message, bool fatal = false) => wire.SendJsonAsync(MessageType.Error, id, new Result(false, code, message, fatal), stop.Token);
    private async Task Upload(Wire wire, Frame f, string directory, UserRuntime user)
    {
        var meta = f.Json<FileMeta>();
        string target = SafeFiles.Target(directory, meta.Name);
        if (meta.Length < 0 || meta.Length > SafeFiles.MaxFileSize)
        {
            await Error(wire, f.RequestId, "Size", "文件大小超限");
            return;
        }
        if (File.Exists(target) || HasPendingUpload(directory, meta.Name) || !writers.TryAdd(target, 0))
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
            await using var guard = new ProgressGuard(options, meta.Length, user.Upload.Rate, stop.Token);
            await wire.SendJsonAsync(MessageType.Ready, f.RequestId, new Result(true, "Ready", "开始上传"), stop.Token);
            while (true)
            {
                var next = await wire.ReadAsync(guard.Token, (t, r) => r == f.RequestId && t is MessageType.Data or MessageType.TransferEnd);
                if (next.Type == MessageType.Data)
                {
                    await guard.Throttle(user.Upload, next.Payload.Length);
                    await receiver.AppendAsync(next.Payload, guard.Token);
                    guard.Advance(next.Payload.Length);
                    continue;
                }
                try
                {
                    var end = await receiver.CommitAsync(next.Json<EndInfo>(), stop.Token);
                    await wire.SendJsonAsync(MessageType.TransferResult, f.RequestId, end, stop.Token);
                    Emit($"COMMIT upload id={f.RequestId} bytes={end.Length} sha256={end.Sha256}");
                }
                catch (ProtocolException) { await Error(wire, f.RequestId, "Integrity", "长度或 SHA-256 不匹配，已取消提交"); }
                return;
            }
        }
        finally { writers.TryRemove(target, out _); }
    }
    private async Task Download(Wire wire, Frame f, string directory, UserRuntime user)
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
        await using var guard = new ProgressGuard(options, input.Length, user.Download.Rate, stop.Token);
        byte[] buffer = new byte[Wire.ChunkSize];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long sent = 0;
        int count;
        while ((count = await input.ReadAsync(buffer, stop.Token)) != 0)
        {
            hash.AppendData(buffer, 0, count);
            sent += count;
            await guard.Throttle(user.Download, count);
            await wire.SendAsync(MessageType.Data, f.RequestId, buffer.AsMemory(0, count), guard.Token);
            guard.Advance(count);
        }
        var end = new EndInfo(sent, Convert.ToHexString(hash.GetHashAndReset()));
        await wire.SendJsonAsync(MessageType.TransferEnd, f.RequestId, end, stop.Token);
        var ack = (await wire.ReadAsync(guard.Token, (t, r) => r == f.RequestId && t == MessageType.TransferResult)).Json<EndInfo>();
        if (ack.Length != end.Length || !SafeFiles.HashEquals(end.Sha256, ack.Sha256))
            throw new ProtocolException("接收确认错误");
        await wire.SendJsonAsync(MessageType.Ready, f.RequestId, new Result(true, "Idle", "提交确认已收到"), stop.Token);
        Emit($"COMMIT download id={f.RequestId} bytes={end.Length} sha256={end.Sha256}");
    }
    private bool AllowRequest(UserRuntime user)
    {
        lock (admission)
        {
            if (Environment.TickCount64 - user.Window > 60000) { user.Window = Environment.TickCount64; user.Requests = 0; }
            return ++user.Requests <= options.RequestsPerMinute;
        }
    }
    private void Emit(string message)
    {
        lock (admission)
        {
            if (Environment.TickCount64 - logWindow > 60000) { logWindow = Environment.TickCount64; logCount = 0; }
            if (++logCount <= 600) Log?.Invoke(message);
        }
    }
    private async Task MaintainAsync()
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Clamp(options.ResumeRetentionSeconds / 4, 1, 60)));
            while (await timer.WaitForNextTickAsync(stop.Token))
                foreach (var directory in Directory.EnumerateDirectories(options.Root))
                    try { SafeFiles.NoReparse(directory); CleanupResumes(directory); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Emit("RECLAIM " + ex.GetType().Name); }
        }
        catch (OperationCanceledException) { }
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        listener.Stop();
        if (acceptTask is not null)
            await acceptTask;
        if (maintenanceTask is not null) await maintenanceTask;
        await Task.WhenAll(tasks.Values);
        certificate.Dispose();
        ca.Dispose();
        stop.Dispose();
    }
}
