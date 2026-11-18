using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureTransfer.Protocol;
using SecureTransfer.Server;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]
namespace SecureTransfer.Tests;
public sealed class Lab : IAsyncLifetime
{
    public string Root { get; } = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../.local/tests-" + Guid.NewGuid().ToString("N")));
    public string Certs => Path.Combine(Root, "certs");
    public string Password { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
    public string Db => Path.Combine(Root, "accounts.db");
    public TransferServer Server { get; private set; } = null!;
    public ServerOptions Options => new() { Port = 0, Root = Path.Combine(Root, "data"), Database = Db, Certificate = Path.Combine(Certs, "server.pfx"), Ca = Path.Combine(Certs, "ca.cer"), MaxPerIp = 12, ConnectionsPerMinute = 200, FailuresPerMinute = 100 };
    public Task InitializeAsync()
    {
        Certificates.CreateLab(Certs, Password);
        var accounts = new Accounts(Db);
        foreach (var user in new[] { "alice", "bob" })
        {
            using var cert = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(Certs, user + ".cer"));
            accounts.Add(user, Password, cert.GetCertHashString(HashAlgorithmName.SHA256));
        }
        Directory.CreateDirectory(Path.Combine(Root, "downloads"));
        Server = new TransferServer(Options, Password);
        Server.Log = Log;
        Server.Start();
        return Task.CompletedTask;
    }
    public void Log(string message)
    {
        lock (this)
            File.AppendAllText(Path.Combine(Root, "server.log"), $"{DateTimeOffset.Now:O} {message}\n");
    }
    public async Task<TransferClient> Client(string name = "alice", int? port = null, string? certificate = null)
    {
        var c = new TransferClient();
        try
        {
            await c.ConnectAsync("localhost", port ?? Server.Port, Path.Combine(Certs, "ca.cer"), name, Password, certificate, Password);
            return c;
        }
        catch { await c.DisposeAsync(); throw; }
    }
    public async Task<Raw> Raw(int? port = null)
    {
        var r = new Raw();
        await r.Connect(port ?? Server.Port, Path.Combine(Certs, "ca.cer"));
        return r;
    }
    public async Task DisposeAsync()
    {
        await Server.DisposeAsync();
    }
}
public sealed class Raw : IDisposable
{
    public TcpClient Tcp { get; } = new();
    public SslStream Tls { get; private set; } = null!;
    public Wire Wire { get; private set; } = null!;
    public async Task Connect(int port, string caPath)
    {
        await Tcp.ConnectAsync("localhost", port);
        Tls = new SslStream(Tcp.GetStream(), false);
        using var ca = X509CertificateLoader.LoadCertificateFromFile(caPath);
        var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
        policy.CustomTrustStore.Add(ca);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "localhost", CertificateChainPolicy = policy }, timeout.Token);
        Wire = new Wire(Tls, 5);
    }
    public async Task Login(Lab lab)
    {
        await Wire.SendJsonAsync(MessageType.Login, 1, new Login("alice", lab.Password));
        Assert.Equal(MessageType.LoginResult, (await Wire.ReadAsync()).Type);
    }
    public void Dispose()
    {
        Tls?.Dispose();
        Tcp.Dispose();
        Wire?.Dispose();
    }
}
public sealed class IntegrationTests(Lab lab) : IClassFixture<Lab>
{
    [Fact]
    public async Task TwoUsersConcurrentBinaryEmptyRoundTripsAndHeartbeat()
    {
        string sourceDir = Path.Combine(lab.Root, "source");
        Directory.CreateDirectory(sourceDir);
        string binary = Path.Combine(sourceDir, "binary.dat"), empty = Path.Combine(sourceDir, "empty.dat");
        await File.WriteAllBytesAsync(binary, RandomNumberGenerator.GetBytes(2 * 1024 * 1024 + 137));
        await File.WriteAllBytesAsync(empty, []);
        await using var alice = await lab.Client();
        await using var bob = await lab.Client("bob");
        string aId = alice.Session!.ConnectionId, bId = bob.Session!.ConnectionId;
        Assert.NotEqual(aId, bId);
        var results = await Task.WhenAll(alice.UploadAsync(binary), bob.UploadAsync(binary));
        Assert.Equal(results[0], results[1]);
        await alice.UploadAsync(empty);
        string ad = Path.Combine(lab.Root, "downloads/alice"), bd = Path.Combine(lab.Root, "downloads/bob");
        Directory.CreateDirectory(ad);
        Directory.CreateDirectory(bd);
        await Task.WhenAll(alice.DownloadAsync("binary.dat", ad), bob.DownloadAsync("binary.dat", bd));
        await alice.DownloadAsync("empty.dat", ad);
        Assert.Equal(0, new FileInfo(Path.Combine(ad, "empty.dat")).Length);
        foreach (var path in new[] { Path.Combine(ad, "binary.dat"), Path.Combine(bd, "binary.dat") })
            Assert.Equal(SHA256.HashData(await File.ReadAllBytesAsync(binary)), SHA256.HashData(await File.ReadAllBytesAsync(path)));
        await Task.Delay(5600);
        Assert.True(alice.Heartbeats > 0);
        Assert.True(bob.Heartbeats > 0);
        Assert.Equal(aId, alice.Session!.ConnectionId);
        Assert.Equal(bId, bob.Session!.ConnectionId);
        Assert.Contains(await alice.ListAsync(), f => f.Name == "empty.dat");
        Assert.DoesNotContain(await bob.ListAsync(), f => f.Name == "empty.dat");
        Assert.Equal("NotFound", (await Assert.ThrowsAsync<RemoteException>(() => bob.DownloadAsync("empty.dat", bd))).Code);
        Assert.Equal("Conflict", (await Assert.ThrowsAsync<RemoteException>(() => alice.UploadAsync(binary))).Code);
        Assert.Equal("Conflict", (await Assert.ThrowsAsync<RemoteException>(() => alice.DownloadAsync("binary.dat", ad))).Code);
        lab.Log($"EVIDENCE two-users same-session alice={aId} bob={bId} sha256={results[0].Sha256} bytes={results[0].Length}");
    }
    [Fact]
    public async Task BadDigestRejectedAndSessionRemainsUsable()
    {
        using var raw = await lab.Raw();
        await raw.Login(lab);
        await raw.Wire.SendJsonAsync(MessageType.UploadBegin, 2, new FileMeta("bad-hash.bin", 3));
        Assert.Equal(MessageType.Ready, (await raw.Wire.ReadAsync()).Type);
        await raw.Wire.SendAsync(MessageType.Data, 2, new byte[] { 1, 2, 3 });
        await raw.Wire.SendJsonAsync(MessageType.TransferEnd, 2, new EndInfo(3, new string('0', 64)));
        Assert.Equal("Integrity", (await raw.Wire.ReadAsync()).Json<Result>().Code);
        await raw.Wire.SendAsync(MessageType.List, 3);
        var list = (await raw.Wire.ReadAsync()).Json<FileList>();
        Assert.DoesNotContain(list.Files, f => f.Name == "bad-hash.bin");
        Assert.Empty(Directory.GetFiles(lab.Options.Root, "*.part", SearchOption.AllDirectories));
    }
    [Fact]
    public async Task ShortTransferAndExcessDataRejected()
    {
        using (var raw = await lab.Raw())
        {
            await raw.Login(lab);
            await raw.Wire.SendJsonAsync(MessageType.UploadBegin, 2, new FileMeta("short.bin", 10));
            await raw.Wire.ReadAsync();
            await raw.Wire.SendJsonAsync(MessageType.TransferEnd, 2, new EndInfo(0, Convert.ToHexString(SHA256.HashData([]))));
            Assert.Equal("Integrity", (await raw.Wire.ReadAsync()).Json<Result>().Code);
        }
        using (var raw = await lab.Raw())
        {
            await raw.Login(lab);
            await raw.Wire.SendJsonAsync(MessageType.UploadBegin, 2, new FileMeta("long.bin", 1));
            await raw.Wire.ReadAsync();
            await raw.Wire.SendAsync(MessageType.Data, 2, new byte[] { 1, 2 });
            Assert.Equal(MessageType.Error, (await raw.Wire.ReadAsync()).Type);
        }
        await Task.Delay(150);
        Assert.Empty(Directory.GetFiles(lab.Options.Root, "*.part", SearchOption.AllDirectories));
    }
    [Fact]
    public async Task MidTransferDisconnectCleansStagingAndReleasesTarget()
    {
        using (var raw = await lab.Raw())
        {
            await raw.Login(lab);
            await raw.Wire.SendJsonAsync(MessageType.UploadBegin, 2, new FileMeta("interrupted.bin", 500));
            await raw.Wire.ReadAsync();
            await raw.Wire.SendAsync(MessageType.Data, 2, new byte[] { 1, 2, 3 });
        }
        await Task.Delay(250);
        Assert.Empty(Directory.GetFiles(lab.Options.Root, "*.part", SearchOption.AllDirectories));
        using var next = await lab.Raw();
        await next.Login(lab);
        await next.Wire.SendJsonAsync(MessageType.UploadBegin, 2, new FileMeta("interrupted.bin", 0));
        Assert.Equal(MessageType.Ready, (await next.Wire.ReadAsync()).Type);
    }
    [Fact]
    public async Task ConcurrentSameTargetHasSingleReservation()
    {
        using var first = await lab.Raw();
        using var second = await lab.Raw();
        await first.Login(lab);
        await second.Login(lab);
        await first.Wire.SendJsonAsync(MessageType.UploadBegin, 2, new FileMeta("race.bin", 100));
        Assert.Equal(MessageType.Ready, (await first.Wire.ReadAsync()).Type);
        await second.Wire.SendJsonAsync(MessageType.UploadBegin, 2, new FileMeta("race.bin", 100));
        Assert.Equal("Conflict", (await second.Wire.ReadAsync()).Json<Result>().Code);
    }
    [Fact]
    public async Task UnauthenticatedFileRequestRejected()
    {
        using var raw = await lab.Raw();
        await raw.Wire.SendAsync(MessageType.List, 77);
        var response = await raw.Wire.ReadAsync();
        Assert.Equal(MessageType.Error, response.Type);
        Assert.Equal(77u, response.RequestId);
    }
    [Theory]
    [InlineData("' OR 1=1 --")]
    [InlineData("alice'--")]
    [InlineData("alice")]
    public async Task SqlInjectionAndWrongPasswordCannotLogin(string user)
    {
        await using var client = new TransferClient();
        await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync("localhost", lab.Server.Port, Path.Combine(lab.Certs, "ca.cer"), user, "' OR 1=1 --"));
        Assert.False(client.Connected);
    }
    [Theory]
    [InlineData("wrong.invalid")]
    [InlineData("127.0.0.2")]
    public async Task WrongHostnameFailsTls(string target)
    {
        await using var c = new TransferClient();
        await Assert.ThrowsAnyAsync<Exception>(() => c.ConnectAsync("localhost", lab.Server.Port, Path.Combine(lab.Certs, "ca.cer"), "alice", lab.Password, targetHost: target));
        Assert.False(c.Connected);
    }
    [Fact]
    public async Task WrongCaFailsTls()
    {
        string other = Path.Combine(lab.Root, "other-ca");
        Certificates.CreateLab(other, lab.Password);
        await using var c = new TransferClient();
        await Assert.ThrowsAnyAsync<Exception>(() => c.ConnectAsync("localhost", lab.Server.Port, Path.Combine(other, "ca.cer"), "alice", lab.Password));
        Assert.False(c.Connected);
    }
    [Fact]
    public async Task MutualTlsRequiresTrustedCertificateAndAccountBinding()
    {
        await using var server = new TransferServer(lab.Options with { MutualTls = true }, lab.Password) { Log = lab.Log };
        server.Start();
        await using (var good = await lab.Client(port: server.Port, certificate: Path.Combine(lab.Certs, "alice.pfx")))
            Assert.NotNull(await good.ListAsync());
        await Assert.ThrowsAnyAsync<Exception>(() => lab.Client(port: server.Port));
        await Assert.ThrowsAnyAsync<Exception>(() => lab.Client(port: server.Port, certificate: Path.Combine(lab.Certs, "bob.pfx")));
        string other = Path.Combine(lab.Root, "mtls-wrong");
        Certificates.CreateLab(other, lab.Password);
        await Assert.ThrowsAnyAsync<Exception>(() => lab.Client(port: server.Port, certificate: Path.Combine(other, "alice.pfx")));
        lab.Log("EVIDENCE mTLS valid alice accepted; missing, wrong binding and wrong CA rejected");
    }
    [Fact]
    public async Task ConnectionLimitProtectsExistingSessionAndRecovers()
    {
        await using var server = new TransferServer(lab.Options with { MaxConnections = 2, MaxPerIp = 2, HandshakeSeconds = 1 }, lab.Password) { Log = lab.Log };
        server.Start();
        await using var good = await lab.Client(port: server.Port);
        using var held = new TcpClient();
        await held.ConnectAsync("localhost", server.Port);
        await Task.Delay(100);
        await Assert.ThrowsAnyAsync<Exception>(() => lab.Client(port: server.Port));
        Assert.NotNull(await good.ListAsync());
        await Task.Delay(1300);
        await using var recovered = await lab.Client("bob", server.Port);
        Assert.NotNull(await recovered.ListAsync());
    }
    [Fact]
    public async Task LoginDeadlineReleasesSlot()
    {
        await using var server = new TransferServer(lab.Options with { LoginSeconds = 1, MaxConnections = 1, MaxPerIp = 1 }, lab.Password) { Log = lab.Log };
        server.Start();
        using var idle = await lab.Raw(server.Port);
        await Task.Delay(1400);
        await using var good = await lab.Client(port: server.Port);
        Assert.NotNull(await good.ListAsync());
    }
    [Fact]
    public async Task FailedLoginRateLimitKeepsExistingClientUsable()
    {
        await using var server = new TransferServer(lab.Options with { FailuresPerMinute = 2 }, lab.Password) { Log = lab.Log };
        server.Start();
        await using var good = await lab.Client(port: server.Port);
        for (int i = 0; i < 2; i++)
        {
            await using var bad = new TransferClient();
            await Assert.ThrowsAnyAsync<Exception>(() => bad.ConnectAsync("localhost", server.Port, Path.Combine(lab.Certs, "ca.cer"), "alice", "wrong password"));
        }
        await Assert.ThrowsAnyAsync<Exception>(() => lab.Client(port: server.Port));
        Assert.NotNull(await good.ListAsync());
    }
    [Theory]
    [InlineData("../x")]
    [InlineData("..\\x")]
    [InlineData("C:\\x")]
    [InlineData("x:y")]
    [InlineData("CON.txt")]
    [InlineData("LPT1")]
    [InlineData("x.")]
    [InlineData("x ")]
    [InlineData(".hidden")]
    public void UnsafeWindowsNamesRejected(string name) => Assert.Throws<ProtocolException>(() => SafeFiles.ValidateName(name));
    [Fact]
    public async Task TraversalRejectedOverNetwork()
    {
        using var r = await lab.Raw();
        await r.Login(lab);
        await r.Wire.SendJsonAsync(MessageType.DownloadRequest, 2, new FileMeta("../accounts.db", 0));
        Assert.Equal(MessageType.Error, (await r.Wire.ReadAsync()).Type);
    }
    [Fact]
    public async Task MalformedLengthRejectedBeforeAllocation()
    {
        using var r = await lab.Raw();
        await r.Login(lab);
        byte[] header = new byte[16];
        BinaryPrimitives.WriteUInt32BigEndian(header, Wire.Magic);
        header[4] = 1;
        header[5] = (byte)MessageType.UploadBegin;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), 2);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), uint.MaxValue);
        await r.Tls.WriteAsync(header);
        Assert.Equal(MessageType.Error, (await r.Wire.ReadAsync()).Type);
    }
}
