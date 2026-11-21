using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureTransfer.Protocol;
using SecureTransfer.Server;
using Xunit;
using Xunit.Abstractions;

namespace SecureTransfer.Tests;

public sealed class EnhancedLab : IAsyncLifetime
{
    public string Root { get; } = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../.validation/advanced-" + Guid.NewGuid().ToString("N")));
    public string Certs => Path.Combine(Root, "certs");
    public string Password { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    public string Database => Path.Combine(Root, "accounts.db");
    public Task InitializeAsync()
    {
        Certificates.CreateLab(Certs, Password);
        foreach (string name in new[] { "alice", "bob" })
        {
            using var cert = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(Certs, name + ".cer"));
            new Accounts(Database).Add(name, Password, cert.GetCertHashString(HashAlgorithmName.SHA256));
        }
        return Task.CompletedTask;
    }
    public Task DisposeAsync() => Task.CompletedTask;
    public TestCase Create(Func<ServerOptions,ServerOptions>? configure = null)
    {
        string path = Path.Combine(Root, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(path);
        var options = new ServerOptions { Port = 0, Root = Path.Combine(path,"data"), Database = Database,
            Certificate=Path.Combine(Certs,"server.pfx"), Ca=Path.Combine(Certs,"ca.cer"), MutualTls=true,
            ConnectionsPerMinute=200, FailuresPerMinute=100, MaxPerIp=16 };
        return new TestCase(this,path,configure?.Invoke(options)??options);
    }
}
public sealed class TestCase : IAsyncDisposable
{
    private readonly EnhancedLab lab;
    public string Root { get; }
    public ServerOptions Options { get; private set; }
    public TransferServer Server { get; private set; }
    public ConcurrentQueue<string> Logs { get; } = new();
    public int Port => Server.Port;
    public TestCase(EnhancedLab lab,string root,ServerOptions options)
    {
        this.lab=lab;Root=root;Options=options;Server=NewServer();Server.Start();
    }
    private TransferServer NewServer()=>new(Options,lab.Password){Log=line=>Logs.Enqueue(line)};
    public async Task Restart()
    {
        int port=Port;await Server.DisposeAsync();Options=Options with{Port=port};Server=NewServer();Server.Start();
    }
    public ConnectionSettings Settings(string user="alice",int count=3)=>new("localhost",Port,Options.Ca,user,lab.Password,Path.Combine(lab.Certs,user+".pfx"),lab.Password,count);
    public async Task<TransferClient> Client(string name="alice")
    {
        var c=new TransferClient();var s=Settings(name);
        try {await c.ConnectAsync(s.Host,s.Port,s.CaPath,s.User,s.Password,s.ClientPfx,s.PfxPassword);return c;}
        catch{await c.DisposeAsync();throw;}
    }
    public string FilePath(string name,int length)
    {
        string path=Path.Combine(Root,name);File.WriteAllBytes(path,RandomNumberGenerator.GetBytes(length));return path;
    }
    public string DirectoryPath(string name){string path=Path.Combine(Root,name);Directory.CreateDirectory(path);return path;}
    public string State(string name)=>Path.Combine(Root,name+".json");
    public async Task<SecureRaw> Raw(string name="alice")
    {
        var s=Settings(name);var raw=new SecureRaw();await raw.Connect(s);return raw;
    }
    public async ValueTask DisposeAsync()
    {
        await Server.DisposeAsync();File.WriteAllLines(Path.Combine(Root,"server.log"),Logs);
    }
}
public sealed class SecureRaw : IDisposable
{
    private readonly TcpClient tcp=new();
    private SslStream? tls;
    public Wire Wire {get;private set;}=null!;
    public async Task Connect(ConnectionSettings s)
    {
        await tcp.ConnectAsync(s.Host,s.Port);tls=new SslStream(tcp.GetStream(),false);
        using var ca=X509CertificateLoader.LoadCertificateFromFile(s.CaPath);
        using var cert=X509CertificateLoader.LoadPkcs12FromFile(s.ClientPfx,s.PfxPassword,X509KeyStorageFlags.DefaultKeySet);
        var policy=new X509ChainPolicy{TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.NoCheck};policy.CustomTrustStore.Add(ca);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions{TargetHost=s.Host,CertificateChainPolicy=policy,ClientCertificates=new X509CertificateCollection{cert}},deadline.Token);
        Wire=new Wire(tls,5);await Wire.SendJsonAsync(MessageType.Login,1,new Login(s.User,s.Password));
        Assert.Equal(MessageType.LoginResult,(await Wire.ReadAsync()).Type);
    }
    public void Dispose(){tls?.Dispose();tcp.Dispose();Wire?.Dispose();}
}
public sealed class InlineProgress(Action<TransferProgress> action):IProgress<TransferProgress>
{public void Report(TransferProgress value)=>action(value);}

public sealed class AdvancedTests(EnhancedLab lab,ITestOutputHelper output):IClassFixture<EnhancedLab>
{
    [Fact] public async Task DeploymentRatesAndIndependentDuplexBudgets()
    {
        await using var e=lab.Create(o=>o with{UserRates=new(){["alice"]=new(131072,131072),["bob"]=new(524288,524288)}});
        string seed=e.FilePath("duplex-seed.bin",262144),source=e.FilePath("duplex-up.bin",262144);
        await using(var setup=await e.Client())await setup.UploadAsync(seed);
        await using var pool=await TransferPool.ConnectAsync(e.Settings());
        var clock=Stopwatch.StartNew();
        await Task.WhenAll(pool.ExecuteAsync((c,t)=>c.ResumeUploadAsync(source,e.State("duplex-up"),ct:t)),pool.ExecuteAsync((c,t)=>c.ResumeDownloadAsync("duplex-seed.bin",e.DirectoryPath("duplex-down"),e.State("duplex-down"),ct:t)));
        double duplex=clock.Elapsed.TotalSeconds;Assert.InRange(duplex,1.9,3.9);
        await AssertHash(seed,Path.Combine(e.DirectoryPath("duplex-down"),"duplex-seed.bin"));
        await using var alice=await e.Client();await using var bob=await e.Client("bob");
        async Task<double> Timed(TransferClient c,string name){var w=Stopwatch.StartNew();await c.ResumeUploadAsync(e.FilePath(name,524288),e.State(name));return w.Elapsed.TotalSeconds;}
        var measured=await Task.WhenAll(Timed(alice,"alice-rate.bin"),Timed(bob,"bob-rate.bin"));
        Assert.True(measured[0]>=3.9);Assert.True(measured[1]<measured[0]*.7);
        output.WriteLine($"Deployment policy: alice={524288/measured[0]:F0} B/s; bob={524288/measured[1]:F0} B/s; independent duplex 2x262144 bytes={duplex:F2}s");
    }
    private static async Task WaitUntil(Func<bool> predicate,int milliseconds=5000)
    {
        var clock=Stopwatch.StartNew();while(!predicate()&&clock.ElapsedMilliseconds<milliseconds)await Task.Delay(20);Assert.True(predicate());
    }
    private static async Task AssertHash(string first,string second)=>Assert.Equal(SHA256.HashData(await File.ReadAllBytesAsync(first)),SHA256.HashData(await File.ReadAllBytesAsync(second)));
    [Fact] public async Task LocalPreflightFailureKeepsOriginalConnectionUsable()
    {
        await using var e=lab.Create();await using var c=await e.Client();string id=c.Session!.ConnectionId;
        await Assert.ThrowsAsync<FileNotFoundException>(()=>c.UploadAsync(Path.Combine(e.Root,"missing.bin")));
        await Assert.ThrowsAsync<DirectoryNotFoundException>(()=>c.DownloadAsync("file.bin",Path.Combine(e.Root,"missing-dir")));
        await Assert.ThrowsAsync<FileNotFoundException>(()=>c.ResumeUploadAsync(Path.Combine(e.Root,"missing.bin"),e.State("missing")));
        Assert.True(c.Connected);Assert.Equal(id,c.Session!.ConnectionId);Assert.Empty(await c.ListAsync());
        string source=e.FilePath("valid.bin",70001);await c.UploadAsync(source);string dest=e.DirectoryPath("download");await c.DownloadAsync("valid.bin",dest);await AssertHash(source,Path.Combine(dest,"valid.bin"));Assert.Equal(id,c.Session!.ConnectionId);
    }
    [Fact] public async Task FatalProtocolErrorImmediatelyInvalidatesClientSession()
    {
        using var cert=X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(lab.Certs,"server.pfx"),lab.Password,X509KeyStorageFlags.DefaultKeySet);
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
        var peer=Task.Run(async()=>
        {
            using var tcp=await listener.AcceptTcpClientAsync();using var tls=new SslStream(tcp.GetStream(),false);
            await tls.AuthenticateAsServerAsync(cert,false,false);using var wire=new Wire(tls);
            var login=await wire.ReadAsync();await wire.SendJsonAsync(MessageType.LoginResult,login.RequestId,new LoginResult("fatal-test","alice","Tls"));
            var list=await wire.ReadAsync();await wire.SendJsonAsync(MessageType.Error,list.RequestId,new Result(false,"Protocol","测试致命错误",true));
        });
        await using var c=new TransferClient();
        try
        {
            await c.ConnectAsync("localhost",((IPEndPoint)listener.LocalEndpoint).Port,Path.Combine(lab.Certs,"ca.cer"),"alice",lab.Password);
            var error=await Assert.ThrowsAsync<RemoteException>(()=>c.ListAsync());Assert.True(error.Fatal);Assert.Equal("Protocol",error.Code);Assert.False(c.Connected);Assert.Null(c.Session);await peer;
        }finally{listener.Stop();}
    }
    [Fact] public async Task UploadResumesAtConfirmedOffsetAcrossServerRestartAndRepeatedDispose()
    {
        await using var e=lab.Create();string source=e.FilePath("resume-up.bin",512*1024+13),checkpoint=e.State("up");
        var c=await e.Client();using var cancellation=new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<Exception>(()=>c.ResumeUploadAsync(source,checkpoint,new InlineProgress(p=>{if(p.Bytes>=65536)cancellation.Cancel();}),cancellation.Token));
        Assert.False(c.Connected);long offset=ResumeFiles.Load(checkpoint).Offset;Assert.InRange(offset,65536,new FileInfo(source).Length-1);
        await Task.WhenAll(c.DisposeAsync().AsTask(),c.DisposeAsync().AsTask());await e.Restart();
        await using var next=await e.Client();long resumed=0;await next.ResumeUploadAsync(source,checkpoint,new InlineProgress(p=>resumed=p.ResumedFrom));Assert.True(resumed>=offset);
        string dest=e.DirectoryPath("down");await next.DownloadAsync("resume-up.bin",dest);await AssertHash(source,Path.Combine(dest,"resume-up.bin"));output.WriteLine($"upload resume offset={resumed}, length={new FileInfo(source).Length}");
    }
    [Fact] public async Task DownloadResumesAtConfirmedOffsetAndPreservesFullHash()
    {
        await using var e=lab.Create();string source=e.FilePath("resume-down.bin",512*1024+37),dest=e.DirectoryPath("down"),state=e.State("down");
        var c=await e.Client();await c.UploadAsync(source);using var cancel=new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<Exception>(()=>c.ResumeDownloadAsync("resume-down.bin",dest,state,new InlineProgress(p=>{if(p.Bytes>=65536)cancel.Cancel();}),cancel.Token));
        long offset=ResumeFiles.Load(state).Offset;Assert.True(offset>0);await c.DisposeAsync();await WaitUntil(()=>e.Server.ActiveConnections==0);
        await using var next=await e.Client();long resumed=0;await next.ResumeDownloadAsync("resume-down.bin",dest,state,new InlineProgress(p=>resumed=p.ResumedFrom));Assert.Equal(offset,resumed);await AssertHash(source,Path.Combine(dest,"resume-down.bin"));output.WriteLine($"download resume offset={resumed}");
    }
    private async Task<(string Source,string State,Checkpoint Checkpoint)> InterruptUpload(TestCase e,string name="partial.bin")
    {
        string source=e.FilePath(name,256*1024),state=e.State(name);
        await using(var c=await e.Client())
        {using var cancel=new CancellationTokenSource();await Assert.ThrowsAnyAsync<Exception>(()=>c.ResumeUploadAsync(source,state,new InlineProgress(p=>{if(p.Bytes>=65536)cancel.Cancel();}),cancel.Token));}
        await WaitUntil(()=>e.Server.ActiveConnections==0);return(source,state,ResumeFiles.Load(state));
    }
    [Fact] public async Task ChangedUploadSourceIsRejectedBeforeRequestWithoutDisconnect()
    {
        await using var e=lab.Create();var p=await InterruptUpload(e);using(var file=File.OpenWrite(p.Source))file.WriteByte(123);
        // Ensure a change even if the original first byte happened to be 123.
        File.SetLastWriteTimeUtc(p.Source,DateTime.UtcNow);var bytes=await File.ReadAllBytesAsync(p.Source);bytes[1]^=255;await File.WriteAllBytesAsync(p.Source,bytes);
        await using var c=await e.Client();string id=c.Session!.ConnectionId;await Assert.ThrowsAsync<ProtocolException>(()=>c.ResumeUploadAsync(p.Source,p.State));Assert.True(c.Connected);Assert.Empty(await c.ListAsync());Assert.Equal(id,c.Session!.ConnectionId);
    }
    [Fact] public async Task CrossUserResumeAndInvalidOffsetAreRejectedOnServer()
    {
        await using var e=lab.Create();var p=await InterruptUpload(e);var s=p.Checkpoint;
        using(var bob=await e.Raw("bob"))
        {
            await bob.Wire.SendJsonAsync(MessageType.ResumeUpload,2,new ResumeRequest(s.TransferId,s.Name,s.Length,s.Sha256,s.Offset,s.PrefixSha256,false));
            var error=(await bob.Wire.ReadAsync()).Json<Result>();Assert.Equal("ResumeNotFound",error.Code);Assert.False(error.Fatal);
        }
        using(var alice=await e.Raw())
        {
            await alice.Wire.SendJsonAsync(MessageType.ResumeUpload,2,new ResumeRequest(s.TransferId,s.Name,s.Length,s.Sha256,s.Offset+1,s.PrefixSha256,false));
            Assert.Equal("ResumeOffset",(await alice.Wire.ReadAsync()).Json<Result>().Code);
            await alice.Wire.SendJsonAsync(MessageType.ResumeUpload,3,new ResumeRequest(s.TransferId,s.Name,s.Length,s.Sha256,s.Offset,new string('0',64),false));
            Assert.Equal("ResumeCorrupt",(await alice.Wire.ReadAsync()).Json<Result>().Code);
        }
    }
    [Fact] public async Task CorruptedServerResumeDataIsRejectedAndNotCommitted()
    {
        await using var e=lab.Create();var p=await InterruptUpload(e);
        string data=Directory.GetFiles(e.Options.Root,p.Checkpoint.TransferId+".data",SearchOption.AllDirectories).Single();
        var bytes=await File.ReadAllBytesAsync(data);bytes[0]^=255;await File.WriteAllBytesAsync(data,bytes);
        await using var c=await e.Client();var error=await Assert.ThrowsAsync<RemoteException>(()=>c.ResumeUploadAsync(p.Source,p.State));Assert.Equal("ResumeCorrupt",error.Code);Assert.True(c.Connected);Assert.Empty(await c.ListAsync());
    }
    [Fact] public async Task CorruptedLocalDownloadDataIsRejectedBeforeNetworkUse()
    {
        await using var e=lab.Create();string source=e.FilePath("local-corrupt.bin",262144),dest=e.DirectoryPath("down"),state=e.State("download");
        await using(var c=await e.Client())
        {
            await c.UploadAsync(source);using var cancel=new CancellationTokenSource();await Assert.ThrowsAnyAsync<Exception>(()=>c.ResumeDownloadAsync("local-corrupt.bin",dest,state,new InlineProgress(p=>{if(p.Bytes>=65536)cancel.Cancel();}),cancel.Token));
        }
        var checkpoint=ResumeFiles.Load(state);string data=Path.Combine(dest,".sft-resume-"+checkpoint.TransferId+".data");var bytes=await File.ReadAllBytesAsync(data);bytes[0]^=255;await File.WriteAllBytesAsync(data,bytes);
        await using var next=await e.Client();await Assert.ThrowsAsync<ProtocolException>(()=>next.ResumeDownloadAsync("local-corrupt.bin",dest,state));Assert.True(next.Connected);Assert.Single(await next.ListAsync());
    }
    [Fact] public async Task OneWorkspaceOverlapsUploadAndDownloadAndIsolatesFailureAndCancellation()
    {
        await using var e=lab.Create(o=>o with{DefaultRate=new UserRate(131072,131072)});
        string seed=e.FilePath("seed.bin",262144),u1=e.FilePath("first.bin",262144),u2=e.FilePath("second.bin",262144);
        await using(var setup=await e.Client())await setup.UploadAsync(seed);
        var pool=await TransferPool.ConnectAsync(e.Settings());await using var workspace=new TransferWorkspace(pool,e.DirectoryPath("workspace"));
        var first=workspace.Add("upload",u1);var second=workspace.Add("upload",u2);var down=workspace.Add("download","seed.bin",e.DirectoryPath("downloads"));var bad=workspace.Add("upload",Path.Combine(e.Root,"missing.bin"));
        var active=new ConcurrentDictionary<string,string>();int overlap=0;bool canceled=false;
        workspace.Changed+=job=>
        {
            if(job.Progress is {Bytes:>0} p&&p.Bytes<p.Total&&job.State is "传输中" or "续传中")active[job.Plan.Id]=job.Plan.Direction;
            if(job.Result is not null||job.FinishedAt is not null)active.TryRemove(job.Plan.Id,out _);
            if(active.Values.Contains("upload")&&active.Values.Contains("download"))Interlocked.Exchange(ref overlap,1);
            if(job==first&&job.Progress?.Bytes>=65536&&!canceled){canceled=true;workspace.Cancel(first);}
        };
        await Task.WhenAll(workspace.Start(first),workspace.Start(second),workspace.Start(down),workspace.Start(bad));
        Assert.Equal(1,overlap);Assert.Equal("已中断，可恢复",first.State);Assert.Equal("已完成",second.State);Assert.Equal("已完成",down.State);Assert.Equal("失败，可重试",bad.State);
        await workspace.Start(first);Assert.Equal("已完成",first.State);Assert.True(first.Progress!.ResumedFrom>0);
        await AssertHash(seed,Path.Combine(down.Plan.Destination,"seed.bin"));Assert.InRange(pool.ConnectedCount,1,3);output.WriteLine("GUI controller: upload/download overlap verified; failed and canceled tasks isolated; nonzero resume.");
    }
    [Fact] public async Task AggregateUploadAndDownloadRateCannotBeBypassedWithConnections()
    {
        const int rate=131072,length=131072;
        await using var e=lab.Create(o=>o with{DefaultRate=new UserRate(rate,rate)});
        string a=e.FilePath("rate-a.bin",length),b=e.FilePath("rate-b.bin",length);
        await using var pool=await TransferPool.ConnectAsync(e.Settings());var clock=Stopwatch.StartNew();
        await Task.WhenAll(pool.ExecuteAsync((c,t)=>c.ResumeUploadAsync(a,e.State("a"),ct:t)),pool.ExecuteAsync((c,t)=>c.ResumeUploadAsync(b,e.State("b"),ct:t)));
        double uploadSeconds=clock.Elapsed.TotalSeconds;Assert.True(uploadSeconds>=1.85,$"upload {uploadSeconds}");
        clock.Restart();string dest=e.DirectoryPath("downloads");
        await Task.WhenAll(pool.ExecuteAsync((c,t)=>c.ResumeDownloadAsync("rate-a.bin",dest,e.State("da"),ct:t)),pool.ExecuteAsync((c,t)=>c.ResumeDownloadAsync("rate-b.bin",dest,e.State("db"),ct:t)));
        double downloadSeconds=clock.Elapsed.TotalSeconds;Assert.True(downloadSeconds>=1.85,$"download {downloadSeconds}");
        output.WriteLine($"rate={rate} B/s, 2 connections, upload={2*length/uploadSeconds:F0} B/s, download={2*length/downloadSeconds:F0} B/s");
    }
    [Fact] public async Task DifferentUsersHaveIndependentBandwidthBudgets()
    {
        await using var e=lab.Create(o=>o with{UserRates=new(){["alice"]=new(65536,65536),["bob"]=new(262144,262144)}});
        string a=e.FilePath("slow.bin",262144),b=e.FilePath("fast.bin",262144);await using var alice=await e.Client();await using var bob=await e.Client("bob");
        async Task<double> Timed(TransferClient c,string source,string state){var watch=Stopwatch.StartNew();await c.ResumeUploadAsync(source,state);return watch.Elapsed.TotalSeconds;}
        var durations=await Task.WhenAll(Timed(alice,a,e.State("slow")),Timed(bob,b,e.State("fast")));Assert.True(durations[0]>=3.8);Assert.True(durations[1]<durations[0]*.75);
        output.WriteLine($"alice 65536 B/s: {durations[0]:F2}s; bob 262144 B/s: {durations[1]:F2}s");
    }
    [Fact] public async Task SlowTrickleConnectionsAreReclaimedAndNormalClientRecovers()
    {
        await using var e=lab.Create(o=>o with{MaxConnections=2,MaxPerIp=2,IoSeconds=1,ProgressGraceSeconds=.4,ProgressWindowSeconds=.6,MinTransferBytesPerSecond=64});
        using var first=await e.Raw();using var second=await e.Raw("bob");
        foreach(var raw in new[]{first,second}){await raw.Wire.SendJsonAsync(MessageType.UploadBegin,2,new FileMeta("trickle.bin",10000));Assert.Equal(MessageType.Ready,(await raw.Wire.ReadAsync()).Type);}
        async Task Trickle(SecureRaw raw){try{for(int i=0;i<8;i++){await raw.Wire.SendAsync(MessageType.Data,2,new byte[]{1});await Task.Delay(400);}}catch(IOException){} }
        var streams=Task.WhenAll(Trickle(first),Trickle(second));await Assert.ThrowsAnyAsync<Exception>(()=>e.Client());
        await WaitUntil(()=>e.Server.ActiveConnections==0,4000);await streams;
        await using var normal=await e.Client();Assert.Empty(await normal.ListAsync());Assert.Empty(Directory.GetFiles(e.Options.Root,"*.part",SearchOption.AllDirectories));
    }
    [Fact] public async Task LegitimatelyRateLimitedConcurrentTransfersAreNotKilledByProgressGuard()
    {
        await using var e=lab.Create(o=>o with{DefaultRate=new(16384,16384),IoSeconds=1,ProgressGraceSeconds=.3,ProgressWindowSeconds=.5,MinTransferBytesPerSecond=8192});
        await using var pool=await TransferPool.ConnectAsync(e.Settings());var files=Enumerable.Range(0,3).Select(i=>e.FilePath($"legal-{i}.bin",32768)).ToArray();
        var watch=Stopwatch.StartNew();await Task.WhenAll(files.Select((file,i)=>pool.ExecuteAsync((c,t)=>c.ResumeUploadAsync(file,e.State("legal"+i),ct:t))));
        Assert.Equal(3,(await pool.ListAsync()).Length);Assert.True(watch.Elapsed.TotalSeconds>=5.7);output.WriteLine($"3 shared limited sessions completed in {watch.Elapsed.TotalSeconds:F2}s with IoSeconds=1");
    }
    [Fact] public async Task PerUserConnectionAndBusinessRequestLimitsAreEnforced()
    {
        await using var e=lab.Create(o=>o with{MaxPerUserConnections=1,RequestsPerMinute=2});
        await using var alice=await e.Client();await Assert.ThrowsAnyAsync<Exception>(()=>e.Client());await using var bob=await e.Client("bob");
        await alice.ListAsync();await alice.ListAsync();var error=await Assert.ThrowsAsync<RemoteException>(()=>alice.ListAsync());Assert.True(error.Fatal);Assert.Equal("RequestLimit",error.Code);Assert.False(alice.Connected);Assert.Empty(await bob.ListAsync());
    }
    [Fact] public async Task DisposingWorkspaceCancelsJobsAndPersistedQueueCanReconnect()
    {
        await using var e=lab.Create(o=>o with{DefaultRate=new(65536,65536)});string file=e.FilePath("closing.bin",131072),dir=e.DirectoryPath("queue");
        var pool=await TransferPool.ConnectAsync(e.Settings());var workspace=new TransferWorkspace(pool,dir);var job=workspace.Add("upload",file);var task=workspace.Start(job);
        await WaitUntil(()=>job.Progress?.Bytes>0);await Task.WhenAll(workspace.DisposeAsync().AsTask(),workspace.DisposeAsync().AsTask());await task;Assert.False(pool.IsOpen);Assert.Equal("已中断，可恢复",job.State);
        await WaitUntil(()=>e.Server.ActiveConnections==0);
        var newPool=await TransferPool.ConnectAsync(e.Settings());await using var next=new TransferWorkspace(newPool,dir);var recovered=Assert.Single(next.Jobs);await next.Start(recovered);Assert.Equal("已完成",recovered.State);Assert.True(recovered.Progress!.ResumedFrom>0);
    }
    [Fact] public async Task ResumeQuotaAndExpiryPreserveUnrelatedFiles()
    {
        await using var e=lab.Create(o=>o with{MaxResumeStates=1,ResumeRetentionSeconds=2});var p=await InterruptUpload(e);
        string marker=Path.Combine(e.Options.Root,"preserve-user-file.txt");await File.WriteAllTextAsync(marker,"preserve");
        await using(var c=await e.Client())
        {
            var error=await Assert.ThrowsAsync<RemoteException>(()=>c.ResumeUploadAsync(e.FilePath("quota.bin",10),e.State("quota")));Assert.Equal("Quota",error.Code);
        }
        await WaitUntil(()=>Directory.GetFiles(e.Options.Root,p.Checkpoint.TransferId+".json",SearchOption.AllDirectories).Length==0,5000);
        Assert.Equal("preserve",await File.ReadAllTextAsync(marker));
        await using var next=await e.Client();Assert.Equal("ResumeNotFound",(await Assert.ThrowsAsync<RemoteException>(()=>next.ResumeUploadAsync(p.Source,p.State))).Code);
    }
    [Fact] public async Task DownloadResumeRejectsForeignOwnerBadOffsetAndChangedSource()
    {
        await using var e=lab.Create();string source=e.FilePath("download-identity.bin",262144),dest=e.DirectoryPath("down"),path=e.State("down");
        await using(var c=await e.Client())
        {
            await c.UploadAsync(source);using var cancel=new CancellationTokenSource();
            await Assert.ThrowsAnyAsync<Exception>(()=>c.ResumeDownloadAsync(Path.GetFileName(source),dest,path,new InlineProgress(p=>{if(p.Bytes>=65536)cancel.Cancel();}),cancel.Token));
        }
        var s=ResumeFiles.Load(path);
        await using(var bob=await e.Client("bob"))await bob.UploadAsync(source);
        using(var bob=await e.Raw("bob"))
        {
            await bob.Wire.SendJsonAsync(MessageType.ResumeDownload,2,new ResumeRequest(s.TransferId,s.Name,s.Length,s.Sha256,s.Offset,s.PrefixSha256,false));
            Assert.Equal("ResumeNotFound",(await bob.Wire.ReadAsync()).Json<Result>().Code);
        }
        using(var raw=await e.Raw())
        {
            await raw.Wire.SendJsonAsync(MessageType.ResumeDownload,2,new ResumeRequest(s.TransferId,s.Name,s.Length,s.Sha256,s.Length,s.PrefixSha256,false));
            Assert.Equal("ResumeOffset",(await raw.Wire.ReadAsync()).Json<Result>().Code);
            await raw.Wire.SendJsonAsync(MessageType.ResumeDownload,3,new ResumeRequest(s.TransferId,s.Name,s.Length,s.Sha256,s.Offset,new string('0',64),false));
            Assert.Equal("ResumeCorrupt",(await raw.Wire.ReadAsync()).Json<Result>().Code);
        }
        foreach(string remote in Directory.GetFiles(e.Options.Root,s.Name,SearchOption.AllDirectories))
        {var bytes=await File.ReadAllBytesAsync(remote);bytes[0]^=255;await File.WriteAllBytesAsync(remote,bytes);}
        await using var next=await e.Client();Assert.Equal("ResumeIdentity",(await Assert.ThrowsAsync<RemoteException>(()=>next.ResumeDownloadAsync(s.Name,dest,path))).Code);
        Assert.True(next.Connected);Assert.False(File.Exists(Path.Combine(dest,s.Name)));
    }
    [Fact] public async Task FailedPoolConnectCanBeFollowedBySuccessfulConnection()
    {
        await using var e=lab.Create();await Assert.ThrowsAnyAsync<Exception>(()=>TransferPool.ConnectAsync(e.Settings() with{Password="incorrect-password"}));
        await WaitUntil(()=>e.Server.ActiveConnections==0);await using var pool=await TransferPool.ConnectAsync(e.Settings());Assert.Empty(await pool.ListAsync());
    }
    [Fact] public async Task DeployedExecutableForcesMutualTlsEvenForLegacyConfig()
    {
        string root=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../.."));
        var template=JsonSerializer.Deserialize<ServerOptions>(await File.ReadAllTextAsync(Path.Combine(root,"server.json")))!;Assert.True(template.MutualTls);
        string folder=Path.Combine(lab.Root,"cli-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        var config=template with{Port=0,MutualTls=false,Root=Path.Combine(folder,"data"),LogDirectory=Path.Combine(folder,"logs"),Database=lab.Database,Certificate=Path.Combine(lab.Certs,"server.pfx"),Ca=Path.Combine(lab.Certs,"ca.cer"),FailuresPerMinute=100};
        string path=Path.Combine(folder,"server.json");await File.WriteAllTextAsync(path,JsonSerializer.Serialize(config));
        var start=new ProcessStartInfo("dotnet"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=root};
        start.ArgumentList.Add(Path.Combine(root,"Server/bin/Release/net9.0/Server.dll"));start.ArgumentList.Add("serve");start.ArgumentList.Add(path);start.Environment["SFT_PFX_PASSWORD"]=lab.Password;
        using var process=Process.Start(start)!;
        try
        {
            string line=(await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)))!;
            Assert.Contains("mTLS=True",line);int port=int.Parse(line.Split(' ')[1].Split(':')[1]);
            async Task Attempt(string ca,string? cert,string user)
            {await using var c=new TransferClient();await c.ConnectAsync("localhost",port,ca,user,lab.Password,cert,lab.Password);Assert.Empty(await c.ListAsync());}
            await Attempt(config.Ca,Path.Combine(lab.Certs,"alice.pfx"),"alice");
            await Assert.ThrowsAnyAsync<Exception>(()=>Attempt(config.Ca,null,"alice"));
            await Assert.ThrowsAnyAsync<Exception>(()=>Attempt(config.Ca,Path.Combine(lab.Certs,"bob.pfx"),"alice"));
            string other=Path.Combine(folder,"other");Certificates.CreateLab(other,lab.Password);
            await Assert.ThrowsAnyAsync<Exception>(()=>Attempt(Path.Combine(other,"ca.cer"),Path.Combine(lab.Certs,"alice.pfx"),"alice"));
            await Assert.ThrowsAnyAsync<Exception>(()=>Attempt(config.Ca,Path.Combine(other,"alice.pfx"),"alice"));
        }
        finally {if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync();}
    }
    [Fact] public void LogRotationHasBoundedSizeAndCount()
    {
        string folder=Path.Combine(lab.Root,"log-"+Guid.NewGuid().ToString("N"));
        using(var log=new RotatingLog(folder,4096,2))for(int i=0;i<1000;i++)log.Write(new string('x',500));
        var files=Directory.GetFiles(folder);Assert.Equal(3,files.Length);Assert.All(files,f=>Assert.InRange(new FileInfo(f).Length,1,4700));
    }
    [Fact] public async Task ExpiredOrphanResumeArtifactsAreReclaimedWithoutDeletingUnrelatedFiles()
    {
        await using var e=lab.Create(o=>o with{ResumeRetentionSeconds=1});var p=await InterruptUpload(e);
        string folder=Path.GetDirectoryName(Directory.GetFiles(e.Options.Root,p.Checkpoint.TransferId+".json",SearchOption.AllDirectories).Single())!;
        string id=Guid.NewGuid().ToString("N"),data=Path.Combine(folder,id+".data"),pending=Path.Combine(folder,id+".json.new"),unrelated=Path.Combine(folder,"user-notes.txt");
        await File.WriteAllTextAsync(data,"orphan");await File.WriteAllTextAsync(pending,"incomplete");await File.WriteAllTextAsync(unrelated,"keep");
        File.SetLastWriteTimeUtc(data,DateTime.UtcNow.AddMinutes(-1));File.SetLastWriteTimeUtc(pending,DateTime.UtcNow.AddMinutes(-1));
        await WaitUntil(()=>!File.Exists(data)&&!File.Exists(pending),4000);Assert.Equal("keep",await File.ReadAllTextAsync(unrelated));
    }
    [Fact] public async Task CheckpointReadersDoNotBlockAtomicPublicationDuringConcurrentQuotaChecks()
    {
        string path=Path.Combine(lab.Root,"metadata-"+Guid.NewGuid().ToString("N")+".json");
        var state=new Checkpoint{TransferId=Guid.NewGuid().ToString("N"),Owner="owner",Direction="upload",Name="file.bin",Length=0,Sha256=ResumeFiles.EmptyHash};
        ResumeFiles.Save(path,state);using var stop=new CancellationTokenSource();
        var readers=Enumerable.Range(0,4).Select(_=>Task.Run(()=>{while(!stop.IsCancellationRequested)Assert.Equal(state.TransferId,ResumeFiles.Load(path).TransferId);})).ToArray();
        try{for(int i=0;i<300;i++){ResumeFiles.Save(path,state with{UpdatedUtc=DateTimeOffset.UtcNow});await Task.Yield();}}
        finally{stop.Cancel();await Task.WhenAll(readers);}
    }
}
