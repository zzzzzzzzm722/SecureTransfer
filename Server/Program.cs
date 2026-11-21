using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureTransfer.Server;

try
{
    string command = args.FirstOrDefault() ?? "help";
    switch (command)
    {
        case "certs":
            Certificates.CreateLab(args[1], Required("SFT_PFX_PASSWORD"));
            Console.WriteLine("已生成实验 CA 和证书；CA 私钥未保存。");
            break;
        case "add-user":
            string? fingerprint = null;
            if (args.Length > 3)
            {
                using var cert = X509CertificateLoader.LoadCertificateFromFile(args[3]);
                fingerprint = cert.GetCertHashString(HashAlgorithmName.SHA256);
            }
            new Accounts(args[1]).Add(args[2], Required("SFT_USER_PASSWORD"), fingerprint);
            Console.WriteLine("账号创建成功：" + args[2]);
            break;
        case "serve":
        {
            var config = JsonSerializer.Deserialize<ServerOptions>(File.ReadAllText(args.Length > 1 ? args[1] : "server.json"))!;
            // The deployed executable always authenticates both certificates, including legacy configurations.
            config = config with { MutualTls = true };
            using var log = new RotatingLog(config.LogDirectory, config.LogFileBytes, config.LogArchives);
            await using (var server = new TransferServer(config, Required("SFT_PFX_PASSWORD")))
            {
                server.Log += log.Write;
                var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                Console.CancelKeyPress += (s, e) => { e.Cancel = true; done.TrySetResult(); };
                server.Start();
                await done.Task;
            }
            break;
        }
        default:
            Console.WriteLine("Server certs <目录> | add-user <数据库> <用户名> [客户端公证书] | serve [配置.json]\n口令由 SFT_PFX_PASSWORD / SFT_USER_PASSWORD 环境变量提供。");
            break;
    }
}
catch (Exception ex) { Console.Error.WriteLine($"操作失败：{ex.Message}"); Environment.ExitCode = 1; }
static string Required(string name) => Environment.GetEnvironmentVariable(name) ?? throw new ArgumentException("缺少环境变量 " + name);
