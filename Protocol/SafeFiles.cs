using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SecureTransfer.Protocol;
public static class SafeFiles
{
    public const long MaxFileSize = 256L * 1024 * 1024;
    public static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || name.StartsWith('.') || name.EndsWith('.') || name.EndsWith(' ') ||
           name.Any(c => c < 32 || "<>:\"/\\|?*".Contains(c)) || Path.IsPathRooted(name) ||
           Regex.IsMatch(name, @"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:[ .]|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            throw new ProtocolException("不安全的文件名");
    }
    public static void NoReparse(string path)
    {
        for (var p = new DirectoryInfo(Path.GetFullPath(path)); p is not null; p = p.Parent)
            if (p.Exists && (p.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new ProtocolException("拒绝重解析点");
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new ProtocolException("拒绝重解析文件");
    }
    public static string Target(string directory, string name)
    {
        ValidateName(name);
        NoReparse(directory);
        string root = Path.GetFullPath(directory) + Path.DirectorySeparatorChar;
        string target = Path.GetFullPath(Path.Combine(directory, name));
        if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new ProtocolException("越界路径");
        NoReparse(target);
        return target;
    }
    public static bool HashEquals(string actual, string supplied)
    {
        if (supplied is null || supplied.Length != 64)
            return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), Convert.FromHexString(supplied));
        }
        catch (FormatException) { return false; }
    }
}

// Same-volume staging; successful verification is necessary but not sufficient: Move must succeed.
public sealed class FileReceiver : IDisposable
{
    private readonly string target, temp;
    private readonly long expected;
    private readonly FileStream file;
    private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    public long Received
    {
        get; private set;
    }
    public FileReceiver(string target, long length)
    {
        if (length < 0 || length > SafeFiles.MaxFileSize)
            throw new ProtocolException("文件大小超限");
        SafeFiles.NoReparse(target);
        if (File.Exists(target))
            throw new IOException("目标已存在，拒绝覆盖");
        this.target = target;
        expected = length;
        temp = Path.Combine(Path.GetDirectoryName(target)!, ".sft-" + Guid.NewGuid().ToString("N") + ".part");
        file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, Wire.ChunkSize, FileOptions.Asynchronous);
    }
    public async Task AppendAsync(byte[] data, CancellationToken ct)
    {
        if (data.Length == 0 || data.Length > expected - Received)
            throw new ProtocolException("数据超出申报长度");
        await file.WriteAsync(data, ct);
        hash.AppendData(data);
        Received += data.Length;
    }
    public async Task<EndInfo> CommitAsync(EndInfo end, CancellationToken ct)
    {
        string digest = Convert.ToHexString(hash.GetHashAndReset());
        if (Received != expected || end.Length != expected || !SafeFiles.HashEquals(digest, end.Sha256))
            throw new ProtocolException("长度或 SHA-256 校验失败");
        await file.FlushAsync(ct);
        file.Flush(true);
        file.Dispose();
        SafeFiles.NoReparse(target);
        File.Move(temp, target, false);
        return new EndInfo(Received, digest);
    }
    public void Dispose()
    {
        file.Dispose();
        hash.Dispose();
        if (File.Exists(temp))
            File.Delete(temp);
    }
}
