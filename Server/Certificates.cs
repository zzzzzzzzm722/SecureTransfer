using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace SecureTransfer.Server;
public static class Certificates
{
    public static void CreateLab(string directory, string password)
    {
        Directory.CreateDirectory(directory);
        if (Directory.EnumerateFiles(directory).Any())
            throw new IOException("证书目录非空，拒绝覆盖");
        using var caKey = RSA.Create(3072);
        var caRequest = new CertificateRequest("CN=SFT Laboratory CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(90));
        File.WriteAllBytes(Path.Combine(directory, "ca.cer"), ca.Export(X509ContentType.Cert));
        Issue("server", true);
        Issue("alice", false);
        Issue("bob", false);
        // Lab CA private key is deliberately discarded; regenerate the whole lab to rotate.
        void Issue(string name, bool server)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
            var san = new SubjectAlternativeNameBuilder();
            if (server)
            {
                san.AddDnsName("localhost");
                san.AddIpAddress(IPAddress.Loopback);
                san.AddIpAddress(IPAddress.IPv6Loopback);
            }
            else
                san.AddDnsName(name);
            request.CertificateExtensions.Add(san.Build());
            using var issued = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(16));
            using var full = issued.CopyWithPrivateKey(key);
            File.WriteAllBytes(Path.Combine(directory, name + ".pfx"), full.Export(X509ContentType.Pfx, password));
            File.WriteAllBytes(Path.Combine(directory, name + ".cer"), full.Export(X509ContentType.Cert));
        }
    }
}
