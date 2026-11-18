using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
namespace SecureTransfer.Server;
public record Account(string Id, string Name, string? Certificate);
public sealed class Accounts
{
    public const int Iterations = 210000;
    private readonly string connectionString;
    public Accounts(string path, bool readOnly = false)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        connectionString = new SqliteConnectionStringBuilder { DataSource = path, Pooling = false, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate }.ToString();
        if (readOnly)
            return;
        using var db = Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, hash BLOB NOT NULL, iterations INTEGER NOT NULL, certificate TEXT)";
        cmd.ExecuteNonQuery();
    }
    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString);
        db.Open();
        return db;
    }
    public void Add(string name, string password, string? certificate = null)
    {
        if (!Regex.IsMatch(name, @"^[A-Za-z0-9_-]{1,32}$") || password.Length < 10 || password.Length > 128)
            throw new ArgumentException("账号须为 1–32 位字母数字下划线；口令须为 10–128 字符");
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        using var db = Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "INSERT INTO users VALUES($id,$name,$salt,$hash,$iterations,$cert)";
        cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
        cmd.Parameters.AddWithValue("$name", name);
        cmd.Parameters.AddWithValue("$salt", salt);
        cmd.Parameters.AddWithValue("$hash", hash);
        cmd.Parameters.AddWithValue("$iterations", Iterations);
        cmd.Parameters.AddWithValue("$cert", (object?)certificate ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }
    public Account? Verify(string name, string password, string? certificate, bool requireCertificate)
    {
        if (name is null || password is null || name.Length > 128 || password.Length > 128)
            return null;
        using var db = Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT id,name,salt,hash,iterations,certificate FROM users WHERE name=$name";
        cmd.Parameters.AddWithValue("$name", name);
        using var reader = cmd.ExecuteReader();
        bool exists = reader.Read();
        byte[] salt = exists ? (byte[])reader[2] : new byte[16];
        byte[] expected = exists ? (byte[])reader[3] : new byte[32];
        int iterations = exists ? reader.GetInt32(4) : Iterations;
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        bool valid = CryptographicOperations.FixedTimeEquals(actual, expected);
        if (!exists || !valid)
            return null;
        string? bound = reader.IsDBNull(5) ? null : reader.GetString(5);
        if (requireCertificate && (bound is null || !string.Equals(bound, certificate, StringComparison.OrdinalIgnoreCase)))
            return null;
        return new Account(reader.GetString(0), reader.GetString(1), bound);
    }
}
