using Microsoft.Data.Sqlite;
using SafeVault.Api.Infrastructure;

namespace SafeVault.Tests.Support;

// Real SQLite running in memory: we test the actual SQL (and SQL injection),
// without needing a database server. Each instance gets its own isolated database.
public sealed class TestDatabase : IDisposable
{
    // A shared in-memory database is deleted when its last connection closes,
    // so we keep one connection open for the lifetime of the test.
    private readonly SqliteConnection _keepAlive;

    public TestDatabase()
    {
        ConnectionString = $"Data Source=safevault-test-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        _keepAlive = new SqliteConnection(ConnectionString);
        _keepAlive.Open();
        DatabaseInitializer.EnsureCreated(ConnectionString);
    }

    public string ConnectionString { get; }

    public void Dispose() => _keepAlive.Dispose();
}
