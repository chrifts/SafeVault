using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace SafeVault.Tests.Support;

// Starts the real API in memory, with a test database and a test-only JWT key.
public sealed class SafeVaultFactory : WebApplicationFactory<Program>
{
    // Test-only value. The real key always comes from the Jwt__Key environment variable.
    public const string JwtKey = "test-only-signing-key-with-at-least-32-bytes";

    private readonly TestDatabase _database = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:SafeVault"] = _database.ConnectionString,
                ["Jwt:Key"] = JwtKey,
            }));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _database.Dispose();
        }
    }
}
