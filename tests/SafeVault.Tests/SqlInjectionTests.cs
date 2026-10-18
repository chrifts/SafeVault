using SafeVault.Api.Domain;
using SafeVault.Api.Infrastructure;
using SafeVault.Tests.Support;

namespace SafeVault.Tests;

// These tests skip input validation on purpose and hit the repository directly,
// to prove the parameterized queries are safe on their own (defense in depth).
public class SqlInjectionTests
{
    private TestDatabase _database = null!;
    private SqliteUserRepository _repository = null!;

    [SetUp]
    public async Task SetUp()
    {
        _database = new TestDatabase();
        _repository = new SqliteUserRepository(_database.ConnectionString);
        await _repository.AddAsync(new User
        {
            Username = "alice",
            Email = "alice@mail.com",
            PasswordHash = "hash",
            Role = Roles.User,
        });
    }

    [TearDown]
    public void TearDown() => _database.Dispose();

    [Test]
    public async Task FindByUsername_WithAlwaysTruePayload_ReturnsNoUser()
    {
        // With string concatenation this would become "... WHERE Username = '' OR '1'='1'"
        // and return the first user in the table.
        var user = await _repository.FindByUsernameAsync("' OR '1'='1");

        Assert.That(user, Is.Null);
    }

    [Test]
    public async Task FindByUsername_WithDropTablePayload_DoesNotRunIt()
    {
        await _repository.FindByUsernameAsync("x'; DROP TABLE Users; --");

        // If the payload had run, the table would be gone and this would throw.
        var alice = await _repository.FindByUsernameAsync("alice");
        Assert.That(alice, Is.Not.Null);
    }
}
