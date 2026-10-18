using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SafeVault.Api.Application;
using SafeVault.Api.Domain;
using SafeVault.Api.Infrastructure;
using SafeVault.Tests.Support;

namespace SafeVault.Tests;

public class AuthServiceTests
{
    private const string Password = "Passw0rd!";

    private TestDatabase _database = null!;
    private SqliteUserRepository _repository = null!;
    private AuthService _auth = null!;

    [SetUp]
    public void SetUp()
    {
        _database = new TestDatabase();
        _repository = new SqliteUserRepository(_database.ConnectionString);
        var tokens = new JwtTokenService(Options.Create(new JwtSettings { Key = SafeVaultFactory.JwtKey }));
        _auth = new AuthService(_repository, new PasswordHasher<User>(), tokens);
    }

    [TearDown]
    public void TearDown() => _database.Dispose();

    [Test]
    public async Task Register_StoresHashedPassword_NeverPlainText()
    {
        await _auth.RegisterAsync("alice", "alice@mail.com", Password);

        var stored = await _repository.FindByUsernameAsync("alice");

        Assert.That(stored, Is.Not.Null);
        Assert.That(stored!.PasswordHash, Is.Not.EqualTo(Password));
        Assert.That(stored.PasswordHash, Does.Not.Contain(Password));
    }

    [Test]
    public async Task Login_WithCorrectPassword_ReturnsToken()
    {
        await _auth.RegisterAsync("alice", "alice@mail.com", Password);

        var token = await _auth.LoginAsync("alice", Password);

        Assert.That(token, Is.Not.Null.And.Not.Empty);
    }

    [Test]
    public async Task Login_WithWrongPassword_ReturnsNull()
    {
        await _auth.RegisterAsync("alice", "alice@mail.com", Password);

        var token = await _auth.LoginAsync("alice", "WrongPassw0rd");

        Assert.That(token, Is.Null);
    }

    [Test]
    public async Task Register_WithXssUsername_IsRejectedAndNotStored()
    {
        var result = await _auth.RegisterAsync("<script>alert(1)</script>", "x@mail.com", Password);

        Assert.That(result.Succeeded, Is.False);
        Assert.That(await _repository.GetAllAsync(), Is.Empty);
    }
}
