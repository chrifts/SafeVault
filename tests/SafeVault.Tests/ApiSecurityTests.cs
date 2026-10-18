using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SafeVault.Api.Application;
using SafeVault.Api.Domain;
using SafeVault.Api.Infrastructure;
using SafeVault.Tests.Support;

namespace SafeVault.Tests;

// End-to-end checks through the real HTTP pipeline: JWT validation, RBAC and XSS encoding.
public class ApiSecurityTests
{
    private const string Password = "Passw0rd!";
    private const string DashboardUrl = "/api/admin/dashboard";

    private SafeVaultFactory _factory = null!;
    private HttpClient _client = null!;

    [OneTimeSetUp]
    public async Task OneTimeSetUp()
    {
        _factory = new SafeVaultFactory();
        _client = _factory.CreateClient();

        using var scope = _factory.Services.CreateScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        await auth.RegisterAsync("alice", "alice@mail.com", Password, Roles.User);
        await auth.RegisterAsync("boss", "boss@mail.com", Password, Roles.Admin);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Test]
    public async Task AdminDashboard_WithoutToken_Returns401()
    {
        using var response = await GetAsync(DashboardUrl, token: null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminDashboard_WithUserRole_Returns403()
    {
        var token = await LoginAsync("alice");

        using var response = await GetAsync(DashboardUrl, token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task AdminDashboard_WithAdminRole_Returns200_WithoutPasswordHashes()
    {
        var token = await LoginAsync("boss");

        using var response = await GetAsync(DashboardUrl, token);
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(body, Does.Contain("alice"));
        Assert.That(body, Does.Not.Contain("passwordHash").IgnoreCase);
    }

    [Test]
    public async Task AdminDashboard_WithForgedAdminToken_Returns401()
    {
        // An attacker signs their own "Admin" token with a key they made up.
        var forger = new JwtTokenService(Options.Create(new JwtSettings
        {
            Key = "attacker-made-up-key-that-is-32-bytes-long",
        }));
        var forgedToken = forger.CreateToken(new User
        {
            Id = 999,
            Username = "mallory",
            Email = "mallory@mail.com",
            PasswordHash = "none",
            Role = Roles.Admin,
        });

        using var response = await GetAsync(DashboardUrl, forgedToken);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Welcome_WithScriptInName_ReturnsEncodedHtml()
    {
        var payload = Uri.EscapeDataString("<script>alert('xss')</script>");

        var body = await _client.GetStringAsync($"/welcome?name={payload}");

        Assert.That(body, Does.Not.Contain("<script>"));
        Assert.That(body, Does.Contain("&lt;script&gt;"));
    }

    private async Task<string> LoginAsync(string username)
    {
        using var response = await _client.PostAsJsonAsync("/api/auth/login", new { username, password = Password });
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        return body!.Token;
    }

    private Task<HttpResponseMessage> GetAsync(string url, string? token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return _client.SendAsync(request);
    }

    private sealed record TokenResponse(string Token);
}
