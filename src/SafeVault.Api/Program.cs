using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Application;
using SafeVault.Api.Domain;
using SafeVault.Api.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

const string AdminOnlyPolicy = "AdminOnly";

// ---------- Services ----------

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));

// Factory needed because the repository takes a plain connection string.
// Config is read lazily (inside the lambda) so tests can override it.
builder.Services.AddSingleton<IUserRepository>(sp =>
    new SqliteUserRepository(GetConnectionString(sp.GetRequiredService<IConfiguration>())));

builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddScoped<AuthService>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();

// Every incoming token is checked against the same key, issuer and audience used to create it.
// A token with a bad signature, wrong issuer/audience or past its expiry gets a 401.
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtSettings>>((bearer, jwt) =>
    {
        var settings = jwt.Value;
        bearer.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = settings.GetSigningKey(),
            ValidateIssuer = true,
            ValidIssuer = settings.Issuer,
            ValidateAudience = true,
            ValidAudience = settings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30), // default is 5 minutes, too generous
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(AdminOnlyPolicy, policy => policy.RequireRole(Roles.Admin));

var app = builder.Build();

// ---------- Startup tasks ----------

// Fail fast: crash at startup if the JWT key is missing or too short,
// instead of failing later on the first login request.
app.Services.GetRequiredService<IOptions<JwtSettings>>().Value.GetSigningKey();

DatabaseInitializer.EnsureCreated(GetConnectionString(app.Configuration));
await SeedAdminAsync(app);

// ---------- Middleware ----------

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();

// Defense in depth against XSS and clickjacking: even if some HTML slips through,
// the browser refuses inline scripts and scripts from other origins.
app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// ---------- Endpoints ----------

var api = app.MapGroup("/api");

api.MapPost("/auth/register", async (RegisterRequest request, AuthService auth) =>
{
    // No role in the request: self-registered accounts are always "User".
    var result = await auth.RegisterAsync(request.Username, request.Email, request.Password);

    return result.Succeeded
        ? Results.StatusCode(StatusCodes.Status201Created)
        : Results.BadRequest(new { error = result.Error });
});

api.MapPost("/auth/login", async (LoginRequest request, AuthService auth) =>
{
    var token = await auth.LoginAsync(request.Username, request.Password);
    return token is null ? Results.Unauthorized() : Results.Ok(new { token });
});

api.MapGet("/users/me", (ClaimsPrincipal user) => Results.Ok(new
{
    username = user.Identity?.Name,
    role = user.FindFirst(ClaimTypes.Role)?.Value,
}))
.RequireAuthorization();

api.MapGet("/admin/dashboard", async (IUserRepository users) =>
{
    // Project to a DTO so password hashes never leave the server.
    var all = await users.GetAllAsync();
    return Results.Ok(all.Select(u => new { u.Username, u.Email, u.Role }));
})
.RequireAuthorization(AdminOnlyPolicy);

// Writes user input into HTML, so it must be encoded first:
// "<script>" becomes "&lt;script&gt;" and is shown as text instead of running.
app.MapGet("/welcome", (string? name) =>
{
    var safeName = HtmlEncoder.Default.Encode(name ?? "guest");
    return Results.Content($"<h1>Welcome, {safeName}!</h1>", "text/html");
});

app.Run();

// ---------- Helpers ----------

static string GetConnectionString(IConfiguration configuration) =>
    configuration.GetConnectionString("SafeVault")
    ?? throw new InvalidOperationException("Connection string 'SafeVault' is missing.");

// Creates the first admin only when SeedAdmin__Password is set (environment variable),
// so no admin password is ever stored in the repository.
static async Task SeedAdminAsync(WebApplication app)
{
    var password = app.Configuration["SeedAdmin:Password"];
    if (string.IsNullOrEmpty(password))
        return;

    using var scope = app.Services.CreateScope();
    var auth = scope.ServiceProvider.GetRequiredService<AuthService>();

    // Fails silently if the admin already exists, which is fine on restarts.
    await auth.RegisterAsync("admin", "admin@safevault.local", password, Roles.Admin);
}

// Lets the test project start the API in memory (WebApplicationFactory<Program>).
public partial class Program { }
