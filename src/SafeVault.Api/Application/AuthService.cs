using Microsoft.AspNetCore.Identity;
using SafeVault.Api.Domain;
using SafeVault.Api.Infrastructure;
using SafeVault.Api.Security;

namespace SafeVault.Api.Application;

public sealed record AuthResult(bool Succeeded, string? Error = null)
{
    public static AuthResult Ok() => new(true);
    public static AuthResult Fail(string error) => new(false, error);
}

public sealed class AuthService(
    IUserRepository users,
    IPasswordHasher<User> passwordHasher,
    JwtTokenService tokens)
{
    // The public register endpoint never passes a role, so self-registered users are
    // always "User". Only trusted code (the admin seeder, tests) can create an Admin.
    public async Task<AuthResult> RegisterAsync(
        string username, string email, string password, string role = Roles.User)
    {
        if (!InputValidator.IsValidUsername(username))
            return AuthResult.Fail("Username must be 3-30 letters or numbers.");

        if (!InputValidator.IsValidEmail(email))
            return AuthResult.Fail("Email format is not valid.");

        if (!InputValidator.IsStrongPassword(password))
            return AuthResult.Fail("Password needs 8+ characters with upper case, lower case and a digit.");

        var user = new User { Username = username, Email = email, Role = role, PasswordHash = string.Empty };

        // PasswordHasher uses PBKDF2 with a random salt, so equal passwords get different hashes
        // and a leaked database does not reveal the real passwords.
        user = user with { PasswordHash = passwordHasher.HashPassword(user, password) };

        return await users.AddAsync(user)
            ? AuthResult.Ok()
            : AuthResult.Fail("Username or email is already registered.");
    }

    // Returns null for both "unknown user" and "wrong password" on purpose,
    // so attackers can't use the login to find out which usernames exist.
    public async Task<string?> LoginAsync(string username, string password)
    {
        if (!InputValidator.IsValidUsername(username) || string.IsNullOrEmpty(password))
            return null;

        var user = await users.FindByUsernameAsync(username);
        if (user is null)
            return null;

        var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

        return result == PasswordVerificationResult.Failed ? null : tokens.CreateToken(user);
    }
}
