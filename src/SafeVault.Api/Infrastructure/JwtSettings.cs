using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SafeVault.Api.Infrastructure;

public sealed class JwtSettings
{
    public const string SectionName = "Jwt";

    // No default on purpose: the key must come from an environment variable or user secrets,
    // never from source code or appsettings.json in a public repo.
    public string Key { get; set; } = string.Empty;
    public string Issuer { get; set; } = "SafeVault";
    public string Audience { get; set; } = "SafeVault";

    // Short-lived tokens limit the damage if one is stolen (JWTs can't be revoked).
    public int ExpiresMinutes { get; set; } = 15;

    public SymmetricSecurityKey GetSigningKey()
    {
        // HS256 needs at least 256 bits (32 bytes). A short key is easy to brute force.
        if (Encoding.UTF8.GetByteCount(Key) < 32)
        {
            throw new InvalidOperationException(
                "Jwt:Key is missing or shorter than 32 bytes. Set it with the Jwt__Key environment variable.");
        }

        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key));
    }
}
