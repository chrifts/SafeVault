using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Domain;

namespace SafeVault.Api.Infrastructure;

public sealed class JwtTokenService(IOptions<JwtSettings> options)
{
    private readonly JwtSettings _settings = options.Value;

    public string CreateToken(User user)
    {
        // Only the minimum claims needed for authorization. The payload is just
        // Base64, anyone can read it, so no emails or other personal data here.
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role),
        };

        var credentials = new SigningCredentials(_settings.GetSigningKey(), SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_settings.ExpiresMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
