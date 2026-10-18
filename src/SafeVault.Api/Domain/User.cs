namespace SafeVault.Api.Domain;

public sealed record User
{
    public int Id { get; init; }
    public required string Username { get; init; }
    public required string Email { get; init; }

    // Never the real password: only the salted hash produced by PasswordHasher.
    public required string PasswordHash { get; init; }

    public required string Role { get; init; }
}
