namespace SafeVault.Api.Application;

public sealed record RegisterRequest(string Username, string Email, string Password);

public sealed record LoginRequest(string Username, string Password);
