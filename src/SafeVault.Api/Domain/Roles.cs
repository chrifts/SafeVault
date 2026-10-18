namespace SafeVault.Api.Domain;

// Constants instead of magic strings, so a typo in a role name fails at compile time.
public static class Roles
{
    public const string Admin = "Admin";
    public const string User = "User";
}
