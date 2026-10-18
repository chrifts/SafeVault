using System.Text.RegularExpressions;

namespace SafeVault.Api.Security;

// Whitelist validation: we only accept known-safe characters instead of trying
// to block every dangerous pattern (blacklists always miss something).
// This is the first layer against SQL injection and XSS, not the only one.
public static partial class InputValidator
{
    public static bool IsValidUsername(string? username) =>
        !string.IsNullOrEmpty(username) && UsernameRegex().IsMatch(username);

    public static bool IsValidEmail(string? email) =>
        !string.IsNullOrEmpty(email) && email.Length <= 254 && EmailRegex().IsMatch(email);

    public static bool IsStrongPassword(string? password) =>
        password is { Length: >= 8 and <= 128 }
        && password.Any(char.IsUpper)
        && password.Any(char.IsLower)
        && password.Any(char.IsDigit);

    // \A and \z (not ^ and $) so a trailing newline like "admin\n" is rejected too.
    [GeneratedRegex(@"\A[a-zA-Z0-9]{3,30}\z")]
    private static partial Regex UsernameRegex();

    // Blocks characters used in HTML/SQL payloads: < > " ' ` ; and whitespace.
    [GeneratedRegex(@"\A[^@\s<>""'`;]+@[^@\s<>""'`;]+\.[a-zA-Z]{2,}\z")]
    private static partial Regex EmailRegex();
}
