using SafeVault.Api.Security;

namespace SafeVault.Tests;

public class InputValidatorTests
{
    [TestCase("' OR '1'='1")]
    [TestCase("admin'; DROP TABLE Users; --")]
    [TestCase("<script>alert('xss')</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("admin\n")]
    [TestCase("ab")]
    [TestCase("")]
    [TestCase(null)]
    public void IsValidUsername_RejectsMaliciousOrMalformedInput(string? username)
    {
        Assert.That(InputValidator.IsValidUsername(username), Is.False);
    }

    [Test]
    public void IsValidUsername_AcceptsLettersAndNumbers()
    {
        Assert.That(InputValidator.IsValidUsername("alice123"), Is.True);
    }

    [TestCase("\"<script>alert(1)</script>\"@mail.com")]
    [TestCase("user@mail.com'; DROP TABLE Users; --")]
    [TestCase("not-an-email")]
    public void IsValidEmail_RejectsMaliciousOrMalformedInput(string email)
    {
        Assert.That(InputValidator.IsValidEmail(email), Is.False);
    }

    [Test]
    public void IsValidEmail_AcceptsNormalEmail()
    {
        Assert.That(InputValidator.IsValidEmail("alice@mail.com"), Is.True);
    }

    [TestCase("short1A")]      // too short
    [TestCase("alllowercase1")] // no upper case
    [TestCase("NoDigitsHere")]  // no digit
    public void IsStrongPassword_RejectsWeakPasswords(string password)
    {
        Assert.That(InputValidator.IsStrongPassword(password), Is.False);
    }

    [Test]
    public void IsStrongPassword_AcceptsStrongPassword()
    {
        Assert.That(InputValidator.IsStrongPassword("Passw0rd!"), Is.True);
    }
}
