# SafeVault

SafeVault is a small ASP.NET Core 8 API that manages user accounts. It was built as the capstone project for the secure coding course, and it covers:

- Input validation and SQL injection prevention
- Authentication (hashed passwords + JWT) and role-based authorization (RBAC)
- Debugging and fixing SQL injection and XSS vulnerabilities
- Automated security tests (NUnit), run on every push with GitHub Actions

## Project structure

```
src/SafeVault.Api/
  Domain/           User, Roles, IUserRepository
  Application/      AuthService (register / login)
  Infrastructure/   SQLite repository (parameterized queries), JWT token service
  Security/         InputValidator (whitelist validation)
  wwwroot/          Simple register/login page
  Program.cs        DI, JWT validation, RBAC policy, endpoints, security headers
tests/SafeVault.Tests/
  InputValidatorTests   Malicious and malformed input is rejected
  SqlInjectionTests     Injection payloads can't change the SQL query
  AuthServiceTests      Passwords are hashed, login works only with the right password
  ApiSecurityTests      401 / 403 / 200 per role, forged JWT rejected, XSS output encoded
```

## Endpoints

| Method | Route | Access |
|---|---|---|
| POST | `/api/auth/register` | Public (always creates a `User`) |
| POST | `/api/auth/login` | Public, returns a JWT |
| GET | `/api/users/me` | Any authenticated user |
| GET | `/api/admin/dashboard` | `Admin` role only |
| GET | `/welcome?name=...` | Public, HTML output encoded |

## How to run

The JWT key is never stored in the repo, so it has to be set as an environment variable (at least 32 characters).

```bash
# Linux / macOS
export Jwt__Key="replace-with-a-long-random-secret-of-32-chars-or-more"
export SeedAdmin__Password="Adm1nPassw0rd"   # optional: creates the first admin user
dotnet run --project src/SafeVault.Api
```

```powershell
# Windows PowerShell
$env:Jwt__Key = "replace-with-a-long-random-secret-of-32-chars-or-more"
$env:SeedAdmin__Password = "Adm1nPassw0rd"
dotnet run --project src/SafeVault.Api
```

Run the tests (no environment variables needed):

```bash
dotnet test
```

## Security summary

### Vulnerabilities identified and fixes applied

**1. SQL injection in user queries**

The original lookup built the SQL by concatenating user input:

```csharp
// Vulnerable
command.CommandText = $"SELECT * FROM Users WHERE Username = '{username}'";
```

The input `' OR '1'='1` turned the query into `WHERE Username = '' OR '1'='1'`, which returns every user, and `x'; DROP TABLE Users; --` could delete data.

*Fix:* all queries in `SqliteUserRepository` now use parameters, so the input is always treated as data and never as SQL:

```csharp
command.CommandText = "SELECT ... FROM Users WHERE Username = $username";
command.Parameters.AddWithValue("$username", username);
```

On top of that, `InputValidator` only accepts letters and numbers in usernames (whitelist), as a first layer of defense.

**2. Cross-site scripting (XSS)**

The welcome page inserted the `name` query parameter straight into HTML, so `<script>alert('xss')</script>` ran in the browser. The front end also used `innerHTML` to show server messages.

*Fix:*
- Output is encoded with `HtmlEncoder` before it goes into HTML (`<script>` becomes `&lt;script&gt;`).
- The front end uses `textContent` instead of `innerHTML`.
- Malicious usernames and emails are rejected at registration, so they are never stored.
- A `Content-Security-Policy: default-src 'self'` header blocks inline scripts as a last line of defense.

**3. Plain-text passwords**

*Fix:* passwords are hashed with ASP.NET Identity's `PasswordHasher` (PBKDF2 with a random salt). The hash is never returned by any endpoint.

**4. Broken access control**

The admin dashboard was reachable by any logged-in user, and the register endpoint allowed sending a role, so anyone could sign up as `Admin`.

*Fix:*
- The `AdminOnly` policy (`RequireRole("Admin")`) protects `/api/admin/dashboard`.
- The register endpoint no longer accepts a role: new accounts are always `User`. The first admin is created only from a server-side environment variable.

**5. Weak token handling**

*Fix:*
- JWTs are validated for signature, issuer, audience and expiry, with a 30-second clock skew.
- Tokens last 15 minutes.
- The signing key comes from an environment variable, and the app refuses to start if the key is missing or shorter than 32 bytes.
- The front end keeps the token in memory, not in `localStorage`.

**6. User enumeration on login**

*Fix:* login returns the same `401` for "unknown user" and "wrong password", so attackers can't find out which usernames exist.

### Tests

The tests in `tests/SafeVault.Tests` simulate real attacks:

- SQL injection payloads against the repository (bypassing validation on purpose)
- XSS payloads against the validator and the HTML endpoint
- Requests with no token (401), with a `User` token on an admin route (403), with an `Admin` token (200), and with a forged `Admin` token signed with another key (401)

They run on every push with GitHub Actions (see the **Actions** tab of the repository).

### How Copilot assisted in the debugging process

I used GitHub Copilot Chat in VS Code in all three activities. These are the main prompts I used (paraphrased) and what I did with each answer.

**1. Input validation and SQL injection prevention**

> *"Review this method that finds a user by username. Is it vulnerable to SQL injection? Show me an example attack and a safe version."*

Copilot showed that `' OR '1'='1` turns the concatenated query into one that returns every user, and rewrote it with a parameter (`$username`). I then applied the same pattern to every query in `SqliteUserRepository`.

> *"Write a C# validator for username, email and password that uses a whitelist instead of a blacklist."*

This became the base of `InputValidator`: usernames accept only letters and numbers, and the email pattern rejects `<`, `>`, quotes and `;`.

**2. Authentication and authorization (RBAC)**

> *"Add register and login to this ASP.NET Core minimal API. Store passwords securely and return a JWT that includes the user's role."*

Copilot suggested ASP.NET Identity's `PasswordHasher` (PBKDF2 with a random salt) and the JWT setup: a signed token, with the issuer, audience and expiry checked on every request.

> *"Make /api/admin/dashboard accessible only to users with the Admin role."*

It added the `AdminOnly` policy (`RequireRole("Admin")`), so a `User` token gets a 403.

**3. Finding and fixing the vulnerabilities**

> *"Find the security vulnerabilities in this code and explain how each one could be exploited."* (on the welcome endpoint and `app.js`)

Copilot flagged the unencoded `name` parameter and the use of `innerHTML`. The fixes were `HtmlEncoder` on the server and `textContent` on the front end. When I asked how to add another layer against XSS, it suggested the `Content-Security-Policy` header.

**4. Security tests**

> *"Generate NUnit tests that send SQL injection and XSS payloads to these methods, and tests that check the API returns 401 without a token and 403 with the wrong role."*

Copilot generated the attack payloads and the 401/403 checks. I added the forged `Admin` token test (signed with a different key) and the trailing-newline username case.

**What I didn't accept as-is**

- The first regex used `^...$`. In .NET, `$` also matches before a final newline, so `"admin\n"` passed validation. I changed it to `\A...\z` and added a test for that case.
- The first register request had a `role` field, which let anyone sign up as `Admin`. I removed it: public sign-ups are always `User`, and the first admin is created from a server-side environment variable.
