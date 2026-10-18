using Microsoft.Data.Sqlite;
using SafeVault.Api.Domain;

namespace SafeVault.Api.Infrastructure;

// Every query here is parameterized: values travel separately from the SQL text,
// so input like "' OR 1=1 --" is treated as plain data and can never change the query.
// Never build SQL with string concatenation or interpolation.
public sealed class SqliteUserRepository(string connectionString) : IUserRepository
{
    private const int SqliteConstraintError = 19;

    public async Task<User?> FindByUsernameAsync(string username)
    {
        await using var connection = await OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT UserID, Username, Email, PasswordHash, Role FROM Users WHERE Username = $username";
        command.Parameters.AddWithValue("$username", username);

        await using var reader = await command.ExecuteReaderAsync();
        return await reader.ReadAsync() ? Map(reader) : null;
    }

    public async Task<bool> AddAsync(User user)
    {
        await using var connection = await OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($username, $email, $passwordHash, $role)
            """;
        command.Parameters.AddWithValue("$username", user.Username);
        command.Parameters.AddWithValue("$email", user.Email);
        command.Parameters.AddWithValue("$passwordHash", user.PasswordHash);
        command.Parameters.AddWithValue("$role", user.Role);

        try
        {
            await command.ExecuteNonQueryAsync();
            return true;
        }
        // UNIQUE constraint hit: username or email is already taken.
        // "& 0xFF" keeps the primary code, so it also matches extended codes like 2067.
        catch (SqliteException ex) when ((ex.SqliteErrorCode & 0xFF) == SqliteConstraintError)
        {
            return false;
        }
    }

    public async Task<IReadOnlyList<User>> GetAllAsync()
    {
        await using var connection = await OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT UserID, Username, Email, PasswordHash, Role FROM Users ORDER BY Username";

        var users = new List<User>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            users.Add(Map(reader));
        }

        return users;
    }

    private async Task<SqliteConnection> OpenAsync()
    {
        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        return connection;
    }

    private static User Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt32(0),
        Username = reader.GetString(1),
        Email = reader.GetString(2),
        PasswordHash = reader.GetString(3),
        Role = reader.GetString(4),
    };
}
