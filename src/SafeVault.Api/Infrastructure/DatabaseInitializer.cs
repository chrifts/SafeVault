using Microsoft.Data.Sqlite;

namespace SafeVault.Api.Infrastructure;

public static class DatabaseInitializer
{
    // Safe to call on every startup: it only creates the table if it is missing.
    public static void EnsureCreated(string connectionString)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        using var command = connection.CreateCommand();

        // COLLATE NOCASE: "Alice" and "alice" are the same user,
        // so nobody can register a look-alike account.
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID       INTEGER PRIMARY KEY AUTOINCREMENT,
                Username     TEXT NOT NULL COLLATE NOCASE UNIQUE,
                Email        TEXT NOT NULL COLLATE NOCASE UNIQUE,
                PasswordHash TEXT NOT NULL,
                Role         TEXT NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }
}
