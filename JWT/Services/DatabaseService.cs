using System.Data;
using System.Data.SqlClient;
using JWT.Controllers;
using Microsoft.Data.Sqlite;

namespace WebApp.Services;

public interface IDatabaseService
{
    Task<bool> IsUnique(string username);
    Task<int> InsertNewUser(User user);
    Task<string> GetUserHash(string username);
}

public class DatabaseService : IDatabaseService
{
    private readonly IConfiguration _config;

    public DatabaseService(IConfiguration config)
    {
        _config = config;
    }

    private async Task<SqliteConnection> GetConnection()
    {
        var connection = new SqliteConnection("Data Source=example-db.db");
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync();
        }

        return connection;
    }

    public async Task<bool> IsUnique(string username)
    {
        await using var connection = await GetConnection();

        var command = connection.CreateCommand();
        command.CommandText = @"SELECT 1 FROM User WHERE username = @1";
        command.Parameters.AddWithValue("@1", username);

        var reader = await command.ExecuteReaderAsync();

        return !reader.HasRows;
        
    }

    public async Task<int> InsertNewUser(User user)
    {
        await using var connection = await GetConnection();

        var command = connection.CreateCommand();
        command.CommandText = @"INSERT INTO User VALUES(@1, @2)";
        command.Parameters.AddWithValue("@1", user.Name);
        command.Parameters.AddWithValue("@2", user.Password);

        var rowsAffected = await command.ExecuteNonQueryAsync();

        return rowsAffected;
    }

    public async Task<string> GetUserHash(string username)
    {
        await using var connection = await GetConnection();

        var command = connection.CreateCommand();
        command.CommandText = @"SELECT password FROM USER WHERE username=@1";
        command.Parameters.AddWithValue("@1", username);

        var reader = await command.ExecuteReaderAsync();
        await reader.ReadAsync();

        return reader.GetString("password");
    }
}