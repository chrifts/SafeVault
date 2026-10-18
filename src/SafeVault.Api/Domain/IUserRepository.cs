namespace SafeVault.Api.Domain;

public interface IUserRepository
{
    Task<User?> FindByUsernameAsync(string username);

    // Returns false when the username or email already exists.
    Task<bool> AddAsync(User user);

    Task<IReadOnlyList<User>> GetAllAsync();
}
