using Infraestructure.Contexts;
using LearningCenter.Domain.IAM;
using LearningCenter.Domain.IAM.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualBasic;

namespace LearningCenter.Infraestructure.IAM.Persistence;

public class UserRepository : IUserRepository
{
    private readonly AgroSolutionsContext _agroSolutionsContext;

    public UserRepository(AgroSolutionsContext agroSolutionsContext)
    {
        _agroSolutionsContext = agroSolutionsContext;
    }
    
    public async Task<int> RegisterAsync(User user)
    {
        _agroSolutionsContext.Users.Add(user);
        await _agroSolutionsContext.SaveChangesAsync();
        
        return user.Id;
    }

    public async Task<User?> GetUserByUserNameAsync(string username)
    {
       var user = await _agroSolutionsContext.Users.FirstOrDefaultAsync(x => x.Username == username && x.IsActive);
       return user;
    }

    public async Task<User?> GetUserByIdAsync(int id)
    {
        var user = await _agroSolutionsContext.Users.FirstOrDefaultAsync(x => x.Id == id && x.IsActive);
        return user;
    }
    
    public async Task<List<User>> GetUserAllAsync()
    {
        var result = await _agroSolutionsContext.Users.Where(t => t.IsActive).ToListAsync();
        return result;
    }

    public async Task<List<User>> GetUserRoleSearchAsync(string role)
    {
        var result = await _agroSolutionsContext.Users.Where(x => x.IsActive && x.Role == role).ToListAsync();
        return result;
    }

    public async Task<User> GetUserByCompanyNameAsync(string companyName)
    {
        return await _agroSolutionsContext.Users
            .Where(x => x.CompanyName == companyName && x.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<User> GetUserByDniOrRucAsync(string dniOrRucruc)
    {
        return await _agroSolutionsContext.Users
            .Where(x => x.DniOrRuc == dniOrRucruc && x.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<bool> DeleteUserAsync(int id)
    {
        var exitingAccount = await _agroSolutionsContext.Users.FirstOrDefaultAsync(t => t.Id == id);
        if (exitingAccount != null)
        {
            exitingAccount.IsActive = false;
            _agroSolutionsContext.Users.Update(exitingAccount);
            await _agroSolutionsContext.SaveChangesAsync();
            return true;
        }
        return false;
    }    
}