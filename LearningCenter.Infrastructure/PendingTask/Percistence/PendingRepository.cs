using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Shared;
using Domain;
using Infraestructure.Contexts;
using Microsoft.AspNetCore.Http;
using Shared;

namespace Infrastructure;

public class PendingRepository : IPendingRepository
{
    private readonly AgroSolutionsContext _agroSolutionsContext;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public PendingRepository(AgroSolutionsContext agroSolutionsContext, IHttpContextAccessor httpContextAccessor)
    {
        _agroSolutionsContext = agroSolutionsContext;
        _httpContextAccessor = httpContextAccessor;
    }
    
    public async Task<List<Pending>> GetAllPendingAsync()
    {
        var result = await _agroSolutionsContext.Pendings.Where(t => t.IsActive).ToListAsync();
        return result;
    }
    
    public async Task<List<Pending>> GetPendingSearchAsync(string? priority, string? category, string? stateOfTask)
    {
        priority = Constants.ToUpperFirstLetter(priority);
        category = Constants.ToUpperFirstLetter(category);
        stateOfTask = Constants.ToUpperFirstLetter(stateOfTask);

        var result = await _agroSolutionsContext.Pendings
            .Where(t =>
                t.IsActive &&
                (string.IsNullOrEmpty(priority) || t.Priority == priority) &&
                (string.IsNullOrEmpty(category) || t.Category == category) &&
                (string.IsNullOrEmpty(stateOfTask) || t.State == stateOfTask))
            .ToListAsync();

        return result;
    }

    public async Task<Pending> GetByIdPendingAsync(int id)
    {
        return await _agroSolutionsContext.Pendings
            .Where(t => t.Id == id && t.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<Pending> GetByNamePendingAsync(string name)
    {
        return await _agroSolutionsContext.Pendings
            .Where(t => t.Name == name && t.IsActive)
            .FirstOrDefaultAsync();    
    }

    public async Task<int> SavePendingAsync(Pending dataPending)
    {
        using (var transaction = await _agroSolutionsContext.Database.BeginTransactionAsync())
        {
            try
            {
               //var userId = GetUserIdFromHttpContext();
               //var userId = GetUserIdFromHttpContext();
                dataPending.IsActive = true;
                _agroSolutionsContext.Pendings.Add(dataPending); 
                await _agroSolutionsContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }
        return dataPending.Id;
        
    }

    public async Task<bool> UpdatePendingAsync(Pending dataPending, int id)
    {
        var existingPendings = _agroSolutionsContext.Pendings
            .Where(t => t.Id == id).FirstOrDefault();

        if (existingPendings != null)
        {
            existingPendings.Description = dataPending.Description;
            existingPendings.DueDate = dataPending.DueDate;
            existingPendings.AssignedTo = dataPending.AssignedTo;
            existingPendings.AssignedTo = dataPending.AssignedTo;
            existingPendings.AssignedTo = dataPending.AssignedTo;
            existingPendings.State = dataPending.State;
            existingPendings.UpdatedDate = DateTime.UtcNow;

            _agroSolutionsContext.Pendings.Update(existingPendings);

            await _agroSolutionsContext.SaveChangesAsync();
            return true;
        }
        return false;
    }

    public async Task<bool> DeletePendingAsync(int id)
    {
        var exitingPendings = await _agroSolutionsContext.Pendings.FirstOrDefaultAsync(t => t.Id == id);
        
        if (exitingPendings != null)
        {
            // _learningCenterContext.Tutorials.Remove(exitingTutorial);
            exitingPendings.IsActive= false;

            _agroSolutionsContext.Pendings.Update(exitingPendings);
            await _agroSolutionsContext.SaveChangesAsync();
            return true;
        }

        return false;    }
}