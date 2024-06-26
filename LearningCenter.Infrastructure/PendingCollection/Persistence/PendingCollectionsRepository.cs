using Domain;
using Infraestructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infraestructure;

public class PendingCollectionsRepository : IPendingCollectionsRepository
{
    private readonly AgroSolutionsContext _agroSolutionsContext;

    public PendingCollectionsRepository(AgroSolutionsContext agroSolutionsContext)
    {
        _agroSolutionsContext = agroSolutionsContext;
    }

    public async Task<List<PendingCollections>> GetAllAsync()
    {
        // COnecta BBDD MySQL
        var result = await _agroSolutionsContext.PendingCollectionsCollections
            .Where(t => t.IsActive)
            .ToListAsync();

        return result;
    }

    public async Task<List<PendingCollections>> GetSearchAsync(string name)
    {
        var result = await _agroSolutionsContext.PendingCollectionsCollections
            .Where(t => t.IsActive && t.Type.Contains(name)).ToListAsync();; //1000 Reigtros
        
        return result;
    }

    public async Task<PendingCollections> GetById(int id)
    {
        return await _agroSolutionsContext.PendingCollectionsCollections
            .SingleOrDefaultAsync(t => t.Id == id && t.IsActive);
    }

    public async Task<PendingCollections> GetByTypeAsync(string name)
    {
        return await _agroSolutionsContext.PendingCollectionsCollections.Where(t => t.Type == name && t.IsActive).FirstOrDefaultAsync();
    }

    public async Task<int> SaveAsync(PendingCollections data)
    {
        using (var transaction = await _agroSolutionsContext.Database.BeginTransactionAsync())
        {
            try
            {
                data.IsActive = true;
                _agroSolutionsContext.PendingCollectionsCollections.Add(data); //no se refleja en BBDD
                await _agroSolutionsContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }


        return data.Id;
    }

    public async Task<bool> Update(PendingCollections data, int id)
    {
        var exitingPendingCollections = _agroSolutionsContext.PendingCollectionsCollections.Where(t => t.Id == id).FirstOrDefault();
        exitingPendingCollections.Type = data.Type;
        exitingPendingCollections.Cost = data.Cost;
        exitingPendingCollections.Description = data.Description;
        

        _agroSolutionsContext.PendingCollectionsCollections.Update(exitingPendingCollections);

        await _agroSolutionsContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool>  Delete(int id)
    {
        var exitingFinance = _agroSolutionsContext.PendingCollectionsCollections.Where(t => t.Id == id).FirstOrDefault();

        // _agroSolutionsContext.Finances.Remove(exitingFinance);
        exitingFinance.IsActive = false;

        _agroSolutionsContext.PendingCollectionsCollections.Update(exitingFinance);

        await _agroSolutionsContext.SaveChangesAsync();
        return true;
    }
}