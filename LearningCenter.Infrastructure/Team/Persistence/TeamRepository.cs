using Microsoft.EntityFrameworkCore;
using Domain;
using Infraestructure.Contexts;


namespace Infrastructure;

public class TeamRepository : ITeamRepository
{
    private readonly AgroSolutionsContext _agroSolutionsContext;

    public TeamRepository(AgroSolutionsContext agroSolutionsContext)
    {
        _agroSolutionsContext = agroSolutionsContext;
    }

    public async Task<List<Team>> GetAllTeamAsync()
    {
        var result = await _agroSolutionsContext.Teams.Where(t => t.IsActive).Include(t => t.Advicers)
            .Include(t => t.Producers).ToListAsync();    
        return result;
    }

    public async Task<Team> GetByIdTeamAsync(int id)
    {
        return await   _agroSolutionsContext.Teams.Where(t => t.Id == id && t.IsActive).Include(t => t.Advicers)
            .Include(t => t.Producers).FirstOrDefaultAsync();
       
    }

    public async Task<Team> GetByTeamCodeAsync(string teamCode)
    {
        return await  _agroSolutionsContext.Teams
            .Where(t => t.TeamCode == teamCode && t.IsActive)
            .FirstOrDefaultAsync();    
    }

    public async Task<Team> GetByCropCodeAsync(string cropCode)
    {
        return await  _agroSolutionsContext.Teams
            .Where(t => t.CropCode == cropCode && t.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<Advicer> GetByNameAdvicerAsync(string name)
    {
        return await _agroSolutionsContext.Advicers
            .Where(t => t.Name == name && t.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<Producer> GetByNameProducerAsync(string name)
    {
        return await _agroSolutionsContext.Producers
            .Where(t => t.Name == name && t.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<Advicer> GetByDniAdvicerAsync(string dni)
    {
        return await _agroSolutionsContext.Advicers
            .Where(t => t.Dni == dni && t.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<Producer> GetByDniProducerAsync(string dni)
    {
        return await _agroSolutionsContext.Producers
            .Where(t => t.Dni == dni && t.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<int> SaveTeamAsync(Team dataTeam)
    {
        using (var transaction = await _agroSolutionsContext.Database.BeginTransactionAsync())
        {
            try
            {
                dataTeam.IsActive = true;
                _agroSolutionsContext.Teams.Add(dataTeam);
                await _agroSolutionsContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }
        return dataTeam.Id;
    }

    public async Task<bool> DeleteTeamAsync(int id)
    {
        var exitingTeam = await _agroSolutionsContext.Teams.FirstOrDefaultAsync(t => t.Id == id);
        
        if (exitingTeam != null)
        {
            // _learningCenterContext.Tutorials.Remove(exitingTutorial);
            exitingTeam.IsActive = false;

            _agroSolutionsContext.Teams.Update(exitingTeam);
            await _agroSolutionsContext.SaveChangesAsync();
            return true;
        }

        return false;
        
    }
}