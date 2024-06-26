using _1_API.Response;
using Domain;
using Infraestructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infraestructure;

public class CropRepository : ICropRepository
{
    private readonly AgroSolutionsContext _agrosolutionContext;

    public CropRepository(AgroSolutionsContext agrosolutionContext)
    {
        _agrosolutionContext = agrosolutionContext;
    }
    
    public async Task<List<Crop>> GetAllCultivosAsync()
    {
        return await _agrosolutionContext.Crops
            .Include(c => c.Calendars)
            .ToListAsync();
    }

  
    public async Task<Crop> GetCultivoByIdAsync(int id)
    {
        return await _agrosolutionContext.Crops
            .Include(c => c.Calendars)
            .FirstOrDefaultAsync(c => c.Id == id);
    }


    public async Task<List<Adviser>> GetAllAsesoresAsync()
    {
        return await _agrosolutionContext.Advisers.ToListAsync();
    }


    public async Task<Adviser> GetAsesorByIdAsync(int id)
    {
        return await _agrosolutionContext.Advisers
            .FirstOrDefaultAsync(a => a.Id == id);
    }
    
    public async Task<Calendar> GetCalendarioByIdAsync(int id)
    {
        return await _agrosolutionContext.Calendars
            .FirstOrDefaultAsync(d => d.Id == id);
    }
    
    public async Task<List<Calendar>> GetAllCalendariosForCultivoAsync(int cultivoId)
    {
        var cultivo = await _agrosolutionContext.Crops
            .Include(c => c.Calendars)
            .FirstOrDefaultAsync(c => c.Id == cultivoId);

        return cultivo?.Calendars ?? new List<Calendar>();
    }
    public async Task<int> SaveCalendarAsync(Calendar calendar)
    {
        using (var transaction = await _agrosolutionContext.Database.BeginTransactionAsync())
        {
            try
            {
                _agrosolutionContext.Calendars.Add(calendar); 
                await _agrosolutionContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }


        return calendar.Id;
    }

    public async Task<int> SaveCropsAsync(Crop crop)
    {
        using (var transaction = await _agrosolutionContext.Database.BeginTransactionAsync())
        {
            try
            {
                _agrosolutionContext.Crops.Add(crop); 
                await _agrosolutionContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }


        return crop.Id;
    }

    public async Task<int> SaveAdviserAsync(Adviser adviser)
    {
        using (var transaction = await _agrosolutionContext.Database.BeginTransactionAsync())
        {
            try
            {
                _agrosolutionContext.Advisers.Add(adviser); 
                await _agrosolutionContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }


        return adviser.Id;
    }

}