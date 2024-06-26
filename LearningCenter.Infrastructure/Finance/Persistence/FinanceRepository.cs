using Domain;
using Infraestructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infraestructure;

public class FinanceRepository : IFinanceRepository
{
    private readonly AgroSolutionsContext _agroSolutionsContext;

    public FinanceRepository(AgroSolutionsContext agroSolutionsContext)
    {
        _agroSolutionsContext = agroSolutionsContext;
    }

    public async Task<List<Finance>> GetAllAsync()
    {
        // COnecta BBDD MySQL
        var result = await _agroSolutionsContext.Finances
            .Where(t => t.IsActive)
            .ToListAsync();

        return result;
    }

    public async Task<List<Finance>> GetSearchAsync(string name)
    {
        var result = await _agroSolutionsContext.Finances
            .Where(t => t.IsActive && t.Month.Contains(name)).ToListAsync();; //1000 Reigtros

        return result;
    }

    public async Task<Finance> GetById(int id)
    {
        return await _agroSolutionsContext.Finances
            .SingleOrDefaultAsync(t => t.Id == id && t.IsActive);
    }

    public async Task<Finance> GetByMonthAsync(string month)
    {
        return await _agroSolutionsContext.Finances.Where(t => t.Month == month && t.IsActive).FirstOrDefaultAsync();
    }

    public async Task<int> SaveAsync(Finance data)
    {
        using (var transaction = await _agroSolutionsContext.Database.BeginTransactionAsync())
        {
            try
            {
                data.IsActive = true;
                _agroSolutionsContext.Finances.Add(data); 
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

    public async Task<bool> Update(Finance data, int id)
    {
        if (float.Parse(data.Incomes) < 0)
        {
            throw new ArgumentException("Incomes cannot be negative");
        }

        if (double.Parse(data.Bills) < 0)
        {
            throw new ArgumentException("Bills cannot be negative");
        }

        var exitingFinance = _agroSolutionsContext.Finances.Where(t => t.Id == id).FirstOrDefault();
        if (exitingFinance == null)
        {
            return false;
        }

        exitingFinance.Month = data.Month;
        exitingFinance.Incomes = data.Incomes;
        exitingFinance.Bills = data.Bills;
        exitingFinance.Earning = data.Earning;

        _agroSolutionsContext.Finances.Update(exitingFinance);

        await _agroSolutionsContext.SaveChangesAsync();
        return true;
    }


    public async Task<bool>  Delete(int id)
    {
        var exitingFinance = _agroSolutionsContext.Finances.Where(t => t.Id == id).FirstOrDefault();

        exitingFinance.IsActive = false;

        _agroSolutionsContext.Finances.Update(exitingFinance);

        await _agroSolutionsContext.SaveChangesAsync();
        return true;
    }
}