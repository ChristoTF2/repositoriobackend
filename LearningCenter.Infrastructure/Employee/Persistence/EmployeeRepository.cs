using Microsoft.EntityFrameworkCore;
using Shared;
using Domain;
using Infraestructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infraestructure;


public class EmployeeRepository : IEmployeeRepository
{
    private readonly AgroSolutionsContext _agroSolutionsContext;

    public EmployeeRepository(AgroSolutionsContext agroSolutionsContext)
    {
        _agroSolutionsContext = agroSolutionsContext;
    }
    
    public async Task<List<Employee>> GetAllEmployeesAsync()
    {
        var result = await _agroSolutionsContext.Employees.Where(t => t.IsActive).ToListAsync();
        return result;
    }
    public async Task<Employee> GetByIdEmployeeAsync(int id)
    {
        return await  _agroSolutionsContext.Employees
            .Where(t => t.Id == id && t.IsActive)
            .FirstOrDefaultAsync();
    }
    public async Task<Employee> GetByDniEmployeeAsync(string dni)
    {
        return await  _agroSolutionsContext.Employees
            .Where(t => t.Dni == dni && t.IsActive)
            .FirstOrDefaultAsync();    
    }
    public async Task<Employee> GetByTeamIdAdviserEmployeeAsync(int iTeamId)
    {
        return await _agroSolutionsContext.Employees
            .Where(t => t.TeamId == iTeamId && t.IsActive && t.Job == "Adviser")
            .FirstOrDefaultAsync();
    }
    public async Task<List<Employee>> GetByJobAndTeamEmployeeAsync(string? job, int teamId)
    {
        job = Constants.ToUpperFirstLetter(job);

        var result = await _agroSolutionsContext.Employees
            .Where(t => t.IsActive &&
                        (string.IsNullOrEmpty(job) || t.Job == job) && t.TeamId == teamId)
            .ToListAsync();

        return result;
    }

    public async Task<List<Employee>> GetByJobEmployeSearcheAsync(string? job)
    {
        var result = await _agroSolutionsContext.Employees.Where(t =>  t.Job == job &&t.IsActive).ToListAsync();
        return result;
    }
    
    public  async Task<int> SaveEmployeeAsync(Employee dataEmployee)
    {
        using (var transaction = await _agroSolutionsContext.Database.BeginTransactionAsync())
        {
            try
            {
                dataEmployee.IsActive = true;
                _agroSolutionsContext.Employees.Add(dataEmployee);
                await _agroSolutionsContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }
        return dataEmployee.Id;
    }

    public async Task<bool> DeleteEmployeeAsync(int id)
    {
        var exitingEmployee = await _agroSolutionsContext.Employees.FirstOrDefaultAsync(t => t.Id == id);
        if (exitingEmployee != null)
        {
            exitingEmployee.IsActive = false;
            _agroSolutionsContext.Employees.Update(exitingEmployee);
            await _agroSolutionsContext.SaveChangesAsync();
            return true;
        }
        return false;
    }
}