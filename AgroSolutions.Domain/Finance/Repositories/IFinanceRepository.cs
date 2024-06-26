using Domain;

namespace Domain;

public interface IFinanceRepository
{
    Task<List<Finance>> GetAllAsync();
    Task<List<Finance>> GetSearchAsync(string name);

    Task<Finance> GetById(int id);

    Task<Finance> GetByMonthAsync(string name);

    Task<int> SaveAsync(Finance data);

    Task<bool> Update(Finance data, int id);

    Task<bool> Delete(int id);
}