namespace Domain;

public interface IPendingRepository
{
    Task<List<Pending>> GetAllPendingAsync();
    
    Task<List<Pending>> GetPendingSearchAsync(string? priority, string? category, string? stateOfTask);
   
    Task<Pending> GetByIdPendingAsync(int id);
    
    Task<Pending> GetByNamePendingAsync(string name);
    
    Task<int>  SavePendingAsync(Pending dataPending);
    
    Task<bool> UpdatePendingAsync(Pending dataPending, int id);
    Task<bool> DeletePendingAsync(int id);
}