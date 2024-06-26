namespace Domain;

public interface IPendingCollectionsRepository
{
    Task<List<PendingCollections>> GetAllAsync();
    
    Task<List<PendingCollections>> GetSearchAsync(string name);

    Task<PendingCollections> GetById(int id);

    Task<PendingCollections> GetByTypeAsync(string name);

    Task<int> SaveAsync(PendingCollections data);

    Task<bool> Update(PendingCollections data, int id);

    Task<bool> Delete(int id);
}