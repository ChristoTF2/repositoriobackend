using Domain;


namespace Domain;

public interface ICropRepository
{
    Task<List<Crop>> GetAllCultivosAsync();
    Task<Crop> GetCultivoByIdAsync(int id);
    Task<Calendar> GetCalendarioByIdAsync(int id);
    Task<List<Adviser>> GetAllAsesoresAsync();
    Task<Adviser> GetAsesorByIdAsync(int id);
    Task<List<Calendar>> GetAllCalendariosForCultivoAsync(int cultivoId);
    Task<int> SaveCalendarAsync(Calendar calendar);
    Task<int> SaveCropsAsync(Crop crop);
    Task<int> SaveAdviserAsync(Adviser adviser);
}