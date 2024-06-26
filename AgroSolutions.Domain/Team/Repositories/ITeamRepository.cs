namespace Domain;


public interface ITeamRepository
{
    Task<List<Team>> GetAllTeamAsync();
    
    Task<Team> GetByIdTeamAsync(int id);
    
    Task<Team> GetByTeamCodeAsync(string teamCode);
    
    Task<Team> GetByCropCodeAsync(string cropCode);

    Task<Advicer> GetByNameAdvicerAsync(string name);
    Task<Producer> GetByNameProducerAsync(string name);
    
    Task<Advicer> GetByDniAdvicerAsync(string dni);
    Task<Producer> GetByDniProducerAsync(string dni);

    Task<int>  SaveTeamAsync(Team dataTeam);
    
    Task<bool> DeleteTeamAsync(int id);
}