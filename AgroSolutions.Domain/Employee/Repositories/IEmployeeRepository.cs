namespace Domain;

public interface IEmployeeRepository
{
    Task<List<Employee>> GetAllEmployeesAsync();
    
    Task<Employee> GetByIdEmployeeAsync(int id);
    
    Task<Employee> GetByDniEmployeeAsync(string dni);
    
    Task<Employee> GetByTeamIdAdviserEmployeeAsync(int iTeamId);

    Task<List<Employee>> GetByJobAndTeamEmployeeAsync(string? job, int teamId);
    
    Task<List<Employee>> GetByJobEmployeSearcheAsync(string? job);


    Task<int>  SaveEmployeeAsync(Employee dataEmployee);
    Task<bool> DeleteEmployeeAsync(int id); 
}