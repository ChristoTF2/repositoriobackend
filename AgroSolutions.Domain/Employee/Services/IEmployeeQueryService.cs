using _1_API.Response;
using LearningCenter.Domain.Publishing.Models.Queries;
namespace Domain;

public interface IEmployeeQueryService
{
    Task<List<EmployeShortResponse>?> Handle(GetAllEmployeesQuery query);
    Task<EmployeeResponse?> Handle(GetByIdEmployeeQuery query);
    Task<EmployeeResponse?> Handle(GetByDniEmployeeQuery query);
    Task<EmployeeResponse?> Handle(GetByTeamIdAdviserEmployeeQuery query);
    Task<List<EmployeeResponse>?> Handle(GetByJobEmployeeQuery query);
    Task<List<EmployeShortResponse>?> Handle(GetByJobSearchQuery query);

}