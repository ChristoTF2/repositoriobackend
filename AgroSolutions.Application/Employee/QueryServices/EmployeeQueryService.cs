using _1_API.Response;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;
namespace Application;

public class EmployeeQueryService : IEmployeeQueryService
{
    private readonly IEmployeeRepository _employeeRepository;
    private readonly IMapper _mapper;


    public EmployeeQueryService(IEmployeeRepository employeeRepository, IMapper mapper)
    {
        _employeeRepository = employeeRepository;
        _mapper = mapper;
    }
    
    public async Task<List<EmployeShortResponse>?> Handle(GetAllEmployeesQuery query)
    {
        var data =  await _employeeRepository.GetAllEmployeesAsync();
        var result = _mapper.Map<List<Employee>, List<EmployeShortResponse>>(data);
        return result;    
    }

    public async Task<EmployeeResponse?> Handle(GetByIdEmployeeQuery query)
    {
        var data =  await _employeeRepository.GetByIdEmployeeAsync(query.Id);
        var result = _mapper.Map<Employee, EmployeeResponse>(data);
        return result;
        
    }

    public async Task<EmployeeResponse?> Handle(GetByDniEmployeeQuery query)
    {
        var data =  await _employeeRepository.GetByDniEmployeeAsync(query.Dni);
        var result = _mapper.Map<Employee, EmployeeResponse>(data);
        return result;
        
    }

    public async Task<EmployeeResponse?> Handle(GetByTeamIdAdviserEmployeeQuery query)
    {
        var data =  await _employeeRepository.GetByTeamIdAdviserEmployeeAsync(query.TeamId);
        var result = _mapper.Map<Employee, EmployeeResponse>(data);
        return result;
        
    }

    public async Task<List<EmployeeResponse>?> Handle(GetByJobEmployeeQuery query)
    {
        var data =  await _employeeRepository.GetByJobAndTeamEmployeeAsync(query.Job, query.TeamId);
        var result = _mapper.Map<List<Employee>, List<EmployeeResponse>>(data);
        return result;
        
    }

    public async Task<List<EmployeShortResponse>?> Handle(GetByJobSearchQuery query)
    {
        var data =  await _employeeRepository.GetByJobEmployeSearcheAsync(query.Job);
        var result = _mapper.Map<List<Employee>, List<EmployeShortResponse>>(data);
        return result;
    }
}