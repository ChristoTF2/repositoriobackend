using System.Data;
using AutoMapper;
using Domain;
using Infraestructure;
using Presentation.Request;
using Shared;

namespace Application;

public class EmployeeCommandService : IEmployeeCommandService
{
    private readonly IEmployeeRepository _employeeRepository;
    private readonly IMapper _mapper;

    public EmployeeCommandService(IEmployeeRepository employeeRepository, IMapper mapper)
    {
        _employeeRepository = employeeRepository;
        _mapper = mapper;
    }
    
    public async Task<int> Handle(CreateEmployeeCommand command)
    {
        var employee = _mapper.Map<CreateEmployeeCommand, Employee>(command);
    
        var existingEmployee = await _employeeRepository.GetByDniEmployeeAsync(employee.Dni);
        if (existingEmployee != null) throw new DuplicateNameException("Dni already exists");
        
        var existingIdTeam = await _employeeRepository.GetByTeamIdAdviserEmployeeAsync(employee.TeamId);
        if (existingIdTeam != null) throw new DuplicateNameException("Adviser for this team already exists");
        
        if (string.IsNullOrWhiteSpace(employee.Dni))
        {
            throw new ArgumentException("Dni is required");
        }
            
        if (employee.Age < 18)
        {
            throw new InvalidOperationException("A minor user cannot entern");
        }
        
        if (employee.Salary < 1200)
        {
            throw new InvalidOperationException("The salary must be greater than the minimum wage");
        }
        
        return await _employeeRepository.SaveEmployeeAsync(employee);
        
    }

    public async Task<bool> Handle(DeleteEmployeeCommand command)
    {
        var  existingEmployee = await _employeeRepository.GetByIdEmployeeAsync(command.Id);
            
        if (existingEmployee == null) 
            throw new NotException("Employee not found");
            
        if (existingEmployee.TeamId != null && existingEmployee.Job == "Asesor" && existingEmployee.Job == "Adviser")
        {
            throw new NotException("Cannot delete employee with associated teams.");
        }
        
        return  await _employeeRepository.DeleteEmployeeAsync(command.Id);    
    }
}