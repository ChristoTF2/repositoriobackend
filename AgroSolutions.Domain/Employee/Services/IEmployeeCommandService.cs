using Presentation.Request;

namespace Domain;

public interface IEmployeeCommandService
{
    Task<int> Handle(CreateEmployeeCommand command);
    Task<bool> Handle(DeleteEmployeeCommand command); 
}