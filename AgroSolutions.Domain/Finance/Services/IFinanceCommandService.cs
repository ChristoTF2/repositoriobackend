using Presentation.Request;

namespace Domain;

public interface IFinanceCommandService
{
    Task<int> Handle(CreateFinanceCommand command);
    Task<bool> Handle(UpdateFinanceCommand command);
    Task<bool> Handle(DeleteFinanceCommand command);
}