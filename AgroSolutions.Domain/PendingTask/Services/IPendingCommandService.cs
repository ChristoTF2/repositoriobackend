using Presentation.Request;

namespace Domain;

public interface IPendingCommandService
{
    Task<int> Handle(CreatePendingCommand command);
    Task<bool> Handle(UpdatePendingCommand command);
    Task<bool> Handle(DeletePendingCommand command); 
}