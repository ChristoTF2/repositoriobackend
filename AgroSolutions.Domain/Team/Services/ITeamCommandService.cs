using Presentation.Request;

namespace Domain;

public interface ITeamCommandService
{
    Task<int> Handle(CreateTeamCommand command);
    //Task<int> Handle(CreateProducerCommand command);
    //Task<int> Handle(CreateAdvicerCommand command);
    Task<bool> Handle(DeleteTeamCommand command); 
}