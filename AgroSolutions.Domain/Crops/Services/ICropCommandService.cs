
using Presentation.Request;

namespace Domain;

public interface ICropCommandService
{
    Task<int> Handle(CreateAdviserCommand command);
    Task<int> Handle(CreateCalendarCommand command);
    Task<int> Handle(CreateCropsCommand command);
}