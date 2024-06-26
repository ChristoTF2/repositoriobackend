using Presentation.Request;

namespace Domain;

public interface IPendingCollectionsCommandService
{
    Task<int> Handle(CreatePendingCollections command);
    Task<bool> Handle(DeletePendingCollections command);
}