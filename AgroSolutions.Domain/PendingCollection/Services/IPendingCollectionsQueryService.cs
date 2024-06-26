using _1_API.Response;
using LearningCenter.Domain.Publishing.Models.Queries;

namespace Domain;

public interface IPendingCollectionsQueryService
{
    Task<List<PendingCollectionsResponse>?> Handle(GetAllPendingCollectionsQuery query);
    Task<PendingCollectionsResponse?> Handle(GetPendingCollectionsByIdQuery query);
}