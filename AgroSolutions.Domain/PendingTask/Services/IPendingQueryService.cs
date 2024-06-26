using _1_API.Response;
using LearningCenter.Domain.Publishing.Models.Queries;
namespace Domain;

public interface IPendingQueryService
{
    Task<List<PendingResponse>?> Handle(GetAllPendingQuery query);
    Task<List<PendingResponse>?> Handle(GetPendingSearchQuery query);
    Task<PendingResponse?> Handle(GetByIdPendingQuery query);
    Task<PendingResponse?> Handle(GetByNamePendingQuery query);
}