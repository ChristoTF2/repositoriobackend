using _1_API.Response;
using LearningCenter.Domain.Publishing.Models.Queries;

namespace Domain;

public interface IFinanceQueryService
{    
    Task<List<FinanceResponse>?> Handle(GetAllFinancesQuery query);
    Task<FinanceResponse?> Handle(GetFinancesByIdQuery query);
}