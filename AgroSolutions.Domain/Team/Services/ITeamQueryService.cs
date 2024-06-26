using _1_API.Response;
using LearningCenter.Domain.Publishing.Models.Queries;
namespace Domain;

public interface ITeamQueryService
{
    Task<List<TeamResponse>?> Handle(GetAllTeamQuery query);
    Task<TeamResponse?> Handle(GetByIdTeamQuery query);
    Task<TeamResponse?> Handle(GetByTeamCodeQuery query);
    Task<TeamResponse?> Handle(GetByCropCodeQuery query);
    Task<ProducerResponse?> Handle(GetByDniProducerQuery query);
    Task<ProducerResponse?> Handle(GetByNameProducerQuery query);

}