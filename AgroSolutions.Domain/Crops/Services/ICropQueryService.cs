using _1_API.Response;
using Agrosolutions.Domain.Crops.Model.Queries;

namespace Domain;

public interface ICropQueryService
{
    Task<List<AdviserResponse>?> Handle(GetAllAsesoresQuery query);
    Task<List<CropsResponse>?> Handle(GetAllCultivosQuery query);
    Task<List<CalendarResponse>?> Handle(GetAllCalendariosForCultivoQuery query);
    
    Task<CalendarResponse?> Handle(GetCalendarioByIdQuery query);
    Task<CropsResponse?> Handle(GetCultivoByIdQuery query);
    Task<AdviserResponse?> Handle(GetAsesorByIdQuery query);
}