using _1_API.Response;
using Agrosolutions.Domain.Crops.Model.Queries;
using AutoMapper;
using Domain;


namespace Application;

public class CropQueryService : ICropQueryService
{
    private readonly ICropRepository _cropRepository;
    private readonly IMapper _mapper;
    
    public CropQueryService(ICropRepository cropRepository, IMapper mapper)
    {
        _cropRepository = cropRepository;
        _mapper = mapper;
    }
    
    public async Task<List<AdviserResponse>?> Handle(GetAllAsesoresQuery query)
    {
        var data = await _cropRepository.GetAllAsesoresAsync();
        var result = _mapper.Map<List<Adviser>, List<AdviserResponse>>(data);
        return result;
    }

    public async Task<List<CropsResponse>?> Handle(GetAllCultivosQuery query)
    {
        var data = await _cropRepository.GetAllCultivosAsync();
        var result = _mapper.Map<List<Crop>, List<CropsResponse>>(data);
        return result;
    }

    public async Task<List<CalendarResponse>?> Handle(GetAllCalendariosForCultivoQuery query)
    {
        var data = await _cropRepository.GetAllCalendariosForCultivoAsync(query.cultivoId);
        var result = _mapper.Map<List<Calendar>, List<CalendarResponse>>(data);
        return result;
    }

    public async Task<CropsResponse?> Handle(GetCultivoByIdQuery query)
    {
        var data = await _cropRepository.GetCultivoByIdAsync(query.id);
        var result = _mapper.Map<Crop, CropsResponse>(data);
        return result;
    }

    public async Task<AdviserResponse?> Handle(GetAsesorByIdQuery query)
    {
        var data = await _cropRepository.GetAsesorByIdAsync(query.id);
        var result = _mapper.Map<Adviser, AdviserResponse>(data);
        return result;
    }
    
    public async Task<CalendarResponse?> Handle(GetCalendarioByIdQuery query)
    {
        var data =  await _cropRepository.GetCalendarioByIdAsync(query.id);
        var result = _mapper.Map<Calendar, CalendarResponse>(data);
        return result;
    }
}
    