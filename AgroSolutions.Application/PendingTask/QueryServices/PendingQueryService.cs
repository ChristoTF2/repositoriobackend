using _1_API.Response;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;

namespace Application;

public class PendingQueryService : IPendingQueryService
{
    private readonly IPendingRepository _pendingRepository;
    private readonly IMapper _mapper;

    public PendingQueryService(IPendingRepository pendingRepository, IMapper mapper)
    {
        _pendingRepository = pendingRepository;
        _mapper = mapper;
    }
    
    public async Task<List<PendingResponse>?> Handle(GetAllPendingQuery query)
    {
        var data =  await _pendingRepository.GetAllPendingAsync();
        var result = _mapper.Map<List<Pending>, List<PendingResponse>>(data);
        return result;    
    }

    public async Task<List<PendingResponse>?> Handle(GetPendingSearchQuery query)
    {
        var data =  await _pendingRepository.GetPendingSearchAsync(query.Priority, query.Category, query.StateOfTask);
        var result = _mapper.Map<List<Pending>, List<PendingResponse>>(data);
        return result;        
    }
    
    public async Task<PendingResponse?> Handle(GetByIdPendingQuery query)
    {
        var data =  await _pendingRepository.GetByIdPendingAsync(query.Id);
        var result = _mapper.Map<Pending, PendingResponse>(data);
        return result;
    }

    public async Task<PendingResponse?> Handle(GetByNamePendingQuery query)
    {
        var data =  await _pendingRepository.GetByNamePendingAsync(query.Name);
        var result = _mapper.Map<Pending, PendingResponse>(data);
        return result;
        
    }
}