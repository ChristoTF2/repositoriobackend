using _1_API.Response;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;

namespace Application;

public class PendingCollectionsQueryService : IPendingCollectionsQueryService
{
    private readonly IPendingCollectionsRepository _pendingCollectionsRepository;
    private readonly IMapper _mapper;
    
    public PendingCollectionsQueryService(IPendingCollectionsRepository pendingCollectionsRepository,IMapper mapper)
    {
        _pendingCollectionsRepository = pendingCollectionsRepository;
        _mapper = mapper;
    }

    public async Task<List<PendingCollectionsResponse>?> Handle(GetAllPendingCollectionsQuery query)
    {
        var data =  await _pendingCollectionsRepository.GetAllAsync();
        var result = _mapper.Map<List<PendingCollections>, List<PendingCollectionsResponse>>(data);
        return result;
    }

    public async Task<PendingCollectionsResponse?> Handle(GetPendingCollectionsByIdQuery query)
    {
        var data =  await _pendingCollectionsRepository.GetById(query.Id);
        var result = _mapper.Map<PendingCollections, PendingCollectionsResponse>(data);
        return result;
    }
}