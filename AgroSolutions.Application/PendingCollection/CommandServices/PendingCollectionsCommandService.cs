using Domain;
using System.Data;
using AutoMapper;
using Domain;
using Presentation.Request;
using Shared;

namespace Application;

public class PendingCollectionsCommandService : IPendingCollectionsCommandService
{
    private readonly IPendingCollectionsRepository _pendingCollectionsRepository;
    private readonly IMapper _mapper;

    public PendingCollectionsCommandService(IPendingCollectionsRepository pendingCollectionsRepository, IMapper mapper)
    {
        _pendingCollectionsRepository = pendingCollectionsRepository;
        _mapper = mapper;
    }

    public async Task<int> Handle(CreatePendingCollections command)
    {
        var pendingCollections = _mapper.Map<CreatePendingCollections, PendingCollections>(command);

        var existingPendingCollections = await _pendingCollectionsRepository.GetByTypeAsync(pendingCollections.Type);
        if (existingPendingCollections != null) throw new DuplicateNameException("Pending collection already exists");

        var total = (await _pendingCollectionsRepository.GetAllAsync()).Count;
        if (total >= Constants.MAX_TUTORIALS)
            throw new ConstraintException("Max pending collections reached " + Constants.MAX_TUTORIALS);

        return await _pendingCollectionsRepository.SaveAsync(pendingCollections);
    }

    public async Task<bool> Handle(DeletePendingCollections command)
    {
        var existingPendingCollection = _pendingCollectionsRepository.GetById(command.Id);
        if (existingPendingCollection == null) throw new NotException("Finance not found");
        return await _pendingCollectionsRepository.Delete(command.Id);
    }
}