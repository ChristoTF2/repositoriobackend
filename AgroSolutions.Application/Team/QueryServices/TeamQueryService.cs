using _1_API.Response;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;

namespace Application;

public class TeamQueryService : ITeamQueryService
{
    private readonly ITeamRepository _teamRepository;
    private readonly IMapper _mapper;

    public TeamQueryService(ITeamRepository teamRepository, IMapper mapper)
    {
        _teamRepository = teamRepository;
        _mapper = mapper;
    }
    
    public async Task<List<TeamResponse>?> Handle(GetAllTeamQuery query)
    {
        var data =  await _teamRepository.GetAllTeamAsync();
        var result = _mapper.Map<List<Team>, List<TeamResponse>>(data);
        return result;
    }

    public async Task<TeamResponse?> Handle(GetByIdTeamQuery query)
    {
        var data =  await _teamRepository.GetByIdTeamAsync(query.Id);
        var result = _mapper.Map<Team, TeamResponse>(data);
        return result;
    }

    public async Task<TeamResponse?> Handle(GetByTeamCodeQuery query)
    {
        var data =  await _teamRepository.GetByTeamCodeAsync(query.TeamCode);
        var result = _mapper.Map<Team, TeamResponse>(data);
        return result;
    }

    public async Task<TeamResponse?> Handle(GetByCropCodeQuery query)
    {
        var data =  await _teamRepository.GetByCropCodeAsync(query.CropCode);
        var result = _mapper.Map<Team, TeamResponse>(data);
        return result;
    }

   

    public async Task<ProducerResponse?> Handle(GetByDniProducerQuery query)
    {
        var data =  await _teamRepository.GetByDniProducerAsync(query.Dni);
        var result = _mapper.Map<Producer, ProducerResponse>(data);
        return result;
    }

    public async Task<ProducerResponse?> Handle(GetByNameProducerQuery query)
    {
        var data =  await _teamRepository.GetByNameProducerAsync(query.Name);
        var result = _mapper.Map<Producer, ProducerResponse>(data);
        return result;
        
    }
}