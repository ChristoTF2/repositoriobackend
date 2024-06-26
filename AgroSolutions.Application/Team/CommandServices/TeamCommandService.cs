using System.Data;
using _1_API.Response;
using AutoMapper;
using Domain;
using Infraestructure;
using Presentation.Request;
using Shared;

namespace Application;

public class TeamCommandService : ITeamCommandService
{
    private readonly ITeamRepository _teamRepository;

    private readonly IMapper _mapper;

    public TeamCommandService(ITeamRepository teamRepository, IMapper mapper)
    {
        _teamRepository = teamRepository;
        _mapper = mapper;
    }
    
    public async Task<int> Handle(CreateTeamCommand command)
    {
        var team = _mapper.Map<CreateTeamCommand, Team>(command);

        var existingTeam = await _teamRepository.GetByTeamCodeAsync(team.TeamCode);
        if (existingTeam != null) throw new DuplicateNameException("Team Code already exists");
        
        var existingCropCode = await _teamRepository.GetByCropCodeAsync(team.CropCode);
        if (existingCropCode != null) throw new ("Crop code already exists");
        
        if (team.Budget < 5000)
        {
            throw new InvalidOperationException("A minor budget cannot entern");
        }

        return await _teamRepository.SaveTeamAsync(team);
        
    }

    public async Task<bool> Handle(DeleteTeamCommand command)
    {
        var  existingTeam = await _teamRepository.GetByIdTeamAsync(command.Id);
            
        if (existingTeam == null) 
            throw new NotException("Team not found");
            
        if (existingTeam != null && existingTeam.Producers.Count > 0)
        {
            throw new NotException("Cannot delete account with associated employees.");
        }
        
        return  await _teamRepository.DeleteTeamAsync(command.Id);
        
    }
}