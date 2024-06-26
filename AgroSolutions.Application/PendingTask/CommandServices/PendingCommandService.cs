using System.Data;
using AutoMapper;
using Domain;
using Infraestructure;
using Presentation.Request;
using Shared;

namespace Application;

public class PendingCommandService : IPendingCommandService
{
    private readonly IPendingRepository _pendingRepository;
    private readonly IMapper _mapper;

    public PendingCommandService(IPendingRepository pendingRepository, IMapper mapper)
    {
        _pendingRepository = pendingRepository;
        _mapper = mapper;
    }
    
    public async Task<int> Handle(CreatePendingCommand command)
    {
        var pending = _mapper.Map<CreatePendingCommand, Pending>(command);

        var existingPending = await _pendingRepository.GetByNamePendingAsync(pending.Name);
        if (existingPending != null) throw new DuplicateNameException("Pending already exists");

        var total = (await _pendingRepository.GetAllPendingAsync()).Count;
        if (total >= Constants.MAX_PENDING) throw new ConstraintException("Max pending reached " + Constants.MAX_PENDING);

        if (string.IsNullOrWhiteSpace(pending.Name))
        {
            throw new ArgumentException("Name is required");
        }
            
        if (pending.DueDate < DateTime.Now)
        {
            throw new InvalidOperationException("Cannot set the due date to a past date");
        }
        return await _pendingRepository.SavePendingAsync(pending);
    }

    public async Task<bool> Handle(UpdatePendingCommand command)
    {
        var pending = _mapper.Map<UpdatePendingCommand, Pending>(command);

        var existingPending = await _pendingRepository.GetByIdPendingAsync(pending.Id);
        if (existingPending == null) throw new NotException("Tasks Pending not found");
            
        if (existingPending.DueDate < DateTime.Now)
        {
            throw new InvalidOperationException("Cannot set the due date to a past date");
        }
        
        if (existingPending.Name != pending.Name)
            throw new ConstraintException("Name can not be updated");

            
        if (existingPending.Priority != pending.Priority)
            throw new ConstraintException("Priority can not be updated");
        
        return await _pendingRepository.UpdatePendingAsync(pending, command.Id);
        
    }

    public async Task<bool> Handle(DeletePendingCommand command)
    {
        var  existingPending = await    _pendingRepository.GetByIdPendingAsync(command.Id);
            
        if (existingPending == null) 
            throw new NotException("Tasks Pending not found");
            
        if (existingPending.State == "Done" || existingPending.State == "Hecho")
            throw new InvalidOperationException("Cannot delete a completed pending");
            
        if (existingPending.DueDate < DateTime.Now)
        {
            throw new InvalidOperationException("Cannot delete an overdue pending");
        }
        return  await _pendingRepository.DeletePendingAsync(command.Id);          
    }
}