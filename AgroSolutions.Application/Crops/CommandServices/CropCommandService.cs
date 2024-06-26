using AutoMapper;
using Domain;
using Presentation.Request;
using Shared;

namespace Application;

public class CropCommandService : ICropCommandService
{
    private readonly ICropRepository _cropRepository;
    private readonly IMapper _mapper;
    
    public CropCommandService(ICropRepository cropRepository, IMapper mapper)
    {
        _cropRepository = cropRepository;
        _mapper = mapper;
    }
    
    public async Task<int> Handle(CreateCalendarCommand command)
    {
     
        if (string.IsNullOrWhiteSpace(command.Actividad))
        {
            throw new ArgumentException("La actividad no puede estar vacía.");
        }

        var calendar = _mapper.Map<CreateCalendarCommand, Calendar>(command);
        return await _cropRepository.SaveCalendarAsync(calendar);
    }

    public async Task<int> Handle(CreateCropsCommand command)
    {
       
        if (command.Area < Constants.AREA_MIN)
        {
            throw new ArgumentException($"El área debe ser al menos {Constants.AREA_MIN}.");
        }
        
        if (command.Costo < Constants.COSTO_MIN)
        {
            throw new ArgumentException($"El costo debe ser al menos {Constants.COSTO_MIN}.");
        }
        
        command.Costo += command.Costo * Constants.IGV / 100;

        var crops = _mapper.Map<CreateCropsCommand,Crop >(command);
        return await _cropRepository.SaveCropsAsync(crops);
    }

    public async Task<int> Handle(CreateAdviserCommand command)
    {
 
        if (string.IsNullOrWhiteSpace(command.Nombre))
        {
            throw new ArgumentException("El nombre del asesor no puede estar vacío.");
        }


        if (command.Calificacion < Constants.CALIFICACION_MIN || command.Calificacion > Constants.CALIFICACION_MAX)
        {
            throw new ArgumentException($"La calificación debe estar entre {Constants.CALIFICACION_MIN} y {Constants.CALIFICACION_MAX}.");
        }

        var adviser = _mapper.Map<CreateAdviserCommand, Adviser>(command);
        return await _cropRepository.SaveAdviserAsync(adviser);
    }
}