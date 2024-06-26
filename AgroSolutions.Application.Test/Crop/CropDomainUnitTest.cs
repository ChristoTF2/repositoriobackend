
using AutoMapper;
using Domain;
using Moq;
using Presentation.Request;

namespace Application.Test;

public class CropDomainUnitTest
{
    [Fact]
    public async Task SaveCropsAsync_ValidInput_ReturnValidId()
    {
        // Arrange
        var mockRepository = new Mock<ICropRepository>();
        var mockMapper = new Mock<IMapper>();

        CreateCropsCommand command = new CreateCropsCommand
        {
            Producto = "Maíz",
            Area = 100,
            Costo = 500.00,
            Estado = "Bueno",
            Retorno = 800.00,
            Localizacion = "Campo 1",
            Notificaciones = "Ninguna",
            AsesorId = 1,
            ImageUrl = "http://example.com/image.jpg",
            Calendars = new List<CreateCalendarCommand>
            {
                new CreateCalendarCommand()
                {
                    Fecha = DateOnly.FromDateTime(DateTime.Now),
                    Actividad = "Siembra",
                    Estado = "Completado"
                }
            }
        };

        var cropsEntity = new Crop
        {
            Producto = command.Producto,
            Area = command.Area,
            Costo = command.Costo , 
            Estado = command.Estado,
            Retorno = command.Retorno,
            Localizacion = command.Localizacion,
            Notificaciones = command.Notificaciones,
            AsesorId = command.AsesorId,
            ImageUrl = command.ImageUrl,
            Calendars = new List<Calendar> 
            {
                new Calendar
                {
                    Id = 1,
                    Fecha = new DateOnly(2024, 6, 5), 
                    Actividad = command.Calendars[0].Actividad,
                    Estado = command.Calendars[0].Estado
                }
            }
        };

        mockMapper.Setup(m => m.Map<CreateCropsCommand, Crop>(command)).Returns(cropsEntity);
        mockRepository.Setup(repo => repo.SaveCropsAsync(It.IsAny<Crop>())).ReturnsAsync(1); 
        CropCommandService commandService = new CropCommandService(mockRepository.Object, mockMapper.Object);

        // Act
        var result = await commandService.Handle(command);

        // Assert
        Assert.Equal(1, result); 
    }
}