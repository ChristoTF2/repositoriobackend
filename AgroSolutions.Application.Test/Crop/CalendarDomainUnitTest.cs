using AutoMapper;
using Domain;
using Moq;
using Presentation.Request;

namespace Application.Test;

public class CalendarDomainUnitTest
{
    [Fact]
    public async Task SaveCalendarAsync_ValidInput_ReturnValidId()
    {
        // Arrange
        var mockRepository = new Mock<ICropRepository>();
        var mockMapper = new Mock<IMapper>();

        CreateCalendarCommand command = new CreateCalendarCommand
        {
            Fecha = DateOnly.FromDateTime(DateTime.Now),
            Actividad = "Fertilización",
            Estado = "Pendiente"
        };

        var calendarEntity = new Calendar
        {
            Fecha = command.Fecha,
            Actividad = command.Actividad,
            Estado = command.Estado
        };

        mockMapper.Setup(m => m.Map<CreateCalendarCommand, Calendar>(command)).Returns(calendarEntity);
        mockRepository.Setup(repo => repo.SaveCalendarAsync(It.IsAny<Calendar>())).ReturnsAsync(1);
        CropCommandService commandService = new CropCommandService(mockRepository.Object, mockMapper.Object);

        // Act
        var result = await commandService.Handle(command);

        // Assert
        Assert.Equal(1, result);
    }
}