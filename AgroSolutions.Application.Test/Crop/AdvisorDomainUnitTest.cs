using AutoMapper;
using Domain;
using Moq;
using Presentation.Request;

namespace Application.Test;

public class AdvisorDomainUnitTest
{
    [Fact]
    public async Task SaveAdviserAsync_ValidInput_ReturnValidId()
    {
        // Arrange
        var mockRepository = new Mock<ICropRepository>();
        var mockMapper = new Mock<IMapper>();

        CreateAdviserCommand command = new CreateAdviserCommand
        {
            Nombre = "Juan Pérez",
            Descripcion = "Experto en cultivos de maíz con 5 años de experiencia.",
            Calificacion = 4.5
        };

        var adviserEntity = new Adviser
        {
            Nombre = command.Nombre,
            Descripcion = command.Descripcion,
            Calificacion = command.Calificacion
        };

   
        mockMapper.Setup(m => m.Map<CreateAdviserCommand, Adviser>(command)).Returns(adviserEntity);
        mockRepository.Setup(repo => repo.SaveAdviserAsync(It.IsAny<Adviser>())).ReturnsAsync(1);
        CropCommandService commandService = new CropCommandService(mockRepository.Object, mockMapper.Object);

        // Act
        var result = await commandService.Handle(command);

        // Assert
        Assert.Equal(1, result);
    }
}