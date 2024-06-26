using _1_API.Response;
using Agrosolutions.Domain.Crops.Model.Queries;
using AutoMapper;
using Domain;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Presentation.Controllers;

namespace Presetation.Test;

public class AdivsorControllerUnitTest
{
    [Fact]
    public async Task GetAllAdvisersAsync_ResultOk()
    {
        // Arrange
        var mockMapper = new Mock<IMapper>();
        var mockAdviserQueryService = new Mock<ICropQueryService>();
        var mockAdviserCommandService = new Mock<ICropCommandService>();

        var fakeAdvisersList = new List<AdviserResponse>()
        {
            new AdviserResponse
            {
                Id = 1,
                Nombre = "Ana Torres",
                Descripcion = "Experta en cultivos orgánicos y sostenibilidad.",
                Calificacion = 4.5
            },
            new AdviserResponse
            {
                Id = 2,
                Nombre = "Carlos Gómez",
                Descripcion = "Especialista en manejo de suelos y fertilización.",
                Calificacion = 4.7
            },
            new AdviserResponse
            {
                Id = 3,
                Nombre = "Luisa Fernández",
                Descripcion = "Asesora en tecnologías agrícolas y maquinaria.",
                Calificacion = 4.8
            } 
        };

        mockAdviserQueryService.Setup(t => t.Handle(It.IsAny<GetAllAsesoresQuery>())).ReturnsAsync(fakeAdvisersList);

        var controller = new CropController(mockAdviserQueryService.Object, mockAdviserCommandService.Object, mockMapper.Object);

        // Act
        var result = await controller.GetAllAdvisersAsync();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var returnValue = Assert.IsType<List<AdviserResponse>>(okResult.Value);
        Assert.NotEmpty(returnValue);
    }

    [Fact]
    public async Task GetAllAdvisersAsync_ResultNotFound()
    {
        // Arrange
        var mockMapper = new Mock<IMapper>();
        var mockAdviserQueryService = new Mock<ICropQueryService>();
        var mockAdviserCommandService = new Mock<ICropCommandService>();

        var fakeAdvisersList = new List<AdviserResponse>();

        mockAdviserQueryService.Setup(t => t.Handle(It.IsAny<GetAllAsesoresQuery>())).ReturnsAsync(fakeAdvisersList);

        var controller = new CropController(mockAdviserQueryService.Object, mockAdviserCommandService.Object, mockMapper.Object);

        // Act
        var result = await controller.GetAllAdvisersAsync();

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }
}