using _1_API.Response;
using Agrosolutions.Domain.Crops.Model.Queries;
using AutoMapper;
using Domain;

using Microsoft.AspNetCore.Mvc;
using Moq;
using Presentation.Controllers;

namespace Presetation.Test;

public class CropControllerUnitTest
{
    [Fact]
    public async Task GetAllCropsAsync_ResultOk()
    {
        // Arrange
        var mockMapper = new Mock<IMapper>();
        var mockcropQueryService = new Mock<ICropQueryService>();
        var mockCropCommandService = new Mock<ICropCommandService>();

        var fakeCropsList = new List<CropsResponse>()
        {
            new CropsResponse() 
        };

        mockcropQueryService.Setup(t => t.Handle(It.IsAny<GetAllCultivosQuery>())).ReturnsAsync(fakeCropsList);

        var controller = new CropController(mockcropQueryService.Object, mockCropCommandService.Object, mockMapper.Object);

        // Act
        var result = await controller.GetAllCropsAsync();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var returnValue = Assert.IsType<List<CropsResponse>>(okResult.Value);
        Assert.NotEmpty(returnValue);
    }

    [Fact]
    public async Task GetAllCropsAsync_ResultNotFound()
    {
        // Arrange
        var mockMapper = new Mock<IMapper>();
        var mocKCropQueryService = new Mock<ICropQueryService>();
        var mockCropCommandService = new Mock<ICropCommandService>();

        var fakeCropsList = new List<CropsResponse>();

        mocKCropQueryService.Setup(t => t.Handle(It.IsAny<GetAllCultivosQuery>())).ReturnsAsync(fakeCropsList);

        var controller = new CropController(mocKCropQueryService.Object, mockCropCommandService.Object, mockMapper.Object);

        // Act
        var result = await controller.GetAllCropsAsync();

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

}