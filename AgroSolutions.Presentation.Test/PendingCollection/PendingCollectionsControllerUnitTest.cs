using _1_API.Response;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Presentation.Controllers;

namespace TestProject1LearningCenter.Presetation.Test;

public class PendingCollectionsControllerUnitTest
{
    [Fact]
    public async Task GetAsync_ResultOk()
    {
        //Arrange
        var mockMapper = new Mock<IMapper>();
        var mockPendingCollectionsQueryService = new Mock<IPendingCollectionsQueryService>();
        var mockPendingCollectionsCommandService = new Mock<IPendingCollectionsCommandService>();

        var fakeList = new List<PendingCollectionsResponse>()
        {
            new PendingCollectionsResponse()
        };
        
        mockPendingCollectionsQueryService.Setup(t => t.Handle(new GetAllPendingCollectionsQuery())).ReturnsAsync(fakeList);

        var controller = new PendingCollectionsController(mockPendingCollectionsQueryService.Object, mockPendingCollectionsCommandService.Object, mockMapper.Object);

        //Act
        var result = await controller.GetAsync();

        //Assert
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAsync_ResultNotFound()
    {
        //Arrange
        var mockMapper = new Mock<IMapper>();
        var mockPendingCollectionQueryService = new Mock<IPendingCollectionsQueryService>();
        var mockPendingCollectionCommandService = new Mock<IPendingCollectionsCommandService>();

        var fakeList = new List<PendingCollectionsResponse>();
        
        mockPendingCollectionQueryService.Setup(t => t.Handle(new GetAllPendingCollectionsQuery())).ReturnsAsync(fakeList);

        var controller = new PendingCollectionsController(mockPendingCollectionQueryService.Object, mockPendingCollectionCommandService.Object, mockMapper.Object);

        //Act
        var result = await controller.GetAsync();

        //Assert
        Assert.IsType<NotFoundResult>(result);
    }
}