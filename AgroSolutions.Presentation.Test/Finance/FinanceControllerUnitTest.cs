using _1_API.Response;
using Application;
using Infraestructure;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Publishing.Models.Queries;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Presentation.Controllers;

namespace TestProject1LearningCenter.Presetation.Test;

public class FinanceControllerUnitTest
{
    [Fact]
    public async Task GetAsync_ResultOk()
    {
        //Arrange
        var mockMapper = new Mock<IMapper>();
        var mockFinanceQueryService = new Mock<IFinanceQueryService>();
        var mockFinanceCommandService = new Mock<IFinanceCommandService>();

        var fakeList = new List<FinanceResponse>()
        {
            new FinanceResponse()
        };
        
        mockFinanceQueryService.Setup(t => t.Handle(new GetAllFinancesQuery())).ReturnsAsync(fakeList);

        var controller = new FinanceController(mockFinanceQueryService.Object, mockFinanceCommandService.Object, mockMapper.Object);

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
        var mockFinanceQueryService = new Mock<IFinanceQueryService>();
        var mockFinanceCommandService = new Mock<IFinanceCommandService>();

        var fakeList = new List<FinanceResponse>();
        
        mockFinanceQueryService.Setup(t => t.Handle(new GetAllFinancesQuery())).ReturnsAsync(fakeList);

        var controller = new FinanceController(mockFinanceQueryService.Object, mockFinanceCommandService.Object, mockMapper.Object);

        //Act
        var result = await controller.GetAsync();

        //Assert
        Assert.IsType<NotFoundResult>(result);
    }
}