using AutoMapper;
using Domain;
using Infraestructure;
using Moq;
using NSubstitute;
using Presentation.Request;

namespace Application.Test;

public class FinanceApplicationUnitTest
{
    [Fact]
    public async Task SaveAsync_ValidInput_ReturnValidId()
    {
        //Arrange
        var mock = new Mock<IFinanceRepository>();
        var mockMapper = new Mock<IMapper>();

        CreateFinanceCommand command = new CreateFinanceCommand
        {
            Month = "Fabruary",
            Incomes = "Description",
            Bills = "seismil",
            Earning = "tresmil",
        };

        mockMapper.Setup(m => m.Map<CreateFinanceCommand, Finance>(command)).Returns(new Finance
        {
            Month = command.Month,
            Incomes = command.Incomes,
            Bills = command.Bills,
            Earning = command.Earning,
        });

        mock.Setup(data => data.GetByMonthAsync(command.Month)).ReturnsAsync((Finance)null);
        mock.Setup(data => data.GetAllAsync()).ReturnsAsync(new List<Finance>());
        mock.Setup(data => data.SaveAsync(It.IsAny<Finance>())).ReturnsAsync(1);

        FinanceCommandService financeCommandService = new FinanceCommandService(mock.Object, mockMapper.Object);


        //ACt
        var result = await financeCommandService.Handle(command);

        //Assert
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task DeletAsync_ExistingId_ReturnsTrue()
    {
        //Arrange
        var id = 10;
        var financeDataMock = Substitute.For<IFinanceRepository>();
        var mockMapper = Substitute.For<IMapper>();

        financeDataMock.GetById(id).Returns(new Finance());
        financeDataMock.Delete(id).Returns(true);

        DeleteFinanceCommand command = new DeleteFinanceCommand
        {
            Id = id
        };

        FinanceCommandService financeCommandService = new FinanceCommandService(financeDataMock, mockMapper);

        //Act
        var result = await financeCommandService.Handle(command);

        //Assert
        Assert.True(result);
    }

    [Fact]
    public async Task DeletAsync_NotExistingId_ReturnsFalse()
    {
        //Arrange
        var id = 10;
        var financeDataMock = Substitute.For<IFinanceRepository>();
        var mockMapper = Substitute.For<IMapper>();

        financeDataMock.GetById(id).Returns((Finance)null);
        financeDataMock.Delete(id).Returns(true);

        DeleteFinanceCommand command = new DeleteFinanceCommand
        {
            Id = id
        };

        FinanceCommandService financeCommandService = new FinanceCommandService(financeDataMock, mockMapper);


        //Act and Assert
        Assert.ThrowsAsync<Exception>(() => financeCommandService.Handle(command));
    }
}