using AutoMapper;
using Domain;
using Moq;
using NSubstitute;
using Presentation.Request;

namespace Application.Test;

public class PendingCollectionsUnitTest
{
    [Fact]
    public async Task SaveAsync_ValidInput_ReturnValidId()
    {
        //Arrange
        var mock = new Mock<IPendingCollectionsRepository>();
        var mockMapper = new Mock<IMapper>();

        CreatePendingCollections command = new CreatePendingCollections
        {
            Type = "Compra Abono",
            Cost = "6000",
            Description = "Compra mensual de abono"
        };

        mockMapper.Setup(m => m.Map<CreatePendingCollections, PendingCollections>(command)).Returns(new PendingCollections()
        {
            Type = command.Type,
            Cost = command.Cost,
            Description = command.Description
        });

        mock.Setup(data => data.GetByTypeAsync(command.Type)).ReturnsAsync((PendingCollections)null);
        mock.Setup(data => data.GetAllAsync()).ReturnsAsync(new List<PendingCollections>());
        mock.Setup(data => data.SaveAsync(It.IsAny<PendingCollections>())).ReturnsAsync(1);

        PendingCollectionsCommandService pendingCollectionsCommandService = new PendingCollectionsCommandService(mock.Object, mockMapper.Object);


        //ACt
        var result = await pendingCollectionsCommandService.Handle(command);

        //Assert
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task DeletAsync_ExistingId_ReturnsTrue()
    {
        //Arrange
        var id = 10;
        var pendingCollectionsDataMock = Substitute.For<IPendingCollectionsRepository>();
        var mockMapper = Substitute.For<IMapper>();

        pendingCollectionsDataMock.GetById(id).Returns(new PendingCollections());
        pendingCollectionsDataMock.Delete(id).Returns(true);

        DeletePendingCollections command = new DeletePendingCollections
        {
            Id = id
        };

        PendingCollectionsCommandService pendingCollectionsCommandService = new PendingCollectionsCommandService(pendingCollectionsDataMock, mockMapper);

        //Act
        var result = await pendingCollectionsCommandService.Handle(command);

        //Assert
        Assert.True(result);
    }

    [Fact]
    public async Task DeletAsync_NotExistingId_ReturnsFalse()
    {
        //Arrange
        var id = 10;
        var pendingCollectionsDataMock = Substitute.For<IPendingCollectionsRepository>();
        var mockMapper = Substitute.For<IMapper>();

        pendingCollectionsDataMock.GetById(id).Returns((PendingCollections)null);
        pendingCollectionsDataMock.Delete(id).Returns(true);

        DeletePendingCollections command = new DeletePendingCollections
        {
            Id = id
        };

        PendingCollectionsCommandService pendingCollectionsCommandService = new PendingCollectionsCommandService(pendingCollectionsDataMock, mockMapper);


        //Act and Assert
        Assert.ThrowsAsync<Exception>(() => pendingCollectionsCommandService.Handle(command));
    }
}