using Infraestructure;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Blog.Models.Commands;
using LearningCenter.Domain.Blog.Models.Entities;
using LearningCenter.Domain.IAM.Models.Comands;
using Presentation.Request;

namespace _1_API.Mapper;

public class ModelsToRequest : Profile
{
    public ModelsToRequest()
    {
        CreateMap<Finance, CreateFinanceCommand>();
        CreateMap<PendingCollections, CreatePendingCollections>();
        CreateMap<Crop, CreateCropsCommand>();
        CreateMap<Adviser, CreateAdviserCommand>();
        CreateMap<Calendar, CreateCalendarCommand>();
        CreateMap<User, SingupCommand>();
        CreateMap<User, SigninCommand>();
        CreateMap<Pending, CreatePendingCommand>();
        CreateMap<Employee, CreateEmployeeCommand>();
        CreateMap<Team, CreateTeamCommand>();
        CreateMap<Advicer, CreateAdvicerCommand>();
        CreateMap<Producer, CreateProducerCommand>();
        CreateMap<Blog, CreateBlogCommand>();

    }
}