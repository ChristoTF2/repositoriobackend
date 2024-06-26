using _1_API.Response;
using Infraestructure;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Blog.Models.Entities;
using LearningCenter.Domain.Blog.Models.Response;

namespace _1_API.Mapper;

public class ModelsToResponse : Profile
{
    public ModelsToResponse()
    {
        CreateMap<Finance, FinanceResponse>();
        CreateMap<PendingCollections, PendingCollectionsResponse>();
        CreateMap<Crop, CropsResponse>();
        CreateMap<Adviser, AdviserResponse>();
        CreateMap<Calendar, CalendarResponse>();
        CreateMap<User, UserResponse>();
        CreateMap<Pending, PendingResponse>();
        CreateMap<Employee, EmployeeResponse>();
        CreateMap<Employee, EmployeShortResponse>();
        CreateMap<Team, TeamResponse>();
        CreateMap<Advicer, AdvicerResponse>();
        CreateMap<Producer, ProducerResponse>();
        CreateMap<Blog, BlogResponse>();
        CreateMap<Blog, BlogShortResponse>();

            
            
    }
}