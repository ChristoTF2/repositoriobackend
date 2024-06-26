using _1_API.Response;
using LearningCenter.Domain.IAM.Models;
using LearningCenter.Domain.IAM.Queries;

namespace LearningCenter.Domain.IAM.Services;

public interface IUserQueryService
{
    Task<User?> GetUserByIdAsync(GetUserByIdQuery query);
    Task<UserResponse?> Handle(GetUserByUserNameQuery query);
    Task<List<UserResponse?>> Handle(GetUserAllQuery query);
    Task<List<UserResponse?>> Handle(GetUserRoleSearchQuery query);
    Task<UserResponse?> Handle(GetUserByCompanyNameQuery query);
    Task<UserResponse?> Handle(GetUserByDniOrRucQuery query);
}