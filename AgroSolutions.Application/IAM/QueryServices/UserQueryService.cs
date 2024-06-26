using _1_API.Response;
using AutoMapper;
using LearningCenter.Domain.IAM.Models;
using LearningCenter.Domain.IAM.Queries;
using LearningCenter.Domain.IAM.Repositories;
using LearningCenter.Domain.IAM.Services;
using System.Data;
using Presentation.Request;
using Shared;

namespace Application;

public class UserQueryService : IUserQueryService
{
    private readonly IUserRepository _userRepository;
    private readonly IMapper _mapper;

    
    public UserQueryService(IUserRepository userRepository, IMapper mapper)
    {
        _userRepository = userRepository;
        _mapper = mapper;
    }

    public async Task<User?> GetUserByIdAsync(GetUserByIdQuery query)
    {
        return await _userRepository.GetUserByIdAsync(query.Id);
    }

    public async Task<UserResponse?> Handle(GetUserByUserNameQuery query)
    {
        var data =  await _userRepository.GetUserByUserNameAsync(query.Username);
        var result = _mapper.Map<User, UserResponse>(data);
        return result;
    }

    public async Task<List<UserResponse?>> Handle(GetUserAllQuery query)
    {
        var data =  await _userRepository.GetUserAllAsync();
        var result = _mapper.Map<List<User>, List<UserResponse>>(data);
        return result;
    }

    public async Task<List<UserResponse?>> Handle(GetUserRoleSearchQuery query)
    {
        var data =  await _userRepository.GetUserRoleSearchAsync(query.Role);
        var result = _mapper.Map<List<User>, List<UserResponse>>(data);
        return result;
    }

    public async Task<UserResponse?> Handle(GetUserByCompanyNameQuery query)
    {
        var data =  await _userRepository.GetUserByCompanyNameAsync(query.CompanyName);
        var result = _mapper.Map<User, UserResponse>(data);
        return result;
    }

    public async Task<UserResponse?> Handle(GetUserByDniOrRucQuery query)
    {
        var data = await _userRepository.GetUserByDniOrRucAsync(query.DniOrRuc);
        var result = _mapper.Map<User, UserResponse>(data);
        return result;
    }
}