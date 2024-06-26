using _1_API.Response;
using AutoMapper;
using Domain;
using LearningCenter.Domain.Blog.Models.Entities;
using LearningCenter.Domain.Blog.Models.Queries;
using LearningCenter.Domain.Blog.Models.Response;
using LearningCenter.Domain.Blog.Services;
using LearningCenter.Domain.Publishing.Models.Queries;

namespace Application;

public class BlogQueryService : IBlogQueryService
{
    private readonly IBlogRepository _blogRepository;
    private readonly IMapper _mapper;

    public BlogQueryService(IBlogRepository blogRepository, IMapper mapper)
    {
        _blogRepository = blogRepository;
        _mapper = mapper;
    }


    public async Task<List<BlogShortResponse>?> Handle(GetAllBlogQuery query)
    {
        var data =  await _blogRepository.GetAllBlogAsync();
        var result = _mapper.Map<List<Blog>, List<BlogShortResponse>>(data);
        return result;      
    }

    public async Task<BlogResponse?> Handle(GetByIdBlogQuery query)
    {
        var data =  await _blogRepository.GetByIdBlogAsync(query.Id);
        var result = _mapper.Map<Blog,BlogResponse>(data);
        return result;       
    }

    public async Task<BlogResponse?> Handle(GetByReadTimeMinutesQuery query)
    {
        var data =  await _blogRepository.GetByReadTimeMinutesAsync(query.ReadTimeMinutes);
        var result = _mapper.Map<Blog,BlogResponse>(data);
        return result;       
    }

    public async Task<List<BlogShortResponse>?> Handle(GetByRoleBlogSearchQuery query)
    {
        var data =  await _blogRepository.GetByRoleBlogSearchAsync(query.RoleBlog);
        var result = _mapper.Map<List<Blog>, List<BlogShortResponse>>(data);
        return result;
        
    }

    public async Task<BlogResponse> Handle(GetByTitleQuery query)
    {
        var data =  await _blogRepository.GetByTitleAsync(query.Tittle);
        var result = _mapper.Map<Blog, BlogResponse>(data);
        return result;       
    }
}