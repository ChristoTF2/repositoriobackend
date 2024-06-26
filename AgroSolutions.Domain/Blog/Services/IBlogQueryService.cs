using LearningCenter.Domain.Blog.Models.Queries;
using LearningCenter.Domain.Blog.Models.Response;

namespace LearningCenter.Domain.Blog.Services;

public interface IBlogQueryService
{
    Task<List<BlogShortResponse>?> Handle(GetAllBlogQuery query);
    Task<BlogResponse?> Handle(GetByIdBlogQuery query);
    Task<BlogResponse?> Handle(GetByReadTimeMinutesQuery query);
    
    Task<List<BlogShortResponse>?> Handle(GetByRoleBlogSearchQuery query);
    
    Task<BlogResponse> Handle(GetByTitleQuery query);
}