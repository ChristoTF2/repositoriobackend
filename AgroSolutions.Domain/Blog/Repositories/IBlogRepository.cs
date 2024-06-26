using Domain;
using LearningCenter.Domain.Blog.Models.Entities;


public interface IBlogRepository
{
    Task<List<Blog>> GetAllBlogAsync();
    
    Task<Blog> GetByIdBlogAsync(int id);
    
    Task<Blog> GetByReadTimeMinutesAsync(int readTimeMinutes);
    
    Task<Blog> GetByTitleAsync(string title);

    Task<List<Blog>> GetByRoleBlogSearchAsync(string? roleBlog);

    Task<int>  SaveBlogAsync(Blog data);
}