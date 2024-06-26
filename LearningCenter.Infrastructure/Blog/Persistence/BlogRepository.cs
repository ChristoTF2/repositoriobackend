using Microsoft.EntityFrameworkCore;
using Domain;
using Infraestructure.Contexts;
using LearningCenter.Domain.Blog.Models.Entities;


namespace Infrastructure;


public class BlogRepository : IBlogRepository
{
    private readonly AgroSolutionsContext _agroSolutionsContext;

    public BlogRepository(AgroSolutionsContext agroSolutionsContext)
    {
        _agroSolutionsContext = agroSolutionsContext;
    }


    public async Task<List<Blog>> GetAllBlogAsync()
    {
        var result = await _agroSolutionsContext.Blogs.Where(t => t.IsActive).ToListAsync();
        return result;
    }

    public async Task<Blog> GetByIdBlogAsync(int id)
    {
        return await  _agroSolutionsContext.Blogs
            .Where(t => t.Id == id && t.IsActive)
            .FirstOrDefaultAsync();
    }

    public async Task<Blog> GetByReadTimeMinutesAsync(int readTimeMinutes)
    {
        return await  _agroSolutionsContext.Blogs.Where(t => t.IsActive && t.ReadTimeMinutes == readTimeMinutes).FirstOrDefaultAsync();
    }

    public async Task<Blog> GetByTitleAsync(string title)
    {
        return await  _agroSolutionsContext.Blogs.Where(t => t.IsActive && t.Title == title).FirstOrDefaultAsync();
    }

    public async Task<List<Blog>> GetByRoleBlogSearchAsync(string? roleBlog)
    {
        var result = await _agroSolutionsContext.Blogs.Where(t => t.RoleBlog == roleBlog && t.IsActive).ToListAsync();
        return result;
    }

    public async Task<int> SaveBlogAsync(Blog data)
    {
        using (var transaction = await _agroSolutionsContext.Database.BeginTransactionAsync())
        {
            try
            {
                data.IsActive = true;
                _agroSolutionsContext.Blogs.Add(data);
                await _agroSolutionsContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception(ex.Message);
            }
        }
        return data.Id;
    }
}