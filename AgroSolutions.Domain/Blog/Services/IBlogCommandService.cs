using LearningCenter.Domain.Blog.Models.Commands;

namespace LearningCenter.Domain.Blog.Services;

public interface IBlogCommandService
{
    Task<int> Handle(CreateBlogCommand command);
}