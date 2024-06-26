using System.Data;
using AutoMapper;
using Domain;
using Infraestructure;
using LearningCenter.Domain.Blog.Models.Commands;
using LearningCenter.Domain.Blog.Models.Entities;
using LearningCenter.Domain.Blog.Services;
using Presentation.Request;
using Shared;

namespace Application;

public class BlogCommandService : IBlogCommandService
{
    private readonly IBlogRepository _blogRepository;
    private readonly IMapper _mapper;

    public BlogCommandService(IBlogRepository blogRepository, IMapper mapper)
    {
        _blogRepository = blogRepository;
        _mapper = mapper;
    }
    
    public async Task<int> Handle(CreateBlogCommand command)
    {
        var blog = _mapper.Map<CreateBlogCommand, Blog>(command);

        var existingTitle = await _blogRepository.GetByTitleAsync(blog.Title);
        if (existingTitle != null) throw new DuplicateNameException("Title already exists");

        
        if (blog.ReadTimeMinutes < Constants.TIME_READ)
        {
            throw new InvalidOperationException("Cannot set the time read");
        }
        return await _blogRepository.SaveBlogAsync(blog);    
    }
}