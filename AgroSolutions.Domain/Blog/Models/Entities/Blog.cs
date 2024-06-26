using Domain;

namespace LearningCenter.Domain.Blog.Models.Entities;

public class Blog :ModelBase
{
    public string Title { get; set; }
    public string Subtitle { get; set; }
    public string Content { get; set; }
    public string Summary { get; set; }
    public string CategoryBlog { get; set; }
    public string RoleBlog { get; set; }
    public string TypeAuthor { get; set; }
    public string ImageUrl { get; set; }
    public int CommentsCount { get; set; }
    public int ReadTimeMinutes { get; set; }
}

public enum RoleBlog{
    Farmer,
    Seller
}

public enum TypeAuthor
{
    Editor,
    Collaborator,
    Guest
}

public enum CategoryBlog
{
    Technology,
    Agriculture,
    Health,
    Finance,
}