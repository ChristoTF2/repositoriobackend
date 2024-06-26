namespace LearningCenter.Domain.Blog.Models.Response;

public class BlogResponse
{
    public string Title { get; set; }
    public string Subtitle { get; set; }
    public string Content { get; set; }
    public string Summary { get; set; }
    public string Category { get; set; }
    public string RoleBlog { get; set; }
    public string TypeAuthor { get; set; }
    public string ImageUrl { get; set; }
    public int CommentsCount { get; set; }
    public int ReadTimeMinutes { get; set; }
}