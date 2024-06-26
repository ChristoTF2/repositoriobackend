namespace LearningCenter.Domain.Blog.Models.Response;

public class BlogShortResponse
{
    public string Title { get; set; }
    public string Summary { get; set; }
    public string Category { get; set; }
    public string ImageUrl { get; set; }
    public int ReadTimeMinutes { get; set; }
}