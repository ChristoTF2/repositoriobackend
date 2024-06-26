using System.ComponentModel.DataAnnotations;
using LearningCenter.Domain.Blog.Models.Entities;

namespace LearningCenter.Domain.Blog.Models.Commands;

public class CreateBlogCommand
{
    [Required(ErrorMessage = "Title is required.")]
    [StringLength(50, ErrorMessage = "Assigned to cannot be longer than 20 characters.")]
    public string Title { get; set; }
    [Required(ErrorMessage = "Subtitle is required.")]
    [StringLength(100, ErrorMessage = "Assigned to cannot be longer than 20 characters.")]
    public string Subtitle { get; set; }
    [Required(ErrorMessage = "Content is required.")]
    public string Content { get; set; }
    [Required(ErrorMessage = "Summary is required.")]
    public string Summary { get; set; }
    [EnumDataType(typeof(CategoryBlog), ErrorMessage = "Invalid category blog.")]
    public string CategoryBlog { get; set; }
    [EnumDataType(typeof(RoleBlog), ErrorMessage = "Invalid RoleBlog.")]
    public string RoleBlog { get; set; }
    [EnumDataType(typeof(TypeAuthor), ErrorMessage = "Invalid  TypeAuthor.")]
    public string TypeAuthor { get; set; }
    [Required(ErrorMessage = "ImageUrl is required.")]
    public string ImageUrl { get; set; }
    [Required(ErrorMessage = "CommentsCount is required.")]
    public int CommentsCount { get; set; }
    [Required(ErrorMessage = "ReadTimeMinutes is required.")]
    public int ReadTimeMinutes { get; set; }
}