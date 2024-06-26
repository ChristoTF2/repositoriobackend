using System.ComponentModel.DataAnnotations;
using Domain;

namespace Presentation.Request;

public class CreatePendingCommand
{
    [Required(ErrorMessage = "Task name is required.")]
    [StringLength(20, ErrorMessage = "Assigned to cannot be longer than 20 characters.")]
    public string Name { get; set; }
    
    [Required(ErrorMessage = "Task description is required.")]
    [StringLength(50, ErrorMessage = "Assigned to cannot be longer than 50 characters.")]
    public string Description { get; set; }

    [Required(ErrorMessage = "Due date is required.")]
    [DataType(DataType.Date)]
    [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
    public DateTime DueDate { get; set; }

    [Required(ErrorMessage = "Assigned to is required.")]
    [StringLength(20, ErrorMessage = "Assigned to cannot be longer than 20 characters.")]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "AssignedTo description must contain only letters.")]
    public string AssignedTo { get; set; }

    [Required(ErrorMessage = "Priority is required.")]
    [StringLength(20, ErrorMessage = "Priority cannot be longer than 20 characters.")]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "Priority must contain only letters.")]
    [EnumDataType(typeof(Priority), ErrorMessage = "Invalid user Priority.")]
    public string Priority { get; set; }

    [Required(ErrorMessage = "Category is required.")]
    [StringLength(20, ErrorMessage = "Category cannot be longer than 20 characters.")]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "Task description must contain only letters.")]
    [EnumDataType(typeof(Category), ErrorMessage = "Invalid user Category.")]
    public string Category { get; set; }

    [Required(ErrorMessage = "Task state is required.")]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "State description must contain only letters.")]
    [EnumDataType(typeof(State), ErrorMessage = "Invalid user State.")]
    public string State { get; set; }
}