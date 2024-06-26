using System.ComponentModel.DataAnnotations;
using Domain;

namespace Presentation.Request;

public class CreateEmployeeCommand
{
    [Required(ErrorMessage = "Name date is required.")]
    [RegularExpression(@"^[A-Za-z]{1,50}$", ErrorMessage = "Name must contain only letters and be up to 50 characters long.")]
    public string Name { get; set; }
    
    [Required(ErrorMessage = "Last name date is required.")]
    [RegularExpression(@"^[A-Za-z]{1,50}$", ErrorMessage = "Last name must contain only letters and be up to 50 characters long.")]
    public string LastName { get; set; }
    
    [Required(ErrorMessage = "Last name date is required.")]
    [Range(18, 150, ErrorMessage = "Age must be between 18 and 150.")]
    public int Age { get; set; }
    
    [Required(ErrorMessage = "Dni date is required.")]
    [StringLength(8, MinimumLength = 8, ErrorMessage = "DNI must be 8 digits.")]
    [RegularExpression(@"^\d{8}$", ErrorMessage = "DNI must contain only numbers.")]
    public string Dni { get; set; }
    
    [Required(ErrorMessage = "Job date is required.")]
    [StringLength(10, ErrorMessage = "Job title must be up to 10 characters long.")]
    [EnumDataType(typeof(Job), ErrorMessage = "Invalid user job.")]
    public string Job  { get; set; }

    [Required(ErrorMessage = "Salary date is required.")]
    [Range(1200, 1000000, ErrorMessage = "Salary must be between 1,200 and 1,000,000.")]
    [RegularExpression(@"^\d+(\.\d{1,2})?$", ErrorMessage = "Salary must have up to 2 decimal places.")]
    public float Salary { get; set; }

    [Required(ErrorMessage = "Phone date is required.")]
    [RegularExpression(@"^\d{9,10}$", ErrorMessage = "Enter a valid phone number.")]
    public string Phone  { get; set; }
    
    [Required(ErrorMessage = "PhotoUrl date is required.")]
    [Url(ErrorMessage = "Invalid URL format.")]
    public string PhotoUrl { get; set; }
}