using System.ComponentModel.DataAnnotations;

namespace Presentation.Request;

public class CreateProducerCommand
{
    [Required(ErrorMessage = "Name date is required.")]
    [RegularExpression(@"^[A-Za-z]{1,50}$", ErrorMessage = "Name must contain only letters and be up to 50 characters long.")]
    public string Name { get; set; }
   
    [Required(ErrorMessage = "Dni date is required.")]
    [StringLength(8, MinimumLength = 8, ErrorMessage = "DNI must be 8 digits.")]
    [RegularExpression(@"^\d{8}$", ErrorMessage = "DNI must contain only numbers.")]
    public string Dni { get; set; }
    

}