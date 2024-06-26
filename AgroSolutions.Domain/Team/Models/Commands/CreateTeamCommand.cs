using System.ComponentModel.DataAnnotations;
using Domain;

namespace Presentation.Request;

public class CreateTeamCommand
{
    [Required(ErrorMessage = "Task name is required.")]
    [RegularExpression(@"^[A-Za-z0-9]{4,10}$", ErrorMessage = "Team code must be alphanumeric and between 3 and 10 characters.")]
    public string TeamCode { get; set; }

    [Required(ErrorMessage = "Budget is required.")]
    [Range(0, 1000000000, ErrorMessage = "Budget must be between  0 y 1,000,000,000.")]
    [RegularExpression(@"^\d+(\.\d{1,2})?$", ErrorMessage = "Budget must have up to 2 decimal places")]
    public decimal Budget { get; set; }

    [Required(ErrorMessage = "CropCode is required.")]
    [RegularExpression(@"^[A-Za-z0-9]{4,10}$", ErrorMessage = "Crop code must be alphanumeric and have  4 y 10 characters.")]
    public string CropCode { get; set; }
    
    [MaxLength(1)]
    public List<CreateAdvicerCommand> Advicers { get; set; }      
    [MaxLength(2)]
    public List<CreateProducerCommand> Producers { get; set; }  
    
}


  