using System.ComponentModel.DataAnnotations;


namespace Presentation.Request;

public class CreatePendingCollections
{
    [Required] public string Type { get; set; }
    
    [Required] public string Cost { get; set; }

    [Required] public string Description { get; set; }
}