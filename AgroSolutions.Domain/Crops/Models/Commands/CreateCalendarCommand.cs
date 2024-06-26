using System.ComponentModel.DataAnnotations;

namespace Presentation.Request;

public class CreateCalendarCommand
{
    [Required]
    public DateOnly Fecha { get; set; }
    
    [Required]
    [MaxLength(70)]
    public string Actividad { get; set; }

    [Required]
    [MaxLength(70)]
    public string Estado { get; set; }
}