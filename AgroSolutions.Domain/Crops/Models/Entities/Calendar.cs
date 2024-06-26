using System.ComponentModel.DataAnnotations;

namespace Domain;

public class Calendar
{
    public int Id { get; set; }

    [Required]
    public DateOnly Fecha { get; set; }
    
    [Required]
    [MaxLength(70)]
    public string Actividad { get; set; }
    
    [Required]
    [MaxLength(70)]
    public string Estado { get; set; }
}