using System.ComponentModel.DataAnnotations;

namespace Presentation.Request;

public class CreateAdviserCommand
{
    [Required]
    [MaxLength(90)]
    public string Nombre { get; set; }

    [MaxLength(300)]
    public string Descripcion { get; set; }

    [Range(0.0, 5.0)]
    public double Calificacion { get; set; }
}