using System.ComponentModel.DataAnnotations;

namespace Presentation.Request;

public class CreateCropsCommand
{
    [MaxLength(30)]
    public string Estado { get; set; }

    [Range(1, int.MaxValue)]
    public int Area { get; set; }

    [Required]
    [Range(0.0, double.MaxValue)]
    public double Costo { get; set; }

    [Required]
    [MaxLength(90)]
    public string Producto { get; set; }

    [Range(0.0, double.MaxValue)]
    public double Retorno { get; set; }

    [MaxLength(100)]
    public string Localizacion { get; set; }

    [MaxLength(100)]
    public string Notificaciones { get; set; }

    public int AsesorId { get; set; }

    [Url]
    public string ImageUrl { get; set; }

    public List<CreateCalendarCommand> Calendars { get; set; }
}