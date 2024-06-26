namespace _1_API.Response;

public class CropsResponse
{
    public int Id { get; set; }

    public string Estado { get; set; }

    public int Area { get; set; }

    public double Costo { get; set; }

    public string Producto { get; set; }

    public double Retorno { get; set; }
    
    public string Localizacion { get; set; }

    public string Notificaciones { get; set; }
    
    public int AsesorId { get; set; }
    
    public string ImageUrl { get; set; }
    
    public List<CalendarResponse> Calendars { get; set; }
}