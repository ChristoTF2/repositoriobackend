namespace _1_API.Response;

public class CalendarResponse
{
    public int Id { get; set; }
    public DateOnly Fecha { get; set; }
    public string Actividad { get; set; }
    public string Estado { get; set; }
}