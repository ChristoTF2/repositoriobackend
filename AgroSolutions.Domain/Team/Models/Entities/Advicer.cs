namespace Domain;

public class Advicer: ModelBase
{
    public string Name { get; set; }
    public string Dni { get; set; }
    public int TeamId { get; set; }
    public Team Team { get; set; }
}