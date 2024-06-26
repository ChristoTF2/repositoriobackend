namespace Domain;

public class Team : ModelBase
{
    public string TeamCode { get; set; }
    public decimal Budget { get; set; }
    public string CropCode { get; set; }
    public List<Advicer> Advicers { get; set; }
    public List<Producer> Producers { get; set; }
}