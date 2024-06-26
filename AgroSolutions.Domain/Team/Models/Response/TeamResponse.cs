namespace _1_API.Response;

public class TeamResponse
{
    public string TeamCode { get; set; }
    public decimal Budget { get; set; }
    public string CropCode { get; set; }
    public List<AdvicerResponse> Advicers { get; set; }
    public List<ProducerResponse> Producers { get; set; }
}