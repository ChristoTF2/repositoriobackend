namespace _1_API.Response;

public class PendingResponse
{
    public string Name { get; set; }
    public string Description { get; set; }
    public DateTime CreateDate { get; set; }
    public DateTime DueDate { get; set; }
    public string AssignedTo { get; set; }
    public string Priority { get; set; }
    public string Category { get; set; }
    public string State { get; set; }
    
}