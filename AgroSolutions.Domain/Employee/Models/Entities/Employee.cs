namespace Domain;

public class Employee : ModelBase
{
    public string Name { get; set; }
    public string LastName { get; set; }
    public int Age { get; set; }
    public string Dni { get; set; }
    public string Job  { get; set; }
    public float Salary { get; set; }
    public string Phone  { get; set; }
    public string PhotoUrl { get; set; }
    public int TeamId { get; set; }
}

public enum Job{
    Adviser,
    Producer
}

