using System;
using _1_API.Response;

namespace Domain;

public class Pending: ModelBase
{
    public string Name { get; set; }
    public string Description { get; set; }
    public DateTime DueDate { get; set; }
    public string AssignedTo { get; set; }
    public string Priority { get; set; }
    public string Category { get; set; }
    public string State { get; set; }
}

public enum Priority{
    High,
    Medium,
    Low
}

public enum Category{
    Crop,
    Production,
    Operation,
    Distribution,
    Market,
    Specialization
}

public enum State{
    ToDo,
    Doing,
    Done
}

