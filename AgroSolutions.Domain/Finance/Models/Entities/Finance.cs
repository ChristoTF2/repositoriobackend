using System.ComponentModel.DataAnnotations;

namespace Domain;

public class Finance : ModelBase
{
    [Required] [MaxLength(10)] public string Month { get; set; }
    
     [Required]  public string Incomes { get; set; }
    
    [Required] public string Bills { get; set; }
    
    [Required] public string Earning { get; set; }
    
}