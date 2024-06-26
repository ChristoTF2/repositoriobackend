using System.ComponentModel.DataAnnotations;

namespace Presentation.Request;

public class CreateFinanceCommand
{
    [Required] public string Month { get; set; }
    
    public string Incomes { get; set; }

    public string Bills { get; set; }
    
    public string Earning { get; set; }
}