using System.ComponentModel.DataAnnotations;

namespace Presentation.Request;

public class UpdateFinanceCommand
{
    [Required] public int Id { get; set; }
    
    [Required] public string Month { get; set; }

    [Required] public string Incomes { get; set; }

    [Required] public string Bills { get; set; }
    
    [Required] public string Earning { get; set; }
}