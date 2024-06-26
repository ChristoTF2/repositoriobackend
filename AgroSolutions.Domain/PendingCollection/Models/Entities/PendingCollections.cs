using System.ComponentModel.DataAnnotations;

namespace Domain;

public class PendingCollections : ModelBase
{
    [Required] [MaxLength(15)] public string Type { get; set; }

    [Required] public string Cost { get; set; }

    [Required] [MaxLength(120)] public string Description { get; set; }
}