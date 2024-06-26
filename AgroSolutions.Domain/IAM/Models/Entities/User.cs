using System.ComponentModel.DataAnnotations;
using Domain;

public class User : ModelBase
{
    public string Username { get; set; }
    public string DniOrRuc { get; set; }
    public string CompanyName { get; set; }
    public string EmailAddress { get; set; }
    public string Phone { get; set; }
    public string Role { get; set; }
    public string PasswordHashed { get; set; }
    public string ConfirmPassword { get; set; }
    public List<Pending> Pendings { get; set; }
}


public enum UserRole{
    Farmer,
    Seller,
    Admin
}
