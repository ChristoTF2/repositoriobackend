namespace Shared;

public static class Constants
{
    public static int IGV { get; set; }

    public static int MAX_TUTORIALS { get; set; } = 100;
    public static int MIN_SECCTIONS { get; set; } = 2;
    public const int CALIFICACION_MIN = 0;
    public const int CALIFICACION_MAX = 5;
    public const int AREA_MIN = 1; 
    public const double COSTO_MIN = 0.1; 
    public static int MAX_PENDING { get; set; } = 30;

    public static int TIME_READ { get; set; } = 5;

    public static string ToUpperFirstLetter(string str)
    {
        if (string.IsNullOrEmpty(str))
            return str;

        return char.ToUpper(str[0]) + str.Substring(1).ToLower();
    }
}