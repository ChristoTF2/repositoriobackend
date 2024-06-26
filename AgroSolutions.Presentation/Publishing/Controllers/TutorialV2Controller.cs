using Microsoft.AspNetCore.Mvc;

namespace Presentation.Controllers;

public class FinanceV2Controller : Controller
{
    // GET
    public IActionResult Index()
    {
        return View();
    }
}