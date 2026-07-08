using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VulneraScan.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Index()
        {
            // If user is already authenticated, redirect to dashboard
            if (User?.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Index", "Dashboard");
            }

            return View();
        }

        [HttpGet]
        public IActionResult Error()
        {
            return View();
        }

        [HttpGet]
        public IActionResult About()
        {
            ViewData["Title"] = "About";
            return View();
        }

        [HttpGet]
        public IActionResult Contact()
        {
            ViewData["Title"] = "Contact";
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult TermsAndConditions()
        {
            ViewData["Title"] = "Terms and Conditions";
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult PrivacyPolicy()
        {
            ViewData["Title"] = "Privacy Policy";
            return View();
        }
    }
}
