using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulneraScan.Data;
using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.ViewModels.Dashboard;

namespace VulneraScan.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<DashboardController> _logger;

        public DashboardController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            ILogger<DashboardController> logger)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            var userRoles = await _userManager.GetRolesAsync(user);

            if (userRoles.Contains("Administrator"))
            {
                return RedirectToAction(nameof(AdminDashboard));
            }

            return RedirectToAction(nameof(AnalystDashboard));
        }

        [Authorize(Roles = "Administrator")]
        [HttpGet]
        public async Task<IActionResult> AdminDashboard()
        {
            try
            {
                var viewModel = new AdminDashboardViewModel
                {
                    // User Statistics
                    TotalUsers = await _context.Users.CountAsync(),
                    ActiveUsers = await _context.Users.CountAsync(u => u.IsActive),

                    // Scan Statistics
                    TotalScans = await _context.ScanTargets.CountAsync(),
                    CompletedScans = await _context.ScanTargets.CountAsync(s => s.ScanStatus == ScanStatus.Completed),

                    // Report Statistics
                    TotalReports = await _context.ScanReports.CountAsync(),

                    // Vulnerability Statistics
                    TotalVulnerabilities = await _context.Vulnerabilities.CountAsync(),
                    HighRiskFindings = await _context.Vulnerabilities.CountAsync(v => v.SeverityLevel == SeverityLevel.High),
                    MediumRiskFindings = await _context.Vulnerabilities.CountAsync(v => v.SeverityLevel == SeverityLevel.Medium),
                    LowRiskFindings = await _context.Vulnerabilities.CountAsync(v => v.SeverityLevel == SeverityLevel.Low),

                    // Recent Activity
                    RecentScans = await _context.ScanTargets
                        .Include(s => s.User)
                        .OrderByDescending(s => s.CreatedAt)
                        .Take(10)
                        .ToListAsync(),

                    RecentReports = await _context.ScanReports
                        .Include(r => r.User)
                        .OrderByDescending(r => r.GeneratedAt)
                        .Take(10)
                        .ToListAsync()
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading admin dashboard");
                TempData["ErrorMessage"] = "An error occurred while loading the dashboard.";
                return View(new AdminDashboardViewModel());
            }
        }

        [Authorize(Roles = "SecurityAnalyst")]
        [HttpGet]
        public async Task<IActionResult> AnalystDashboard()
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                var viewModel = new AnalystDashboardViewModel
                {
                    // Personal Scan Statistics
                    PersonalTotalScans = await _context.ScanTargets.CountAsync(s => s.UserId == user.Id),
                    PersonalCompletedScans = await _context.ScanTargets.CountAsync(s => s.UserId == user.Id && s.ScanStatus == ScanStatus.Completed),

                    // Personal Vulnerability Statistics
                    PersonalTotalVulnerabilities = await _context.Vulnerabilities
                        .CountAsync(v => v.ScanTarget.UserId == user.Id),
                    PersonalHighRisk = await _context.Vulnerabilities
                        .CountAsync(v => v.ScanTarget.UserId == user.Id && v.SeverityLevel == SeverityLevel.High),
                    PersonalMediumRisk = await _context.Vulnerabilities
                        .CountAsync(v => v.ScanTarget.UserId == user.Id && v.SeverityLevel == SeverityLevel.Medium),
                    PersonalLowRisk = await _context.Vulnerabilities
                        .CountAsync(v => v.ScanTarget.UserId == user.Id && v.SeverityLevel == SeverityLevel.Low),

                    // Recent Activity
                    RecentScans = await _context.ScanTargets
                        .Where(s => s.UserId == user.Id)
                        .OrderByDescending(s => s.CreatedAt)
                        .Take(10)
                        .ToListAsync(),

                    RecentReports = await _context.ScanReports
                        .Where(r => r.UserId == user.Id)
                        .OrderByDescending(r => r.GeneratedAt)
                        .Take(10)
                        .ToListAsync()
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading analyst dashboard");
                TempData["ErrorMessage"] = "An error occurred while loading the dashboard.";
                return View(new AnalystDashboardViewModel());
            }
        }
    }
}
