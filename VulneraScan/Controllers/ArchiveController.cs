using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulneraScan.Data;
using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Controllers
{
    [Authorize]
    public class ArchiveController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<ArchiveController> _logger;

        public ArchiveController(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            IAuditLogService auditLogService,
            ILogger<ArchiveController> logger)
        {
            _userManager = userManager;
            _context = context;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [Authorize(Roles = Constants.Roles.Administrator)]
        public async Task<IActionResult> Users()
        {
            try
            {
                var users = await _userManager.Users
                    .Where(u => u.IsArchived)
                    .OrderByDescending(u => u.CreatedAt)
                    .ToListAsync();
                
                return View(users);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving archived users");
                TempData["ErrorMessage"] = "An error occurred while retrieving archived users.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpGet]
        public async Task<IActionResult> Scans()
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null) return Unauthorized();

                var isAdmin = await _userManager.IsInRoleAsync(currentUser, Constants.Roles.Administrator);

                var query = _context.ScanTargets.IgnoreQueryFilters().Where(s => s.IsArchived);

                if (!isAdmin)
                {
                    query = query.Where(s => s.UserId == currentUser.Id);
                }

                var scans = await query
                    .Include(s => s.User)
                    .OrderByDescending(s => s.CreatedAt)
                    .ToListAsync();

                return View(scans);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving archived scans");
                TempData["ErrorMessage"] = "An error occurred while retrieving archived scans.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpGet]
        public async Task<IActionResult> Reports()
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null) return Unauthorized();

                var isAdmin = await _userManager.IsInRoleAsync(currentUser, Constants.Roles.Administrator);

                var query = _context.ScanReports.IgnoreQueryFilters().Where(r => r.IsArchived);

                if (!isAdmin)
                {
                    query = query.Where(r => r.UserId == currentUser.Id);
                }

                var reports = await query
                    .Include(r => r.User)
                    .Include(r => r.ScanTarget)
                    .OrderByDescending(r => r.GeneratedAt)
                    .ToListAsync();

                return View(reports);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving archived reports");
                TempData["ErrorMessage"] = "An error occurred while retrieving archived reports.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Constants.Roles.Administrator)]
        public async Task<IActionResult> RestoreUser(string id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null) return Unauthorized();

                var user = await _userManager.FindByIdAsync(id);
                if (user == null) return NotFound();

                user.IsArchived = false;
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    _logger.LogInformation("Admin restored user");
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                    await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.UserRestored, $"User {user.UserName} restored", ipAddress);

                    TempData["SuccessMessage"] = "User restored successfully.";
                }
                else
                {
                    TempData["ErrorMessage"] = "Failed to restore the user.";
                }

                return RedirectToAction(nameof(Users));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error restoring user");
                TempData["ErrorMessage"] = "An error occurred while restoring the user.";
                return RedirectToAction(nameof(Users));
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RestoreScan(int id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null) return Unauthorized();

                var scan = await _context.ScanTargets.IgnoreQueryFilters().FirstOrDefaultAsync(s => s.Id == id && s.IsArchived);
                if (scan == null) return NotFound();

                var isAdmin = await _userManager.IsInRoleAsync(currentUser, Constants.Roles.Administrator);
                if (!isAdmin && scan.UserId != currentUser.Id)
                {
                    return Forbid();
                }

                scan.IsArchived = false;
                await _context.SaveChangesAsync();

                _logger.LogInformation("User {UserId} restored scan {ScanId}", currentUser.Id, id);
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.ScanRestored, $"Scan restored: {scan.TargetUrl}", ipAddress);

                TempData["SuccessMessage"] = "Scan restored successfully.";
                return RedirectToAction(nameof(Scans));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error restoring scan");
                TempData["ErrorMessage"] = "An error occurred while restoring the scan.";
                return RedirectToAction(nameof(Scans));
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RestoreReport(int id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null) return Unauthorized();

                var report = await _context.ScanReports.IgnoreQueryFilters().FirstOrDefaultAsync(r => r.Id == id && r.IsArchived);
                if (report == null) return NotFound();

                var isAdmin = await _userManager.IsInRoleAsync(currentUser, Constants.Roles.Administrator);
                if (!isAdmin && report.UserId != currentUser.Id)
                {
                    return Forbid();
                }

                report.IsArchived = false;
                await _context.SaveChangesAsync();

                _logger.LogInformation("User {UserId} restored report {ReportId}", currentUser.Id, id);
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                
                var action = isAdmin ? Constants.AuditActions.ReportRestoredByAdmin : Constants.AuditActions.ReportRestored;
                var details = isAdmin ? $"Report {id} restored by admin" : $"Report {id} restored";
                
                await _auditLogService.LogAsync(currentUser.Id, action, details, ipAddress);

                TempData["SuccessMessage"] = "Report restored successfully.";
                return RedirectToAction(nameof(Reports));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error restoring report");
                TempData["ErrorMessage"] = "An error occurred while restoring the report.";
                return RedirectToAction(nameof(Reports));
            }
        }
    }
}
