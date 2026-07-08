using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulneraScan.Data;
using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;
using VulneraScan.ViewModels.Report;

namespace VulneraScan.Controllers
{
    [Authorize(Roles = "SecurityAnalyst,Administrator")]
    public class ReportController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IPdfReportService _pdfReportService;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<ReportController> _logger;

        public ReportController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            IPdfReportService pdfReportService,
            IAuditLogService auditLogService,
            ILogger<ReportController> logger)
        {
            _context = context;
            _userManager = userManager;
            _pdfReportService = pdfReportService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> List()
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                var userRoles = await _userManager.GetRolesAsync(user);
                IQueryable<ScanReport> query = _context.ScanReports
                    .Include(r => r.User)
                    .Include(r => r.ScanTarget);

                // Admins see all reports, analysts see only theirs
                if (!userRoles.Contains("Administrator"))
                {
                    query = query.Where(r => r.UserId == user.Id);
                }

                var reports = await query
                    .OrderByDescending(r => r.GeneratedAt)
                    .ToListAsync();

                var viewModel = new ReportListViewModel
                {
                    Reports = reports
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving report list");
                TempData["ErrorMessage"] = "An error occurred while retrieving reports.";
                return RedirectToAction("Index", "Dashboard");
            }
        }

        [HttpGet]
        public async Task<IActionResult> Detail(int id)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                var report = await _context.ScanReports
                    .Include(r => r.User)
                    .Include(r => r.ScanTarget)
                        .ThenInclude(s => s.PortResults)
                    .Include(r => r.ScanTarget)
                        .ThenInclude(s => s.DiscoveredServices)
                    .Include(r => r.ScanTarget)
                        .ThenInclude(s => s.Vulnerabilities)
                            .ThenInclude(v => v.Recommendation)
                    .FirstOrDefaultAsync(r => r.Id == id);

                if (report == null)
                    return NotFound();

                // Check if user is owner or admin
                var userRoles = await _userManager.GetRolesAsync(user);
                if (report.UserId != user.Id && !userRoles.Contains("Administrator"))
                    return Forbid();

                var viewModel = new ReportDetailViewModel
                {
                    Report = report,
                    PortResults = report.ScanTarget.PortResults.ToList(),
                    DiscoveredServices = report.ScanTarget.DiscoveredServices.ToList(),
                    Vulnerabilities = report.ScanTarget.Vulnerabilities.ToList(),
                    HighCount = report.ScanTarget.Vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.High),
                    MediumCount = report.ScanTarget.Vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.Medium),
                    LowCount = report.ScanTarget.Vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.Low),
                    ScanDuration = report.ScanTarget.CompletedAt.HasValue && report.ScanTarget.StartedAt.HasValue
                        ? report.ScanTarget.CompletedAt.Value - report.ScanTarget.StartedAt.Value
                        : null
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving report details");
                return RedirectToAction(nameof(List));
            }
        }

        [HttpGet]
        public async Task<IActionResult> Print(int id)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                var report = await _context.ScanReports
                    .Include(r => r.User)
                    .Include(r => r.ScanTarget)
                        .ThenInclude(s => s.PortResults)
                    .Include(r => r.ScanTarget)
                        .ThenInclude(s => s.DiscoveredServices)
                    .Include(r => r.ScanTarget)
                        .ThenInclude(s => s.Vulnerabilities)
                            .ThenInclude(v => v.Recommendation)
                    .FirstOrDefaultAsync(r => r.Id == id);

                if (report == null)
                    return NotFound();

                // Check if user is owner or admin
                var userRoles = await _userManager.GetRolesAsync(user);
                if (report.UserId != user.Id && !userRoles.Contains("Administrator"))
                    return Forbid();

                var viewModel = new ReportDetailViewModel
                {
                    Report = report,
                    PortResults = report.ScanTarget.PortResults.ToList(),
                    DiscoveredServices = report.ScanTarget.DiscoveredServices.ToList(),
                    Vulnerabilities = report.ScanTarget.Vulnerabilities.ToList(),
                    HighCount = report.ScanTarget.Vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.High),
                    MediumCount = report.ScanTarget.Vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.Medium),
                    LowCount = report.ScanTarget.Vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.Low),
                    ScanDuration = report.ScanTarget.CompletedAt.HasValue && report.ScanTarget.StartedAt.HasValue
                        ? report.ScanTarget.CompletedAt.Value - report.ScanTarget.StartedAt.Value
                        : null
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error preparing print view");
                return RedirectToAction(nameof(List));
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DownloadPdf(int id)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                var report = await _context.ScanReports
                    .FirstOrDefaultAsync(r => r.Id == id);

                if (report == null)
                    return NotFound();

                // Check if user is owner or admin
                var userRoles = await _userManager.GetRolesAsync(user);
                if (report.UserId != user.Id && !userRoles.Contains("Administrator"))
                    return Forbid();

                // Generate PDF
                var pdfBytes = await _pdfReportService.GeneratePdfAsync(id);

                // Log audit
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(user.Id, Constants.AuditActions.ReportDownloaded, $"Report {id} downloaded", ipAddress);

                _logger.LogInformation("User {UserId} downloaded PDF for report {ReportId}", user.Id, id);

                return File(pdfBytes, "application/pdf", $"VulneraScan_Report_{id}_{DateTime.UtcNow:yyyyMMddHHmmss}.pdf");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating PDF report");
                TempData["ErrorMessage"] = "An error occurred while generating the PDF.";
                return RedirectToAction(nameof(Detail), new { id });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Archive(int id)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                var report = await _context.ScanReports.FindAsync(id);
                if (report == null)
                    return NotFound();

                var userRoles = await _userManager.GetRolesAsync(user);
                if (report.UserId != user.Id && !userRoles.Contains("Administrator"))
                    return Forbid();

                report.IsArchived = true;
                await _context.SaveChangesAsync();

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(user.Id, Constants.AuditActions.ReportArchived, $"Report {id} archived", ipAddress);

                TempData["SuccessMessage"] = "Report archived successfully.";
                return RedirectToAction(nameof(List));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error archiving report");
                TempData["ErrorMessage"] = "An error occurred while archiving the report.";
                return RedirectToAction(nameof(List));
            }
        }
    }
}
