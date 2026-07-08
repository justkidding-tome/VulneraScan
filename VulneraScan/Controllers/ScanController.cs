using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulneraScan.Data;
using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;
using VulneraScan.ViewModels.Scan;

namespace VulneraScan.Controllers
{
    [Authorize(Roles = "SecurityAnalyst,Administrator")]
    public class ScanController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<ScanController> _logger;

        public ScanController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            IServiceScopeFactory scopeFactory,
            IAuditLogService auditLogService,
            ILogger<ScanController> logger)
        {
            _context = context;
            _userManager = userManager;
            _scopeFactory = scopeFactory;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SubmitTarget(ScanTargetViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View("Index", model);
            }

            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                // Validate and sanitize input
                var (isValid, sanitizedUrl, errorMessage) = InputValidator.ValidateTarget(model.TargetUrl);
                if (!isValid)
                {
                    ModelState.AddModelError(string.Empty, errorMessage ?? "Invalid target URL or IP address.");
                    return View("Index", model);
                }

                // Extract IP/Domain from URL
                string? ipAddress = null;
                string? domain = null;

                if (InputValidator.IsValidIpAddress(sanitizedUrl))
                {
                    ipAddress = sanitizedUrl;
                }
                else if (InputValidator.IsValidDomain(sanitizedUrl))
                {
                    domain = sanitizedUrl;
                }
                else if (Uri.TryCreate(sanitizedUrl, UriKind.Absolute, out var uri))
                {
                    domain = uri.Host;
                }

                // Create scan target
                var scanTarget = new ScanTarget
                {
                    TargetUrl = sanitizedUrl,
                    IpAddress = ipAddress,
                    Domain = domain,
                    ScanStatus = ScanStatus.Pending,
                    CreatedAt = DateTime.UtcNow,
                    UserId = user.Id
                };

                _context.ScanTargets.Add(scanTarget);
                await _context.SaveChangesAsync();

                // Log audit
                var ipAddressUser = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(user.Id, Constants.AuditActions.ScanCreated, $"Scan target created: {sanitizedUrl}", ipAddressUser);

                _logger.LogInformation("Scan target created for user {UserId}: {TargetUrl}", user.Id, sanitizedUrl);

                // Optionally start scan immediately (async)
                var scanTargetId = scanTarget.Id;
                var userId = user.Id;

                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var scope = _scopeFactory.CreateScope();
                        var scopedOrchestrator = scope.ServiceProvider.GetRequiredService<IScanOrchestrator>();
                        await scopedOrchestrator.ExecuteScanAsync(scanTargetId, userId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error executing scan for target {ScanTargetId}", scanTargetId);
                    }
                });

                return RedirectToAction(nameof(Results), new { id = scanTargetId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error submitting scan target");
                ModelState.AddModelError(string.Empty, "An error occurred while submitting the scan target.");
                return View("Index", model);
            }
        }

        [HttpGet]
        public async Task<IActionResult> Results(int id)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return Unauthorized();

                var scanTarget = await _context.ScanTargets
                    .Include(s => s.PortResults)
                    .Include(s => s.DiscoveredServices)
                    .Include(s => s.Vulnerabilities)
                    .Include(s => s.ScanReport)
                    .FirstOrDefaultAsync(s => s.Id == id);

                if (scanTarget == null)
                    return NotFound();

                // Check if user is owner or admin
                var userRoles = await _userManager.GetRolesAsync(user);
                if (scanTarget.UserId != user.Id && !userRoles.Contains("Administrator"))
                    return Forbid();

                var report = await _context.ScanReports
                    .FirstOrDefaultAsync(r => r.ScanTargetId == id);

                report ??= scanTarget.ScanReport;
                var vulnerabilities = scanTarget.Vulnerabilities?.ToList() ?? new List<Vulnerability>();

                var viewModel = new ScanResultViewModel
                {
                    ScanTarget = scanTarget,
                    PortResults = scanTarget.PortResults?.ToList() ?? new List<PortResult>(),
                    DiscoveredServices = scanTarget.DiscoveredServices?.ToList() ?? new List<DiscoveredService>(),
                    Vulnerabilities = vulnerabilities,
                    Report = report,
                    HighCount = vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.High),
                    MediumCount = vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.Medium),
                    LowCount = vulnerabilities.Count(v => v.SeverityLevel == SeverityLevel.Low),
                    ScanDuration = scanTarget.CompletedAt.HasValue && scanTarget.StartedAt.HasValue
                        ? scanTarget.CompletedAt.Value - scanTarget.StartedAt.Value
                        : null
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving scan results");
                return RedirectToAction("Index", "Dashboard");
            }
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
                IQueryable<ScanTarget> query = _context.ScanTargets.Include(s => s.User);

                // Admins see all scans, analysts see only theirs
                if (!userRoles.Contains("Administrator"))
                {
                    query = query.Where(s => s.UserId == user.Id);
                }

                var scans = await query
                    .OrderByDescending(s => s.CreatedAt)
                    .ToListAsync();

                return View(scans);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving scan list");
                TempData["ErrorMessage"] = "An error occurred while retrieving scans.";
                return RedirectToAction("Index", "Dashboard");
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

                var scanTarget = await _context.ScanTargets.FindAsync(id);
                if (scanTarget == null)
                    return NotFound();

                // Only owner or admin can archive
                var userRoles = await _userManager.GetRolesAsync(user);
                if (scanTarget.UserId != user.Id && !userRoles.Contains("Administrator"))
                    return Forbid();

                scanTarget.IsArchived = true;
                await _context.SaveChangesAsync();

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(user.Id, Constants.AuditActions.ScanArchived, $"Scan archived: {scanTarget.TargetUrl}", ipAddress);

                TempData["SuccessMessage"] = "Scan archived successfully.";
                return RedirectToAction(nameof(List));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error archiving scan");
                TempData["ErrorMessage"] = "An error occurred while archiving the scan.";
                return RedirectToAction(nameof(List));
            }
        }
    }
}
