using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulneraScan.Data;
using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Services;
using VulneraScan.Services.Interfaces;
using VulneraScan.ViewModels.Admin;

namespace VulneraScan.Controllers
{
    [Authorize(Roles = Constants.Roles.Administrator)]
    public class AdminController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<AdminController> _logger;
        private readonly IEncryptionService _encryptionService;

        public AdminController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext context,
            IAuditLogService auditLogService,
            ILogger<AdminController> logger,
            IEncryptionService encryptionService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
            _auditLogService = auditLogService;
            _logger = logger;
            _encryptionService = encryptionService;
        }

        [HttpGet]
        public async Task<IActionResult> Users()
        {
            try
            {
                var users = await _userManager.Users.Where(u => !u.IsArchived).ToListAsync();
                var userViewModels = new List<UserViewModel>();

                foreach (var user in users)
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    var scanCount = await _context.ScanTargets.CountAsync(s => s.UserId == user.Id);
                    var isLockedOut = await _userManager.IsLockedOutAsync(user);
                    var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);

                    userViewModels.Add(new UserViewModel
                    {
                        Id = user.Id,
                        FullName = _encryptionService.Decrypt(user.FullName),
                        Email = _encryptionService.Decrypt(user.Email ?? string.Empty),
                        IsActive = user.IsActive,
                        CreatedAt = user.CreatedAt,
                        Role = roles.FirstOrDefault() ?? "Unknown",
                        ScanCount = scanCount,
                        IsLockedOut = isLockedOut,
                        LockoutEnd = lockoutEnd,
                        AccessFailedCount = user.AccessFailedCount
                    });
                }

                var viewModel = new UserListViewModel
                {
                    Users = userViewModels.OrderByDescending(u => u.CreatedAt).ToList()
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving users list");
                TempData["ErrorMessage"] = "An error occurred while retrieving users.";
                return RedirectToAction("AdminDashboard", "Dashboard");
            }
        }

        [HttpGet]
        public IActionResult CreateUser()
        {
            return View(new CreateUserViewModel
            {
                AvailableRoles = GetAvailableRoles(),
                Role = Constants.Roles.SecurityAnalyst
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateUser(CreateUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                model.AvailableRoles = GetAvailableRoles();
                return View(model);
            }

            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                    return Unauthorized();

                // Check if email already exists
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError(nameof(model.Email), "Email is already in use.");
                    model.AvailableRoles = GetAvailableRoles();
                    return View(model);
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FullName = model.FullName,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // Assign role
                    if (!string.IsNullOrWhiteSpace(model.Role))
                    {
                        await _userManager.AddToRoleAsync(user, model.Role);
                    }

                    _logger.LogInformation("Admin created user");

                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                    await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.UserCreated, "User created", ipAddress);

                    TempData["SuccessMessage"] = "User created successfully.";
                    return RedirectToAction(nameof(Users));
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user");
                ModelState.AddModelError(string.Empty, "An error occurred while creating the user.");
            }

            model.AvailableRoles = GetAvailableRoles();
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> EditUser(string id)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    return NotFound();

                var roles = await _userManager.GetRolesAsync(user);

                var viewModel = new EditUserViewModel
                {
                    Id = user.Id,
                    FullName = user.FullName,
                    Email = user.Email ?? string.Empty,
                    IsActive = user.IsActive,
                    Role = roles.FirstOrDefault() ?? Constants.Roles.SecurityAnalyst,
                    AvailableRoles = GetAvailableRoles()
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user for editing");
                return RedirectToAction(nameof(Users));
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditUser(EditUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                model.AvailableRoles = GetAvailableRoles();
                return View(model);
            }

            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                    return Unauthorized();

                var user = await _userManager.FindByIdAsync(model.Id);
                if (user == null)
                    return NotFound();

                // Update basic info
                user.FullName = model.FullName;
                user.IsActive = model.IsActive;

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    // Update role if changed
                    var currentRoles = await _userManager.GetRolesAsync(user);
                    if (!string.IsNullOrWhiteSpace(model.Role) && !currentRoles.Contains(model.Role))
                    {
                        await _userManager.RemoveFromRolesAsync(user, currentRoles);
                        await _userManager.AddToRoleAsync(user, model.Role);
                    }

                    _logger.LogInformation("Admin updated user");

                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                    await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.UserUpdated, "User updated", ipAddress);

                    TempData["SuccessMessage"] = "User updated successfully.";
                    return RedirectToAction(nameof(Users));
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user");
                ModelState.AddModelError(string.Empty, "An error occurred while updating the user.");
            }

            model.AvailableRoles = GetAvailableRoles();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ArchiveUser(string id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                    return Unauthorized();

                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    return NotFound();

                // Prevent self-archiving
                if (user.Id == currentUser.Id)
                {
                    TempData["ErrorMessage"] = "You cannot archive your own account.";
                    return RedirectToAction(nameof(Users));
                }

                user.IsArchived = true;
                user.IsActive = false; // Optional: mark as inactive when archived
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    _logger.LogInformation("Admin archived user");

                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                    await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.UserArchived, "User archived", ipAddress);

                    TempData["SuccessMessage"] = "User archived successfully.";
                }
                else
                {
                    TempData["ErrorMessage"] = "An error occurred while deleting the user.";
                }

                return RedirectToAction(nameof(Users));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error archiving user");
                TempData["ErrorMessage"] = "An error occurred while archiving the user.";
                return RedirectToAction(nameof(Users));
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleUserStatus(string id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                    return Unauthorized();

                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    return Json(new { success = false, message = "User not found." });

                // Prevent self-deactivation
                if (user.Id == currentUser.Id)
                    return Json(new { success = false, message = "You cannot change the status of your own account." });

                user.IsActive = !user.IsActive;
                var result = await _userManager.UpdateAsync(user);

                if (!result.Succeeded)
                    return Json(new { success = false, message = "Failed to update user status." });

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                var action = user.IsActive ? "activated" : "deactivated";
                await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.UserUpdated,
                    $"User account {action} by admin", ipAddress);

                _logger.LogInformation("Admin {AdminId} {Action} user {UserId}", currentUser.Id, action, user.Id);

                return Json(new { success = true, isActive = user.IsActive });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error toggling user status");
                return Json(new { success = false, message = "An error occurred." });
            }
        }

        [HttpGet]
        public async Task<IActionResult> Statistics()
        {
            try
            {
                var stats = new AdminStatisticsViewModel
                {
                    TotalUsers = await _userManager.Users.CountAsync(u => !u.IsArchived),
                    ActiveUsers = await _userManager.Users.CountAsync(u => u.IsActive && !u.IsArchived),
                    InactiveUsers = await _userManager.Users.CountAsync(u => !u.IsActive && !u.IsArchived),
                    TotalScans = await _context.ScanTargets.CountAsync(),
                    CompletedScans = await _context.ScanTargets.CountAsync(s => s.ScanStatus == Models.Enums.ScanStatus.Completed),
                    PendingScans = await _context.ScanTargets.CountAsync(s => s.ScanStatus == Models.Enums.ScanStatus.Pending),
                    TotalReports = await _context.ScanReports.CountAsync(),
                    TotalVulnerabilities = await _context.Vulnerabilities.CountAsync(),
                    TotalPortResults = await _context.PortResults.CountAsync(),
                    TotalServices = await _context.DiscoveredServices.CountAsync(),
                    AuditLogEntries = await _context.AuditLogs.CountAsync()
                };

                return View(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving system statistics");
                TempData["ErrorMessage"] = "An error occurred while retrieving statistics.";
                return RedirectToAction("AdminDashboard", "Dashboard");
            }
        }

        [HttpGet]
        public async Task<IActionResult> ManageReports()
        {
            try
            {
                var reports = await _context.ScanReports
                    .Include(r => r.User)
                    .Include(r => r.ScanTarget)
                    .OrderByDescending(r => r.GeneratedAt)
                    .ToListAsync();

                return View(new ManageReportsViewModel
                {
                    Reports = reports
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving reports for management");
                TempData["ErrorMessage"] = "An error occurred while retrieving reports.";
                return RedirectToAction("AdminDashboard", "Dashboard");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ArchiveReport(int id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                    return Unauthorized();

                var report = await _context.ScanReports.FindAsync(id);
                if (report == null)
                    return NotFound();

                report.IsArchived = true;
                await _context.SaveChangesAsync();

                _logger.LogInformation("Admin {AdminId} archived report {ReportId}", currentUser.Id, id);

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.ReportArchivedByAdmin, $"Report {id} archived by admin", ipAddress);

                TempData["SuccessMessage"] = "Report archived successfully.";
                return RedirectToAction(nameof(ManageReports));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error archiving report");
                TempData["ErrorMessage"] = "An error occurred while archiving the report.";
                return RedirectToAction(nameof(ManageReports));
            }
        }

        [HttpGet]
        public async Task<IActionResult> AuditLogs()
        {
            try
            {
                var logs = await _context.AuditLogs
                    .Include(l => l.User)
                    .OrderByDescending(l => l.Timestamp)
                    .Take(1000)
                    .ToListAsync();

                return View(new AuditLogListViewModel
                {
                    Logs = logs
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving audit logs");
                TempData["ErrorMessage"] = "An error occurred while retrieving audit logs.";
                return RedirectToAction("AdminDashboard", "Dashboard");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UnlockAccount(string id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                    return Unauthorized();

                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    return NotFound();

                // Unlock the account by removing lockout and resetting failed attempts
                var lockoutResult = await _userManager.SetLockoutEndDateAsync(user, null);
                if (!lockoutResult.Succeeded)
                {
                    _logger.LogError("Error unlocking account {UserId}", user.Id);
                    TempData["ErrorMessage"] = "An error occurred while unlocking the account.";
                    return RedirectToAction(nameof(Users));
                }

                // Reset failed login attempts
                var resetResult = await _userManager.ResetAccessFailedCountAsync(user);
                if (!resetResult.Succeeded)
                {
                    _logger.LogError("Error resetting access failed count for {UserId}", user.Id);
                }

                // Clear lockout information
                user.LockoutReason = null;
                user.LockoutExpiresAt = null;
                await _userManager.UpdateAsync(user);

                _logger.LogInformation("Admin unlocked account");

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(currentUser.Id, Constants.AuditActions.UserUpdated, 
                    "Account unlocked by admin", ipAddress);

                TempData["SuccessMessage"] = "Account has been unlocked successfully.";
                return RedirectToAction(nameof(Users));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unlocking account");
                TempData["ErrorMessage"] = "An error occurred while unlocking the account.";
                return RedirectToAction(nameof(Users));
            }
        }

        private static List<string> GetAvailableRoles()
        {
            return new List<string>
            {
                Constants.Roles.Administrator,
                Constants.Roles.SecurityAnalyst
            };
        }
    }
}
