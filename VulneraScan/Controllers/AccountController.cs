using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using VulneraScan.Models;
using VulneraScan.Helpers;
using VulneraScan.Services.Interfaces;
using VulneraScan.ViewModels.Account;


namespace VulneraScan.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly IAuditLogService _auditLogService;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<AccountController> logger,
            IAuditLogService auditLogService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _auditLogService = auditLogService;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
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
                        // Assign SecurityAnalyst role by default
                        await _userManager.AddToRoleAsync(user, "SecurityAnalyst");

                        _logger.LogInformation("User registered successfully.");

                        // Log audit — use the defined constant so action names are consistent
                        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                        await _auditLogService.LogAsync(user.Id, Constants.AuditActions.UserCreated, "New user registered", ipAddress);

                        return RedirectToAction(nameof(LoginSuccess));
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                catch (Exception ex)
                {
                    // Log the full exception server-side but never expose internal details to the client.
                    _logger.LogError(ex, "Error during user registration");
                    ModelState.AddModelError(string.Empty, "An error occurred during registration. Please try again.");
                }
            }

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                try
                {
                    var user = await _userManager.FindByEmailAsync(model.Email);

                    if (user != null && !user.IsActive)
                    {
                        ModelState.AddModelError(string.Empty, "Your account has been deactivated.");
                        return View(model);
                    }

                    // Check if account is already locked out
                    if (user != null && await _userManager.IsLockedOutAsync(user))
                    {
                        _logger.LogWarning("Login attempt on locked account.");
                        return RedirectToAction(nameof(Lockout), new { email = model.Email });
                    }

                    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);

                    if (result.Succeeded)
                    {
                        // Successful login - reset failed attempt counter and clear lockout info
                        if (user != null)
                        {
                            // Reset failed access attempts on successful login
                            await _userManager.ResetAccessFailedCountAsync(user);

                            // Clear lockout information
                            user.LockoutReason = null;
                            user.LockoutExpiresAt = null;
                            await _userManager.UpdateAsync(user);

                            _logger.LogInformation("User logged in successfully.");

                            // Log audit — use the defined constant
                            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                            await _auditLogService.LogAsync(user.Id, Constants.AuditActions.UserLogin, "User logged in", ipAddress);
                        }

                        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                        {
                            return Redirect(returnUrl);
                        }

                        var userRoles = await _userManager.GetRolesAsync(user);
                        if (userRoles.Contains(Constants.Roles.Administrator))
                        {
                            return RedirectToAction("AdminDashboard", "Dashboard");
                        }

                        if (userRoles.Contains(Constants.Roles.SecurityAnalyst))
                        {
                            return RedirectToAction("AnalystDashboard", "Dashboard");
                        }

                        return RedirectToAction("Index", "Dashboard");
                    }

                    if (result.IsLockedOut)
                    {
                        // Account is now locked after too many failed attempts
                        if (user != null)
                        {
                            var lockoutEndTime = await _userManager.GetLockoutEndDateAsync(user);
                            user.LockoutReason = "Too many failed login attempts";
                            user.LockoutExpiresAt = lockoutEndTime?.UtcDateTime;
                            await _userManager.UpdateAsync(user);

                            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                            await _auditLogService.LogAsync(user.Id, Constants.AuditActions.UserLogin, 
                                $"Account locked due to {user.AccessFailedCount} failed login attempts", ipAddress);
                        }

                        _logger.LogWarning("User account locked out after too many failed attempts.");
                        return RedirectToAction(nameof(Lockout), new { email = model.Email });
                    }

                    // Failed login - display remaining attempts before lockout
                    if (user != null)
                    {
                        var failedAttempts = user.AccessFailedCount;
                        var maxAttempts = _userManager.Options.Lockout.MaxFailedAccessAttempts;
                        var remainingAttempts = maxAttempts - failedAttempts;

                        if (remainingAttempts > 0)
                        {
                            ModelState.AddModelError(string.Empty, 
                                $"Invalid login attempt. You have {remainingAttempts} attempt(s) remaining before your account is locked.");
                        }
                        else
                        {
                            ModelState.AddModelError(string.Empty, 
                                "Invalid login attempt. Your account will be locked after the next failed attempt.");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login attempt. Please check your email and password.");
                    }
                }
                catch (Exception ex)
                {
                    // Log full exception server-side; never expose internal error details to the client.
                    _logger.LogError(ex, "Error during login");
                    ModelState.AddModelError(string.Empty, "An error occurred during login. Please try again.");
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.GetUserAsync(User);

            if (user != null)
            {
                _logger.LogInformation("User logged out.");

                // Log audit — use the defined constant
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
                await _auditLogService.LogAsync(user.Id, Constants.AuditActions.UserLogout, "User logged out", ipAddress);
            }

            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var user = await _userManager.FindByEmailAsync(model.Email);

                    if (user == null || !user.IsActive)
                    {
                        // Don't reveal whether user exists
                        return RedirectToAction(nameof(ForgotPasswordConfirmation));
                    }

                    // Generate password reset token
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                    // In production, send this token via email
                    // For now, just confirm the request
                    _logger.LogInformation("Password reset requested.");

                    // TODO: Implement email service to send reset link
                    // var resetUrl = Url.Action("ResetPassword", "Account", new { token, email = user.Email }, Request.Scheme);
                    // await _emailService.SendPasswordResetEmailAsync(user.Email, resetUrl);

                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error requesting password reset");
                    ModelState.AddModelError(string.Empty, "An error occurred.");
                }
            }

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Lockout(string? email = null)
        {
            // Retrieve user information to display lockout details
            if (!string.IsNullOrEmpty(email))
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                    ViewData["Email"] = email;
                    ViewData["LockoutEnd"] = lockoutEnd;
                    ViewData["LockoutReason"] = user.LockoutReason ?? "Account locked due to multiple failed login attempts";
                    return View();
                }
            }

            return View();
        }

        // AccessDenied must be accessible to unauthenticated users; otherwise an
        // unauthenticated redirect to this endpoint loops: unauthenticated → AccessDenied → Login → ...
        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }

        // LoginSuccess is shown after registration — the user is not yet signed in,
        // so this action must be accessible without authentication.
        [HttpGet]
        [AllowAnonymous]
        public IActionResult LoginSuccess()
        {
            return View();
        }
    }
}
