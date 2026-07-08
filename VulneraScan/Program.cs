using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VulneraScan.Data;
using VulneraScan.Middleware;
using VulneraScan.Models;
using VulneraScan.Services;
using VulneraScan.Services.Interfaces;

using Serilog;

var builder = WebApplication.CreateBuilder(args);

// ──── Configure Serilog for production file logging ────
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .WriteTo.File("Logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// ──── Database ────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlServerOptionsAction: sqlOptions =>
        {
            sqlOptions.EnableRetryOnFailure();
        }));

// ──── Identity ────
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password policy
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;

    // Lockout
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ──── Cookie Configuration ────
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.Cookie.HttpOnly = true;
    // Always require HTTPS for the auth cookie — never transmit over plain HTTP
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    // Strict SameSite prevents the cookie being sent on cross-site requests (CSRF mitigation)
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
    options.Cookie.Name = "VulneraScan.Auth";
    options.ExpireTimeSpan = TimeSpan.FromHours(2);
    options.SlidingExpiration = true;
});

// ──── Session ────
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    // Match auth cookie security settings
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
    options.Cookie.Name = "VulneraScan.Session";
});

// ──── Encryption Service ────
builder.Services.AddScoped<IEncryptionService, EncryptionService>();

// ──── Application Services ────
builder.Services.AddScoped<IPortScannerService, PortScannerService>();
builder.Services.AddScoped<IServiceEnumerationService, ServiceEnumerationService>();
builder.Services.AddScoped<IVulnerabilityDetectionService, VulnerabilityDetectionService>();
builder.Services.AddScoped<IRiskAssessmentService, RiskAssessmentService>();
builder.Services.AddScoped<IRecommendationService, RecommendationService>();
builder.Services.AddScoped<IReportService, ReportService>();
builder.Services.AddScoped<IPdfReportService, PdfReportService>();
builder.Services.AddScoped<IScanOrchestrator, ScanOrchestrator>();
builder.Services.AddScoped<IAuditLogService, AuditLogService>();
builder.Services.AddScoped<ILockoutService, LockoutService>();

// ──── MVC ────
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

var app = builder.Build();

// ──── Apply Migrations & Seed Identity Data (roles + default users) ────
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();

        // Run seeder synchronously to avoid making Program async
        VulneraScan.Data.IdentityDataSeeder.SeedAsync(services).GetAwaiter().GetResult();
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating or seeding the database.");
    }
}

// ──── Middleware Pipeline ────
app.UseDeveloperExceptionPage();
if (!app.Environment.IsDevelopment())
{
    // app.UseExceptionHandler("/Home/Error");
    // HSTS is also set by SecurityHeadersMiddleware in non-dev environments.
    // UseHsts() registers the built-in middleware as a complementary layer.
    app.UseHsts();
}

// Security headers must be registered early so they apply to every response,
// including error pages and static files.
app.UseSecurityHeaders();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
