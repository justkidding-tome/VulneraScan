using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VulneraScan.Models;
using VulneraScan.Services;

namespace VulneraScan.Data
{
    /// <summary>
    /// Application database context using Identity with custom ApplicationUser.
    /// Configures field-level encryption for sensitive PII fields.
    /// </summary>
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        private readonly IEncryptionService? _encryptionService;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, IEncryptionService? encryptionService = null)
            : base(options)
        {
            _encryptionService = encryptionService;
        }

        public DbSet<ScanTarget> ScanTargets => Set<ScanTarget>();
        public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
        public DbSet<ScanReport> ScanReports => Set<ScanReport>();
        public DbSet<PortResult> PortResults => Set<PortResult>();
        public DbSet<DiscoveredService> DiscoveredServices => Set<DiscoveredService>();
        public DbSet<SecurityRecommendation> SecurityRecommendations => Set<SecurityRecommendation>();
        public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Global Query Filters to automatically hide archived records
            builder.Entity<ScanTarget>().HasQueryFilter(s => !s.IsArchived);
            builder.Entity<ScanReport>().HasQueryFilter(r => !r.IsArchived);

            builder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

            // Configure encryption for sensitive ApplicationUser properties
            // Only apply converters if encryption service is available
            if (_encryptionService != null)
            {
                var encryptionConverter = new EncryptionConverter(_encryptionService);

                builder.Entity<ApplicationUser>()
                    .Property(u => u.FullName)
                    .HasConversion(encryptionConverter);

                builder.Entity<ApplicationUser>()
                    .Property(u => u.Email)
                    .HasConversion(encryptionConverter);
            }

            var adminRoleId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
            var analystRoleId = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

            builder.Entity<IdentityRole>().HasData(
                new IdentityRole
                {
                    Id = adminRoleId,
                    Name = "Administrator",
                    NormalizedName = "ADMINISTRATOR",
                    ConcurrencyStamp = adminRoleId
                },
                new IdentityRole
                {
                    Id = analystRoleId,
                    Name = "SecurityAnalyst",
                    NormalizedName = "SECURITYANALYST",
                    ConcurrencyStamp = analystRoleId
                }
            );
        }
    }
}
