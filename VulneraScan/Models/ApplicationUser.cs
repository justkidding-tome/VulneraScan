using Microsoft.AspNetCore.Identity;

namespace VulneraScan.Models
{
    /// <summary>
    /// Extended Identity user with application-specific properties.
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public bool IsActive { get; set; } = true;

        public bool IsArchived { get; set; } = false;

        /// <summary>
        /// Tracks the reason for account lockout (e.g., "Too many failed login attempts").
        /// </summary>
        public string? LockoutReason { get; set; }

        /// <summary>
        /// Timestamp when the lockout will automatically expire.
        /// Used for display purposes to show users when they can retry.
        /// </summary>
        public DateTime? LockoutExpiresAt { get; set; }

        // Navigation properties
        public virtual ICollection<ScanTarget> ScanTargets { get; set; } = new List<ScanTarget>();
        public virtual ICollection<ScanReport> ScanReports { get; set; } = new List<ScanReport>();
        public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
    }
}
