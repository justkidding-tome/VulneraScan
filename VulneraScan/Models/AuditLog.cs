using System.ComponentModel.DataAnnotations;

namespace VulneraScan.Models
{
    /// <summary>
    /// Tracks user actions for security auditing.
    /// </summary>
    public class AuditLog
    {
        public int Id { get; set; }

        [MaxLength(450)]
        public string? UserId { get; set; }

        [Required]
        [MaxLength(100)]
        public string Action { get; set; } = string.Empty;

        [MaxLength(1000)]
        public string Details { get; set; } = string.Empty;

        [MaxLength(45)]
        public string IpAddress { get; set; } = string.Empty;

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        // Navigation property
        public virtual ApplicationUser? User { get; set; }
    }
}
