using System.ComponentModel.DataAnnotations;
using VulneraScan.Models.Enums;

namespace VulneraScan.Models
{
    /// <summary>
    /// Represents a target (URL/IP/Domain) submitted for scanning.
    /// </summary>
    public class ScanTarget
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(2048)]
        public string TargetUrl { get; set; } = string.Empty;

        [MaxLength(45)]
        public string? IpAddress { get; set; }

        [MaxLength(255)]
        public string? Domain { get; set; }

        public ScanStatus ScanStatus { get; set; } = ScanStatus.Pending;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? StartedAt { get; set; }

        public DateTime? CompletedAt { get; set; }

        public bool IsArchived { get; set; } = false;

        // Foreign key to ApplicationUser
        [Required]
        public string UserId { get; set; } = string.Empty;

        // Navigation properties
        public virtual ApplicationUser User { get; set; } = null!;
        public virtual ICollection<PortResult> PortResults { get; set; } = new List<PortResult>();
        public virtual ICollection<DiscoveredService> DiscoveredServices { get; set; } = new List<DiscoveredService>();
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
        public virtual ScanReport? ScanReport { get; set; }
    }
}
