using System.ComponentModel.DataAnnotations;
using VulneraScan.Models.Enums;

namespace VulneraScan.Models
{
    /// <summary>
    /// Represents a generated scan report with risk assessment.
    /// </summary>
    public class ScanReport
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(256)]
        public string Title { get; set; } = string.Empty;

        public int RiskScore { get; set; }

        public RiskLabel RiskLabel { get; set; }

        [MaxLength(4000)]
        public string Summary { get; set; } = string.Empty;

        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

        public bool IsArchived { get; set; } = false;

        // Foreign key to ScanTarget (one-to-one)
        public int ScanTargetId { get; set; }

        // Foreign key to ApplicationUser
        [Required]
        public string UserId { get; set; } = string.Empty;

        // Navigation properties
        public virtual ScanTarget ScanTarget { get; set; } = null!;
        public virtual ApplicationUser User { get; set; } = null!;
    }
}
