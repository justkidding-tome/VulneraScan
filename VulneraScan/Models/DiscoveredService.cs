using System.ComponentModel.DataAnnotations;
using VulneraScan.Models.Enums;

namespace VulneraScan.Models
{
    /// <summary>
    /// Represents a service discovered during enumeration.
    /// </summary>
    public class DiscoveredService
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string ServiceName { get; set; } = string.Empty;

        [MaxLength(100)]
        public string Version { get; set; } = string.Empty;

        [MaxLength(1000)]
        public string Banner { get; set; } = string.Empty;

        public int Port { get; set; }

        [MaxLength(10)]
        public string Protocol { get; set; } = "TCP";

        public SeverityLevel RiskLevel { get; set; }

        // Foreign key to ScanTarget
        public int ScanTargetId { get; set; }

        // Navigation property
        public virtual ScanTarget ScanTarget { get; set; } = null!;
    }
}
