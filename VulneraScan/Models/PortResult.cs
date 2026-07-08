using System.ComponentModel.DataAnnotations;
using VulneraScan.Models.Enums;

namespace VulneraScan.Models
{
    /// <summary>
    /// Represents the result of scanning a specific port on a target.
    /// </summary>
    public class PortResult
    {
        public int Id { get; set; }

        public int PortNumber { get; set; }

        public PortStatus Status { get; set; }

        [MaxLength(100)]
        public string ServiceName { get; set; } = string.Empty;

        public SeverityLevel RiskLevel { get; set; }

        // Foreign key to ScanTarget
        public int ScanTargetId { get; set; }

        // Navigation property
        public virtual ScanTarget ScanTarget { get; set; } = null!;
    }
}
