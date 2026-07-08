using System.ComponentModel.DataAnnotations;
using VulneraScan.Models.Enums;

namespace VulneraScan.Models
{
    /// <summary>
    /// Represents a security recommendation for a specific vulnerability.
    /// </summary>
    public class SecurityRecommendation
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(256)]
        public string Title { get; set; } = string.Empty;

        [MaxLength(2000)]
        public string Description { get; set; } = string.Empty;

        [MaxLength(2000)]
        public string Impact { get; set; } = string.Empty;

        [MaxLength(4000)]
        public string MitigationSteps { get; set; } = string.Empty;

        public SeverityLevel Priority { get; set; }

        // Foreign key to Vulnerability (one-to-one)
        public int VulnerabilityId { get; set; }

        // Navigation property
        public virtual Vulnerability Vulnerability { get; set; } = null!;
    }
}
