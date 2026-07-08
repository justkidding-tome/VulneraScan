using System.ComponentModel.DataAnnotations;
using VulneraScan.Models;
using VulneraScan.Models.Enums;

namespace VulneraScan.ViewModels.Scan
{
    public class ScanTargetViewModel
    {
        [Required(ErrorMessage = "Please enter a target URL or IP address.")]
        [Display(Name = "Target URL / IP Address")]
        [MaxLength(2048)]
        public string TargetUrl { get; set; } = string.Empty;
    }

    public class ScanResultViewModel
    {
        public ScanTarget ScanTarget { get; set; } = null!;
        public List<PortResult> PortResults { get; set; } = new();
        public List<DiscoveredService> DiscoveredServices { get; set; } = new();
        public List<Vulnerability> Vulnerabilities { get; set; } = new();
        public ScanReport? Report { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public TimeSpan? ScanDuration { get; set; }
    }
}
