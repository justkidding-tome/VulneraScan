using VulneraScan.Models;

namespace VulneraScan.ViewModels.Report
{
    public class ReportListViewModel
    {
        public List<ScanReport> Reports { get; set; } = new();
    }

    public class ReportDetailViewModel
    {
        public ScanReport Report { get; set; } = null!;
        public List<PortResult> PortResults { get; set; } = new();
        public List<DiscoveredService> DiscoveredServices { get; set; } = new();
        public List<Vulnerability> Vulnerabilities { get; set; } = new();
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public TimeSpan? ScanDuration { get; set; }
    }
}
