using VulneraScan.Models;
using VulneraScan.Models.Enums;

namespace VulneraScan.ViewModels.Dashboard
{
    public class AdminDashboardViewModel
    {
        public int TotalUsers { get; set; }
        public int ActiveUsers { get; set; }
        public int TotalScans { get; set; }
        public int CompletedScans { get; set; }
        public int TotalReports { get; set; }
        public int TotalVulnerabilities { get; set; }
        public int HighRiskFindings { get; set; }
        public int MediumRiskFindings { get; set; }
        public int LowRiskFindings { get; set; }
        public List<ScanTarget> RecentScans { get; set; } = new();
        public List<ScanReport> RecentReports { get; set; } = new();
    }

    public class AnalystDashboardViewModel
    {
        public int PersonalTotalScans { get; set; }
        public int PersonalCompletedScans { get; set; }
        public int PersonalTotalVulnerabilities { get; set; }
        public int PersonalHighRisk { get; set; }
        public int PersonalMediumRisk { get; set; }
        public int PersonalLowRisk { get; set; }
        public List<ScanTarget> RecentScans { get; set; } = new();
        public List<ScanReport> RecentReports { get; set; } = new();
    }
}
