using VulneraScan.Models;

namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Orchestrates the complete scan pipeline: Port Scan → Service Enum → Vuln Detection → Risk → Recommendations → Report.
    /// </summary>
    public interface IScanOrchestrator
    {
        Task<ScanTarget> ExecuteScanAsync(int scanTargetId, string userId);
    }
}
