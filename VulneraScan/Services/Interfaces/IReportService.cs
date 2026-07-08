using VulneraScan.Models;

namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Generates and persists scan reports.
    /// </summary>
    public interface IReportService
    {
        Task<ScanReport> GenerateReportAsync(ScanTarget scanTarget, string userId);
        Task<ScanReport?> GetReportByIdAsync(int id);
        Task<ScanReport?> GetReportByScanTargetIdAsync(int scanTargetId);
        Task<List<ScanReport>> GetAllReportsAsync();
        Task<List<ScanReport>> GetReportsByUserAsync(string userId);
        Task<bool> DeleteReportAsync(int id);
    }
}
