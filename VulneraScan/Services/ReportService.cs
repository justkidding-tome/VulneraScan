using Microsoft.EntityFrameworkCore;
using VulneraScan.Data;
using VulneraScan.Models;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Generates and persists scan reports with risk assessment.
    /// </summary>
    public class ReportService : IReportService
    {
        private readonly ApplicationDbContext _context;
        private readonly IRiskAssessmentService _riskService;

        public ReportService(ApplicationDbContext context, IRiskAssessmentService riskService)
        {
            _context = context;
            _riskService = riskService;
        }

        public async Task<ScanReport> GenerateReportAsync(ScanTarget scanTarget, string userId)
        {
            var vulnerabilities = await _context.Vulnerabilities
                .Where(v => v.ScanTargetId == scanTarget.Id)
                .ToListAsync();

            var (score, label) = _riskService.CalculateRisk(vulnerabilities);

            var highCount = vulnerabilities.Count(v => v.SeverityLevel == Models.Enums.SeverityLevel.High);
            var mediumCount = vulnerabilities.Count(v => v.SeverityLevel == Models.Enums.SeverityLevel.Medium);
            var lowCount = vulnerabilities.Count(v => v.SeverityLevel == Models.Enums.SeverityLevel.Low);

            var report = new ScanReport
            {
                Title = $"Vulnerability Assessment Report - {scanTarget.Domain ?? scanTarget.TargetUrl}",
                RiskScore = score,
                RiskLabel = label,
                Summary = $"Scan completed with {vulnerabilities.Count} vulnerabilities found: " +
                          $"{highCount} High, {mediumCount} Medium, {lowCount} Low. " +
                          $"Overall risk: {label} (Score: {score}).",
                ScanTargetId = scanTarget.Id,
                UserId = userId,
                GeneratedAt = DateTime.UtcNow
            };

            _context.ScanReports.Add(report);
            await _context.SaveChangesAsync();

            return report;
        }

        public async Task<ScanReport?> GetReportByIdAsync(int id)
        {
            return await _context.ScanReports
                .Include(r => r.ScanTarget)
                    .ThenInclude(s => s.PortResults)
                .Include(r => r.ScanTarget)
                    .ThenInclude(s => s.DiscoveredServices)
                .Include(r => r.ScanTarget)
                    .ThenInclude(s => s.Vulnerabilities)
                        .ThenInclude(v => v.Recommendation)
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Id == id);
        }

        public async Task<ScanReport?> GetReportByScanTargetIdAsync(int scanTargetId)
        {
            return await _context.ScanReports
                .Include(r => r.ScanTarget)
                .FirstOrDefaultAsync(r => r.ScanTargetId == scanTargetId);
        }

        public async Task<List<ScanReport>> GetAllReportsAsync()
        {
            return await _context.ScanReports
                .Include(r => r.ScanTarget)
                .Include(r => r.User)
                .OrderByDescending(r => r.GeneratedAt)
                .ToListAsync();
        }

        public async Task<List<ScanReport>> GetReportsByUserAsync(string userId)
        {
            return await _context.ScanReports
                .Include(r => r.ScanTarget)
                .Where(r => r.UserId == userId)
                .OrderByDescending(r => r.GeneratedAt)
                .ToListAsync();
        }

        public async Task<bool> DeleteReportAsync(int id)
        {
            var report = await _context.ScanReports.FindAsync(id);
            if (report == null) return false;

            _context.ScanReports.Remove(report);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}
