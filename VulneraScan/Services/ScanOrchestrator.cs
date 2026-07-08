using Microsoft.EntityFrameworkCore;
using VulneraScan.Data;
using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Orchestrates the entire scan pipeline from port scanning through report generation.
    /// </summary>
    public class ScanOrchestrator : IScanOrchestrator
    {
        private readonly ApplicationDbContext _context;
        private readonly IPortScannerService _portScanner;
        private readonly IServiceEnumerationService _serviceEnum;
        private readonly IVulnerabilityDetectionService _vulnDetection;
        private readonly IRiskAssessmentService _riskAssessment;
        private readonly IRecommendationService _recommendation;
        private readonly IReportService _reportService;
        private readonly ILogger<ScanOrchestrator> _logger;

        public ScanOrchestrator(
            ApplicationDbContext context,
            IPortScannerService portScanner,
            IServiceEnumerationService serviceEnum,
            IVulnerabilityDetectionService vulnDetection,
            IRiskAssessmentService riskAssessment,
            IRecommendationService recommendation,
            IReportService reportService,
            ILogger<ScanOrchestrator> logger)
        {
            _context = context;
            _portScanner = portScanner;
            _serviceEnum = serviceEnum;
            _vulnDetection = vulnDetection;
            _riskAssessment = riskAssessment;
            _recommendation = recommendation;
            _reportService = reportService;
            _logger = logger;
        }

        public async Task<ScanTarget> ExecuteScanAsync(int scanTargetId, string userId)
        {
            var scanTarget = await _context.ScanTargets.FindAsync(scanTargetId)
                ?? throw new InvalidOperationException($"ScanTarget {scanTargetId} not found.");

            try
            {
                // Mark as in progress
                scanTarget.ScanStatus = ScanStatus.InProgress;
                scanTarget.StartedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                var host = InputValidator.ExtractHost(scanTarget.TargetUrl);
                scanTarget.Domain = host;
                scanTarget.IpAddress = await ResolveIpAsync(host);

                _logger.LogInformation("Starting scan pipeline for {Host} (ID: {Id})", host, scanTargetId);

                // Step 1: Port Scanning
                _logger.LogInformation("Step 1: Port scanning...");
                var portResults = await _portScanner.ScanPortsAsync(host, scanTargetId);
                _context.PortResults.AddRange(portResults);
                await _context.SaveChangesAsync();

                // Step 2: Service Enumeration
                _logger.LogInformation("Step 2: Service enumeration...");
                var services = await _serviceEnum.EnumerateServicesAsync(host, portResults, scanTargetId);
                _context.DiscoveredServices.AddRange(services);
                await _context.SaveChangesAsync();

                // Step 3: Vulnerability Detection
                _logger.LogInformation("Step 3: Vulnerability detection...");
                var vulnerabilities = await _vulnDetection.DetectVulnerabilitiesAsync(
                    scanTarget.TargetUrl, portResults, services, scanTargetId);
                _context.Vulnerabilities.AddRange(vulnerabilities);
                await _context.SaveChangesAsync();

                // Step 4: Generate Recommendations
                _logger.LogInformation("Step 4: Generating recommendations...");
                var recommendations = _recommendation.GenerateRecommendations(vulnerabilities);
                _context.SecurityRecommendations.AddRange(recommendations);
                await _context.SaveChangesAsync();

                // Step 5: Generate Report
                _logger.LogInformation("Step 5: Generating report...");
                await _reportService.GenerateReportAsync(scanTarget, userId);

                // Mark as completed
                scanTarget.ScanStatus = ScanStatus.Completed;
                scanTarget.CompletedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                _logger.LogInformation("Scan pipeline completed for {Host} (ID: {Id})", host, scanTargetId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scan pipeline failed for ScanTarget {Id}", scanTargetId);
                scanTarget.ScanStatus = ScanStatus.Failed;
                scanTarget.CompletedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
                throw;
            }

            return scanTarget;
        }

        private static async Task<string?> ResolveIpAsync(string host)
        {
            try
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(host);
                return addresses.FirstOrDefault()?.ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}
