using System.Net.Sockets;
using System.Text;
using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Enumerates services on open ports using banner grabbing and protocol detection.
    /// </summary>
    public class ServiceEnumerationService : IServiceEnumerationService
    {
        private const int BannerTimeoutMs = 3000;
        private readonly ILogger<ServiceEnumerationService> _logger;

        public ServiceEnumerationService(ILogger<ServiceEnumerationService> logger)
        {
            _logger = logger;
        }

        public async Task<List<DiscoveredService>> EnumerateServicesAsync(
            string host, List<PortResult> openPorts, int scanTargetId)
        {
            var services = new List<DiscoveredService>();
            var openOnly = openPorts.Where(p => p.Status == PortStatus.Open).ToList();

            foreach (var port in openOnly)
            {
                var service = await EnumerateSingleServiceAsync(host, port, scanTargetId);
                services.Add(service);
            }

            _logger.LogInformation("Service enumeration completed for {Host}: {Count} services discovered",
                host, services.Count);

            return services;
        }

        private async Task<DiscoveredService> EnumerateSingleServiceAsync(
            string host, PortResult port, int scanTargetId)
        {
            var service = new DiscoveredService
            {
                ServiceName = port.ServiceName,
                Port = port.PortNumber,
                Protocol = "TCP",
                ScanTargetId = scanTargetId,
                RiskLevel = port.RiskLevel
            };

            try
            {
                var banner = await GrabBannerAsync(host, port.PortNumber);
                if (!string.IsNullOrEmpty(banner))
                {
                    service.Banner = banner.Length > 1000 ? banner[..1000] : banner;
                    service.Version = ParseVersionFromBanner(banner);
                    service.RiskLevel = AnalyzeServiceRisk(port.PortNumber, banner);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Banner grab failed for {Host}:{Port}", host, port.PortNumber);
            }

            return service;
        }

        private static async Task<string> GrabBannerAsync(string host, int port)
        {
            try
            {
                using var client = new TcpClient();
                using var cts = new CancellationTokenSource(BannerTimeoutMs);

                await client.ConnectAsync(host, port, cts.Token);

                var stream = client.GetStream();
                stream.ReadTimeout = BannerTimeoutMs;

                // For HTTP ports, send a request to get the response
                if (port is 80 or 443 or 8080)
                {
                    var requestStr = $"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n";
                    var request = Encoding.ASCII.GetBytes(requestStr);
                    await stream.WriteAsync(request, cts.Token);
                }

                var buffer = new byte[4096];
                var bytesRead = await stream.ReadAsync(buffer, cts.Token);

                if (bytesRead > 0)
                    return Encoding.ASCII.GetString(buffer, 0, bytesRead);
            }
            catch
            {
                // Banner grab failed — not critical
            }

            return string.Empty;
        }

        private static string ParseVersionFromBanner(string banner)
        {
            if (string.IsNullOrEmpty(banner)) return "Unknown";

            // Common version patterns
            var lines = banner.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                // SSH banner: SSH-2.0-OpenSSH_8.9
                if (trimmed.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase))
                    return trimmed;

                // HTTP Server header
                if (trimmed.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                    return trimmed["Server:".Length..].Trim();

                // FTP banner: 220 ProFTPD 1.3.5
                if (trimmed.StartsWith("220 ", StringComparison.OrdinalIgnoreCase))
                    return trimmed[4..].Trim();

                // SMTP banner: 220 mail.example.com ESMTP Postfix
                if (trimmed.Contains("ESMTP", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("SMTP", StringComparison.OrdinalIgnoreCase))
                    return trimmed;
            }

            return banner.Length > 100 ? banner[..100] : banner;
        }

        private static SeverityLevel AnalyzeServiceRisk(int port, string banner)
        {
            var lowerBanner = banner.ToLowerInvariant();

            // High risk indicators
            if (Constants.PortInfo.HighRiskPorts.Contains(port))
                return SeverityLevel.High;

            // Outdated/vulnerable version indicators
            if (lowerBanner.Contains("apache/2.2") || lowerBanner.Contains("apache/2.0") ||
                lowerBanner.Contains("iis/6") || lowerBanner.Contains("iis/7") ||
                lowerBanner.Contains("openssh_5") || lowerBanner.Contains("openssh_6"))
                return SeverityLevel.High;

            if (Constants.PortInfo.MediumRiskPorts.Contains(port))
                return SeverityLevel.Medium;

            return SeverityLevel.Low;
        }
    }
}
