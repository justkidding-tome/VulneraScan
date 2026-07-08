using System.Net.Sockets;
using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Scans predefined TCP ports using TcpClient with timeout detection.
    /// </summary>
    public class PortScannerService : IPortScannerService
    {
        private const int ConnectionTimeoutMs = 2000;
        private readonly ILogger<PortScannerService> _logger;

        public PortScannerService(ILogger<PortScannerService> logger)
        {
            _logger = logger;
        }

        public async Task<List<PortResult>> ScanPortsAsync(string host, int scanTargetId)
        {
            var results = new List<PortResult>();
            var tasks = Constants.PortInfo.WellKnownPorts
                .Select(kvp => ScanSinglePortAsync(host, kvp.Key, kvp.Value, scanTargetId));

            var portResults = await Task.WhenAll(tasks);
            results.AddRange(portResults);

            _logger.LogInformation("Port scan completed for {Host}: {Open} open, {Closed} closed, {Filtered} filtered",
                host,
                results.Count(r => r.Status == PortStatus.Open),
                results.Count(r => r.Status == PortStatus.Closed),
                results.Count(r => r.Status == PortStatus.Filtered));

            return results;
        }

        private async Task<PortResult> ScanSinglePortAsync(string host, int port, string serviceName, int scanTargetId)
        {
            var result = new PortResult
            {
                PortNumber = port,
                ServiceName = serviceName,
                ScanTargetId = scanTargetId
            };

            try
            {
                using var client = new TcpClient();
                using var cts = new CancellationTokenSource(ConnectionTimeoutMs);

                await client.ConnectAsync(host, port, cts.Token);

                result.Status = PortStatus.Open;
                result.RiskLevel = ClassifyPortRisk(port);

                _logger.LogDebug("Port {Port} ({Service}) is OPEN on {Host}", port, serviceName, host);
            }
            catch (OperationCanceledException)
            {
                result.Status = PortStatus.Filtered;
                result.RiskLevel = SeverityLevel.Low;
                _logger.LogDebug("Port {Port} ({Service}) is FILTERED on {Host}", port, serviceName, host);
            }
            catch (SocketException)
            {
                result.Status = PortStatus.Closed;
                result.RiskLevel = SeverityLevel.Low;
                _logger.LogDebug("Port {Port} ({Service}) is CLOSED on {Host}", port, serviceName, host);
            }
            catch (Exception ex)
            {
                result.Status = PortStatus.Filtered;
                result.RiskLevel = SeverityLevel.Low;
                _logger.LogWarning(ex, "Error scanning port {Port} on {Host}", port, host);
            }

            return result;
        }

        private static SeverityLevel ClassifyPortRisk(int port)
        {
            if (Constants.PortInfo.HighRiskPorts.Contains(port))
                return SeverityLevel.High;
            if (Constants.PortInfo.MediumRiskPorts.Contains(port))
                return SeverityLevel.Medium;
            return SeverityLevel.Low;
        }
    }
}
