using VulneraScan.Models;

namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Enumerates services on open ports, including banner grabbing and version detection.
    /// </summary>
    public interface IServiceEnumerationService
    {
        Task<List<DiscoveredService>> EnumerateServicesAsync(string host, List<PortResult> openPorts, int scanTargetId);
    }
}
