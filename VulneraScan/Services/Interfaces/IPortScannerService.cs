using VulneraScan.Models;

namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Scans predefined ports on a target to determine open/closed/filtered status.
    /// </summary>
    public interface IPortScannerService
    {
        Task<List<PortResult>> ScanPortsAsync(string host, int scanTargetId);
    }
}
