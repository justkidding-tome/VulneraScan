namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Generates professional PDF reports from scan data.
    /// </summary>
    public interface IPdfReportService
    {
        Task<byte[]> GeneratePdfAsync(int reportId);
    }
}
