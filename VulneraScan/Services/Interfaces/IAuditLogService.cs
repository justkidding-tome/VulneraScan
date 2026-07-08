namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Logs user actions for security auditing.
    /// </summary>
    public interface IAuditLogService
    {
        Task LogAsync(string? userId, string action, string details, string ipAddress);
    }
}
