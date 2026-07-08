using Microsoft.Extensions.Logging;
using VulneraScan.Data;
using VulneraScan.Models;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Logs user actions for audit trail and compliance.
    /// Failures are swallowed after logging — audit failure must never crash a user request.
    /// </summary>
    public class AuditLogService : IAuditLogService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AuditLogService> _logger;

        public AuditLogService(ApplicationDbContext context, ILogger<AuditLogService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogAsync(string? userId, string action, string details, string ipAddress)
        {
            try
            {
                var log = new AuditLog
                {
                    UserId = userId,
                    Action = action,
                    Details = details,
                    IpAddress = ipAddress,
                    Timestamp = DateTime.UtcNow
                };

                _context.AuditLogs.Add(log);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to persist audit log entry. Action={Action}, UserId={UserId}",
                    action, userId);
            }
        }
    }
}
