using Microsoft.AspNetCore.Identity;
using VulneraScan.Models;

namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Service for managing account lockout operations and queries.
    /// </summary>
    public interface ILockoutService
    {
        /// <summary>
        /// Gets the lockout information for a user.
        /// </summary>
        Task<LockoutInfo?> GetLockoutInfoAsync(ApplicationUser user);

        /// <summary>
        /// Gets the remaining lockout duration in seconds.
        /// </summary>
        Task<int> GetRemainingLockoutSecondsAsync(ApplicationUser user);

        /// <summary>
        /// Checks if a user is currently locked out.
        /// </summary>
        Task<bool> IsLockedOutAsync(ApplicationUser user);

        /// <summary>
        /// Unlocks an account and resets failed attempts.
        /// </summary>
        Task<bool> UnlockAccountAsync(ApplicationUser user);

        /// <summary>
        /// Formats the remaining lockout time into a user-friendly string.
        /// </summary>
        string FormatRemainingLockoutTime(int totalSeconds);
    }

    /// <summary>
    /// Information about an account's lockout status.
    /// </summary>
    public class LockoutInfo
    {
        public bool IsLockedOut { get; set; }
        public DateTime? LockoutEnd { get; set; }
        public int FailedAttempts { get; set; }
        public int RemainingSeconds { get; set; }
        public string Reason { get; set; } = "Too many failed login attempts";
    }
}
