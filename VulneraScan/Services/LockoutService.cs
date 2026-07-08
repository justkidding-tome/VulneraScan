using Microsoft.AspNetCore.Identity;
using VulneraScan.Models;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Service for managing account lockout operations.
    /// Provides centralized lockout management functionality.
    /// </summary>
    public class LockoutService : ILockoutService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LockoutService> _logger;

        public LockoutService(UserManager<ApplicationUser> userManager, ILogger<LockoutService> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        /// <summary>
        /// Gets comprehensive lockout information for a user.
        /// </summary>
        public async Task<LockoutInfo?> GetLockoutInfoAsync(ApplicationUser user)
        {
            if (user == null)
                return null;

            var isLockedOut = await _userManager.IsLockedOutAsync(user);
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);

            if (!isLockedOut)
                return null;

            var remainingSeconds = GetRemainingLockoutSeconds(lockoutEnd);

            return new LockoutInfo
            {
                IsLockedOut = isLockedOut,
                LockoutEnd = lockoutEnd?.UtcDateTime,
                FailedAttempts = user.AccessFailedCount,
                RemainingSeconds = remainingSeconds,
                Reason = user.LockoutReason ?? "Too many failed login attempts"
            };
        }

        /// <summary>
        /// Gets the remaining lockout duration in seconds.
        /// </summary>
        public async Task<int> GetRemainingLockoutSecondsAsync(ApplicationUser user)
        {
            if (user == null)
                return 0;

            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            return GetRemainingLockoutSeconds(lockoutEnd);
        }

        /// <summary>
        /// Checks if a user is currently locked out.
        /// </summary>
        public async Task<bool> IsLockedOutAsync(ApplicationUser user)
        {
            if (user == null)
                return false;

            return await _userManager.IsLockedOutAsync(user);
        }

        /// <summary>
        /// Unlocks an account and resets failed attempts.
        /// </summary>
        public async Task<bool> UnlockAccountAsync(ApplicationUser user)
        {
            if (user == null)
                return false;

            try
            {
                // Remove lockout by setting lockout end to null
                var result = await _userManager.SetLockoutEndDateAsync(user, null);
                if (!result.Succeeded)
                {
                    _logger.LogError("Failed to set lockout end date for user {UserId}", user.Id);
                    return false;
                }

                // Reset failed attempts counter
                result = await _userManager.ResetAccessFailedCountAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogError("Failed to reset access failed count for user {UserId}", user.Id);
                    return false;
                }

                // Clear lockout information
                user.LockoutReason = null;
                user.LockoutExpiresAt = null;
                result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogError("Failed to clear lockout info for user {UserId}", user.Id);
                    return false;
                }

                _logger.LogInformation("Account {UserId} ({Email}) unlocked successfully", user.Id, user.Email);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while unlocking account {UserId}", user.Id);
                return false;
            }
        }

        /// <summary>
        /// Formats the remaining lockout time into a user-friendly string.
        /// </summary>
        public string FormatRemainingLockoutTime(int totalSeconds)
        {
            if (totalSeconds <= 0)
                return "Account should now be unlocked";

            var minutes = totalSeconds / 60;
            var seconds = totalSeconds % 60;

            if (minutes > 0)
            {
                return $"{minutes} minute(s) and {seconds} second(s)";
            }

            return $"{seconds} second(s)";
        }

        /// <summary>
        /// Helper method to calculate remaining lockout seconds.
        /// </summary>
        private static int GetRemainingLockoutSeconds(DateTimeOffset? lockoutEnd)
        {
            if (lockoutEnd == null)
                return 0;

            var remaining = lockoutEnd.Value.UtcDateTime - DateTime.UtcNow;
            return remaining.TotalSeconds > 0 ? (int)remaining.TotalSeconds : 0;
        }
    }
}
