using System.ComponentModel.DataAnnotations;
using VulneraScan.Models;

namespace VulneraScan.ViewModels.Admin
{
    public class UserListViewModel
    {
        public List<UserViewModel> Users { get; set; } = new();
    }

    public class UserViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public string Role { get; set; } = string.Empty;
        public int ScanCount { get; set; }

        /// <summary>
        /// Indicates if the user account is currently locked.
        /// </summary>
        public bool IsLockedOut { get; set; }

        /// <summary>
        /// Timestamp when the account lockout will expire.
        /// </summary>
        public DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>
        /// Number of failed login attempts.
        /// </summary>
        public int AccessFailedCount { get; set; }
    }

    public class CreateUserViewModel
    {
        [Required(ErrorMessage = "Full name is required.")]
        [Display(Name = "Full Name")]
        [MaxLength(100)]
        public string FullName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [MinLength(8)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm the password.")]
        [DataType(DataType.Password)]
        [Compare("Password")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Role is required.")]
        [Display(Name = "Role")]
        public string Role { get; set; } = string.Empty;

        public List<string> AvailableRoles { get; set; } = new();
    }

    public class EditUserViewModel
    {
        public string Id { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Full Name")]
        [MaxLength(100)]
        public string FullName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Display(Name = "Active")]
        public bool IsActive { get; set; }

        [Required]
        [Display(Name = "Role")]
        public string Role { get; set; } = string.Empty;

        public List<string> AvailableRoles { get; set; } = new();
    }

    public class AdminStatisticsViewModel
    {
        public int TotalUsers { get; set; }
        public int ActiveUsers { get; set; }
        public int InactiveUsers { get; set; }
        public int TotalScans { get; set; }
        public int CompletedScans { get; set; }
        public int PendingScans { get; set; }
        public int TotalReports { get; set; }
        public int TotalVulnerabilities { get; set; }
        public int TotalPortResults { get; set; }
        public int TotalServices { get; set; }
        public int AuditLogEntries { get; set; }
    }

    public class ManageReportsViewModel
    {
        public List<ScanReport> Reports { get; set; } = new();
    }

    public class AuditLogListViewModel
    {
        public List<AuditLog> Logs { get; set; } = new();
    }
}
