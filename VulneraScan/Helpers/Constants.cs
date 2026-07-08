namespace VulneraScan.Helpers
{
    /// <summary>
    /// Application-wide constants.
    /// </summary>
    public static class Constants
    {
        public static class Roles
        {
            public const string Administrator = "Administrator";
            public const string SecurityAnalyst = "SecurityAnalyst";
            public const string AllRoles = "Administrator,SecurityAnalyst";
        }

        public static class PortInfo
        {
            /// <summary>
            /// Predefined ports to scan with their well-known service names.
            /// </summary>
            public static readonly Dictionary<int, string> WellKnownPorts = new()
            {
                { 21, "FTP" },
                { 22, "SSH" },
                { 23, "Telnet" },
                { 25, "SMTP" },
                { 53, "DNS" },
                { 80, "HTTP" },
                { 110, "POP3" },
                { 143, "IMAP" },
                { 443, "HTTPS" },
                { 445, "SMB" },
                { 3306, "MySQL" },
                { 3389, "RDP" },
                { 8080, "HTTP-Proxy" }
            };

            /// <summary>
            /// Ports considered high-risk when open.
            /// </summary>
            public static readonly HashSet<int> HighRiskPorts = new() { 21, 23, 445, 3389 };

            /// <summary>
            /// Ports considered medium-risk when open.
            /// </summary>
            public static readonly HashSet<int> MediumRiskPorts = new() { 22, 25, 110, 143, 3306, 8080 };
        }

        public static class RiskScoring
        {
            public const int HighWeight = 3;
            public const int MediumWeight = 2;
            public const int LowWeight = 1;

            // Thresholds for risk labels
            public const int MinimalMax = 2;
            public const int LowMax = 5;
            public const int MediumMax = 10;
            // Above MediumMax = High
        }

        public static class AuditActions
        {
            // Authentication events
            public const string UserLogin = "User Login";
            public const string UserLogout = "User Logout";

            // User management events
            public const string UserCreated = "User Created";
            public const string UserUpdated = "User Updated";
            public const string UserDeleted = "User Deleted";
            public const string UserArchived = "User Archived";
            public const string UserRestored = "User Restored";

            // Scan events
            public const string ScanCreated = "Scan Created";
            public const string ScanDeleted = "Scan Deleted";
            public const string ScanArchived = "Scan Archived";
            public const string ScanRestored = "Scan Restored";

            // Report events
            public const string ReportDownloaded = "Report Downloaded";
            public const string ReportDeleted = "Report Deleted";
            public const string ReportDeletedByAdmin = "Report Deleted By Admin";
            public const string ReportArchived = "Report Archived";
            public const string ReportRestored = "Report Restored";
            public const string ReportArchivedByAdmin = "Report Archived By Admin";
            public const string ReportRestoredByAdmin = "Report Restored By Admin";

            // Role events
            public const string RoleAssigned = "Role Assigned";

            // Registration
            public const string Registration = "Registration";
        }
    }
}
