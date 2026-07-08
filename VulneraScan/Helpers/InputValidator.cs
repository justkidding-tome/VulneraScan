using System.Net;
using System.Text.RegularExpressions;

namespace VulneraScan.Helpers
{
    /// <summary>
    /// Validates and sanitizes user-supplied scan target inputs.
    /// </summary>
    public static partial class InputValidator
    {
        [GeneratedRegex(@"^(?:https?://)?(?:[\w-]+\.)+[\w-]+(?:/[\w\-./?%&=]*)?$", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
        private static partial Regex UrlPattern();

        [GeneratedRegex(@"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$", RegexOptions.Compiled)]
        private static partial Regex Ipv4Pattern();

        [GeneratedRegex(@"^(?:[\w-]+\.)+[\w-]{2,}$", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
        private static partial Regex DomainPattern();

        /// <summary>
        /// Validates whether the input is a valid URL, IP, or domain.
        /// Returns a sanitized target string or null if invalid.
        /// </summary>
        public static (bool IsValid, string SanitizedInput, string? ErrorMessage) ValidateTarget(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return (false, string.Empty, "Target URL or IP address is required.");

            // Sanitize: trim whitespace, remove control characters
            var sanitized = input.Trim();
            sanitized = Regex.Replace(sanitized, @"[\x00-\x1F\x7F]", string.Empty);

            if (sanitized.Length > 2048)
                return (false, string.Empty, "Input is too long (max 2048 characters).");

            // Check for localhost
            if (IsLocalhost(sanitized))
                return (false, string.Empty, "Scanning localhost is not permitted.");

            // Check for internal/private networks
            if (IsInternalNetwork(sanitized))
                return (false, string.Empty, "Scanning internal/private network addresses is not permitted.");

            // Validate as URL, IP, or domain
            if (IsValidUrl(sanitized) || IsValidIpAddress(sanitized) || IsValidDomain(sanitized))
                return (true, sanitized, null);

            return (false, string.Empty, "Invalid target. Please enter a valid URL, IP address, or domain name.");
        }

        public static bool IsValidUrl(string input)
        {
            if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
                return uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps;

            return UrlPattern().IsMatch(input);
        }

        public static bool IsValidIpAddress(string input)
        {
            return Ipv4Pattern().IsMatch(input) && IPAddress.TryParse(input, out _);
        }

        public static bool IsValidDomain(string input)
        {
            // Remove protocol if present
            var domain = input;
            if (domain.Contains("://"))
                domain = new Uri(domain).Host;

            return DomainPattern().IsMatch(domain);
        }

        public static bool IsLocalhost(string input)
        {
            var lower = input.ToLowerInvariant();
            var hostsToCheck = ExtractHost(lower);

            return hostsToCheck == "localhost"
                || hostsToCheck == "127.0.0.1"
                || hostsToCheck == "::1"
                || hostsToCheck == "0.0.0.0";
        }

        public static bool IsInternalNetwork(string input)
        {
            var host = ExtractHost(input);

            if (!IPAddress.TryParse(host, out var ip))
            {
                // Try resolving domain — but for safety, just check common patterns
                return host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                    || host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                    || host.EndsWith(".lan", StringComparison.OrdinalIgnoreCase);
            }

            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4) return false;

            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;

            return false;
        }

        /// <summary>
        /// Extracts the host portion from a URL or returns the input if it's just a host.
        /// </summary>
        public static string ExtractHost(string input)
        {
            if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
                return uri.Host;

            // Try prepending http:// for parsing
            if (Uri.TryCreate("http://" + input, UriKind.Absolute, out uri))
                return uri.Host;

            return input;
        }
    }
}
