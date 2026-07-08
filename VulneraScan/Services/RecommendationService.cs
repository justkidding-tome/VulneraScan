using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Generates actionable security recommendations mapped to vulnerability categories.
    /// </summary>
    public class RecommendationService : IRecommendationService
    {
        public List<SecurityRecommendation> GenerateRecommendations(IEnumerable<Vulnerability> vulnerabilities)
        {
            var recommendations = new List<SecurityRecommendation>();

            foreach (var vuln in vulnerabilities)
            {
                var rec = GenerateForVulnerability(vuln);
                recommendations.Add(rec);
            }

            return recommendations;
        }

        private static SecurityRecommendation GenerateForVulnerability(Vulnerability vuln)
        {
            var (description, impact, mitigation) = GetRecommendationContent(vuln);

            return new SecurityRecommendation
            {
                Title = $"Fix: {vuln.Name}",
                Description = description,
                Impact = impact,
                MitigationSteps = mitigation,
                Priority = vuln.SeverityLevel,
                VulnerabilityId = vuln.Id
            };
        }

        private static (string Description, string Impact, string Mitigation) GetRecommendationContent(Vulnerability vuln)
        {
            if (vuln.Name.StartsWith("Missing Security Header: "))
            {
                return GetSecurityHeaderRec(vuln);
            }

            return vuln.Name switch
            {
                "Server Version Disclosure" => (
                    "The web server is disclosing its exact version through the 'Server' HTTP response header.",
                    "Attackers can use version information to identify known CVEs and exploits specific to that software.",
                    "Remove or obfuscate the Server header. For IIS, use UrlScan or modify the registry. For Nginx, set 'server_tokens off;'. For Apache, set 'ServerTokens Prod'."
                ),
                "Technology Stack Disclosure (X-Powered-By)" => (
                    "The application exposes technology details via the 'X-Powered-By' HTTP response header.",
                    "Revealing framework details (e.g., ASP.NET, PHP) allows attackers to tailor exploits against the specific stack.",
                    "Remove the X-Powered-By header from the server configuration. In ASP.NET Core, this is typically handled by Kestrel automatically, but remove any manual additions."
                ),
                "Expired SSL/TLS Certificate" => (
                    "The SSL/TLS certificate used by the server has expired.",
                    "Browsers will block access or display severe warnings. Data may still be encrypted, but identity verification fails, making MITM attacks possible.",
                    "Immediately renew and install a valid SSL/TLS certificate from a trusted Certificate Authority (CA)."
                ),
                "SSL/TLS Certificate Expiring Soon" => (
                    "The server's SSL/TLS certificate is nearing its expiration date (within 30 days).",
                    "If the certificate expires, users will face browser warnings and connection blocks, disrupting service.",
                    "Renew the SSL/TLS certificate before the expiration date to maintain uninterrupted secure communications."
                ),
                "SSL/TLS Certificate Validation Error" => (
                    "The SSL/TLS certificate presented by the server has validation errors (e.g., untrusted root, hostname mismatch).",
                    "Users will receive browser warnings. Untrusted certificates cannot guarantee server identity, exposing users to MITM attacks.",
                    "Install a valid SSL/TLS certificate issued by a trusted CA that matches the server's domain name exactly."
                ),
                "Weak TLS Protocol Version" => (
                    "The server supports outdated and insecure TLS protocol versions (e.g., TLS 1.0 or TLS 1.1).",
                    "Older protocols have known cryptographic flaws (like BEAST or POODLE), allowing attackers to decrypt intercepted traffic.",
                    "Disable TLS 1.0 and TLS 1.1. Configure the server to accept only TLS 1.2 and TLS 1.3 using strong, modern cipher suites."
                ),
                "No HTTPS Support" => (
                    "The application is accessible over unencrypted HTTP (port 80) without enforcing HTTPS.",
                    "All data transmitted between the user and the server, including credentials and session tokens, is sent in plaintext and can be easily intercepted.",
                    "Configure the server to support HTTPS. Install an SSL/TLS certificate and implement a permanent redirect (HTTP 301) from HTTP to HTTPS."
                ),
                "FTP Service Exposed" => (
                    "The File Transfer Protocol (FTP) service is accessible over the network.",
                    "FTP transmits all data and authentication credentials in plaintext, making it highly susceptible to packet sniffing and interception.",
                    "Disable FTP and replace it with a secure alternative such as SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL/TLS). Block port 21 on the external firewall."
                ),
                "Telnet Service Exposed" => (
                    "The Telnet service is exposed and accessible.",
                    "Telnet transmits all communication, including passwords, in plaintext. It is a deprecated and inherently insecure protocol.",
                    "Disable the Telnet service immediately. Use SSH (Secure Shell) for remote command-line administration. Block port 23 on the external firewall."
                ),
                "SMB Service Exposed" => (
                    "Server Message Block (SMB) is exposed to the internet.",
                    "Exposed SMB services are a prime target for critical vulnerabilities (e.g., EternalBlue) and ransomware attacks.",
                    "Block port 445 on the external firewall immediately. Ensure SMB is only accessible over a secure VPN if remote access is required."
                ),
                "RDP Service Exposed" => (
                    "Remote Desktop Protocol (RDP) is publicly accessible.",
                    "Publicly exposed RDP is frequently targeted by brute-force attacks and known exploits to gain unauthorized remote access.",
                    "Block port 3389 from public access. Require a VPN with Multi-Factor Authentication (MFA) or use an RD Gateway for remote access."
                ),
                "MySQL Service Exposed" => (
                    "The MySQL database service is exposed to the internet.",
                    "Direct internet access to databases increases the risk of brute-force attacks and exploitation of database vulnerabilities.",
                    "Restrict access to port 3306. Ensure the database is only accessible from trusted internal IP addresses or application servers."
                ),
                "Outdated Apache Web Server" => (
                    "The Apache HTTP Server version is severely outdated (e.g., 2.0 or 2.2).",
                    "Outdated versions contain publicly known vulnerabilities that attackers can exploit to compromise the server.",
                    "Upgrade the Apache HTTP Server to the latest stable release (e.g., 2.4.x) and apply all security patches."
                ),
                "Outdated IIS Web Server" => (
                    "The Microsoft IIS version is outdated (e.g., IIS 6 or 7) and no longer supported.",
                    "Unsupported software does not receive security updates, leaving it permanently vulnerable to newly discovered exploits.",
                    "Migrate to a modern, supported operating system and web server version (e.g., IIS 10 on Windows Server 2019/2022)."
                ),
                _ when vuln.Name.StartsWith("Potential Default Credentials on ") => (
                    $"The {vuln.AffectedComponent} service might be using default manufacturer credentials.",
                    "Default credentials are widely known and routinely tested by attackers to easily gain administrative access.",
                    "Change all default passwords immediately. Enforce a strong password policy and implement Multi-Factor Authentication (MFA) if supported."
                ),
                _ => vuln.Category switch
                {
                    VulnerabilityCategory.SecurityMisconfiguration => GetGenericSecurityMisconfigRec(),
                    VulnerabilityCategory.SensitiveDataExposure => GetGenericDataExposureRec(),
                    VulnerabilityCategory.WeakEncryption => GetGenericWeakEncryptionRec(),
                    VulnerabilityCategory.AuthenticationIssues => GetGenericAuthRec(),
                    VulnerabilityCategory.NetworkExposure => GetGenericNetworkExposureRec(),
                    VulnerabilityCategory.Injection => GetGenericInjectionRec(),
                    _ => ("Review and address this security finding.",
                           "Potential security risk if left unaddressed.",
                           "1. Review the finding details\n2. Assess the risk in your environment\n3. Apply appropriate mitigations")
                }
            };
        }

        private static (string Description, string Impact, string Mitigation) GetSecurityHeaderRec(Vulnerability vuln)
        {
            var headerName = vuln.Name.Replace("Missing Security Header: ", "").Trim();

            return headerName switch
            {
                "X-Frame-Options" => (
                    "The X-Frame-Options header is missing from the HTTP response.",
                    "Without this header, the application can be embedded in an iframe on a malicious site, exposing users to clickjacking attacks.",
                    "Add the 'X-Frame-Options: DENY' header to prevent all framing, or 'X-Frame-Options: SAMEORIGIN' if framing within the same site is required."
                ),
                "X-Content-Type-Options" => (
                    "The X-Content-Type-Options header is missing.",
                    "Browsers may perform MIME-type sniffing, potentially interpreting non-executable files as executable code, leading to Cross-Site Scripting (XSS).",
                    "Add the 'X-Content-Type-Options: nosniff' header to instruct browsers to strictly honor the declared Content-Type."
                ),
                "Strict-Transport-Security" => (
                    "The HTTP Strict-Transport-Security (HSTS) header is missing.",
                    "Without HSTS, browsers may connect via unencrypted HTTP before redirecting to HTTPS, allowing man-in-the-middle downgrade attacks.",
                    "Add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to enforce HTTPS for the next year."
                ),
                "Content-Security-Policy" => (
                    "The Content-Security-Policy (CSP) header is not implemented.",
                    "The absence of CSP makes the application more susceptible to Cross-Site Scripting (XSS) and data injection attacks.",
                    "Implement a strict Content-Security-Policy header (e.g., \"Content-Security-Policy: default-src 'self'\"). Test the policy using Report-Only mode before enforcing to prevent website functionality issues."
                ),
                "X-XSS-Protection" => (
                    "The X-XSS-Protection header is not set. Note: This is a legacy security control.",
                    "Older browsers lacking modern CSP may be vulnerable to reflected XSS attacks if this header is not enforced.",
                    "For legacy browser support, add the 'X-XSS-Protection: 1; mode=block' header. However, prioritize implementing a robust Content-Security-Policy as the modern alternative."
                ),
                "Referrer-Policy" => (
                    "The Referrer-Policy header is missing.",
                    "The application might leak sensitive information contained in URLs (like tokens or IDs) to external sites via the Referer header.",
                    "Add the 'Referrer-Policy: strict-origin-when-cross-origin' header to prevent leaking full URLs to different origins."
                ),
                "Permissions-Policy" => (
                    "The Permissions-Policy header (formerly Feature-Policy) is missing.",
                    "The application does not restrict which browser features and APIs (e.g., camera, microphone, geolocation) can be used, potentially leading to privacy abuses.",
                    "Add the 'Permissions-Policy' header to explicitly disable unnecessary features. Example: 'Permissions-Policy: geolocation=(), camera=(), microphone=()'."
                ),
                _ => (
                    $"The {headerName} security header is missing.",
                    "Lack of proper security headers reduces the application's defense-in-depth mechanisms.",
                    $"Configure your web server to include the {headerName} header with appropriate values based on your application's requirements."
                )
            };
        }

        private static (string, string, string) GetGenericSecurityMisconfigRec()
        {
            return (
                "Security misconfiguration can lead to unauthorized access, data exposure, or system compromise.",
                "Misconfigured services or software can be exploited by attackers to gain access or escalate privileges.",
                "1. Update all software to the latest versions\n" +
                "2. Remove unnecessary services and features\n" +
                "3. Follow vendor hardening guides\n" +
                "4. Implement regular configuration audits"
            );
        }

        private static (string, string, string) GetGenericDataExposureRec()
        {
            return (
                "Information disclosure through server headers and error messages can help attackers identify software versions and potential vulnerabilities.",
                "Exposed version information allows attackers to search for known CVEs and exploits targeting the specific software version.",
                "1. Configure custom error pages to prevent stack trace disclosure\n" +
                "2. Disable directory listing\n" +
                "3. Review all HTTP response headers for information leakage"
            );
        }

        private static (string, string, string) GetGenericWeakEncryptionRec()
        {
            return (
                "Weak SSL/TLS configuration can expose encrypted communications to interception and decryption.",
                "Attackers can exploit weak TLS configurations to perform man-in-the-middle attacks and decrypt sensitive data.",
                "1. Use strong cipher suites\n" +
                "2. Configure proper certificate chain\n" +
                "3. Test using SSL Labs (ssllabs.com/ssltest)"
            );
        }

        private static (string, string, string) GetGenericAuthRec()
        {
            return (
                "Services with weak or default authentication configurations are prime targets for unauthorized access.",
                "Default or weak credentials can be easily guessed or brute-forced, leading to complete system compromise.",
                "1. Implement strong password policies\n" +
                "2. Enable multi-factor authentication where possible\n" +
                "3. Implement account lockout policies\n" +
                "4. Monitor for brute-force attempts\n" +
                "5. Use key-based authentication for SSH"
            );
        }

        private static (string, string, string) GetGenericNetworkExposureRec()
        {
            return (
                "Exposing sensitive network services to the internet significantly increases the attack surface.",
                "Publicly accessible services are frequent targets for automated attacks and exploitation.",
                "1. Restrict access using firewall rules (allow only trusted IPs)\n" +
                "2. Use VPN for remote access instead of exposing services directly\n" +
                "3. Disable unnecessary services\n" +
                "4. Implement network segmentation\n" +
                "5. Enable intrusion detection/prevention systems"
            );
        }

        private static (string, string, string) GetGenericInjectionRec()
        {
            return (
                "Injection vulnerabilities allow attackers to inject malicious code or commands into the application.",
                "Successful injection attacks can lead to data theft, data manipulation, or complete system compromise.",
                "1. Use parameterized queries/prepared statements\n" +
                "2. Implement input validation and sanitization\n" +
                "3. Apply the principle of least privilege for database accounts\n" +
                "4. Use stored procedures where possible\n" +
                "5. Implement Web Application Firewall (WAF)"
            );
        }
    }
}

