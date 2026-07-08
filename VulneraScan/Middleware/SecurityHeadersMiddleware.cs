namespace VulneraScan.Middleware
{
    /// <summary>
    /// Adds defensive HTTP security response headers to every outgoing response.
    /// Headers added:
    ///   - X-Frame-Options            : Prevents clickjacking (DENY)
    ///   - X-Content-Type-Options     : Prevents MIME-type sniffing
    ///   - Referrer-Policy            : Limits referrer information leakage
    ///   - X-XSS-Protection           : Legacy XSS filter hint (belt-and-suspenders)
    ///   - Permissions-Policy         : Disables powerful browser features not required by the app
    ///   - Content-Security-Policy    : Allowlist for content sources
    ///   - Strict-Transport-Security  : Enforces HTTPS (production only)
    /// </summary>
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IWebHostEnvironment _env;

        public SecurityHeadersMiddleware(RequestDelegate next, IWebHostEnvironment env)
        {
            _next = next;
            _env = env;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Remove headers that leak server information
            context.Response.Headers.Remove("Server");
            context.Response.Headers.Remove("X-Powered-By");
            context.Response.Headers.Remove("X-AspNet-Version");
            context.Response.Headers.Remove("X-AspNetMvc-Version");

            // Prevent the response from being embedded in a frame (clickjacking protection)
            context.Response.Headers["X-Frame-Options"] = "DENY";

            // Prevent browsers from MIME-sniffing the content-type
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";

            // Control how much referrer information is included with requests
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

            // Legacy XSS filter — most modern browsers ignore this, but included for legacy support
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";

            // Restrict access to powerful browser features that the application does not use
            context.Response.Headers["Permissions-Policy"] =
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), " +
                "microphone=(), payment=(), usb=()";

            // Content Security Policy — allowlist for trusted content sources.
            // Bootstrap and Bootstrap Icons are loaded from the jsDelivr CDN.
            // 'unsafe-inline' for style-src is required for Bootstrap inline styles and Razor-rendered styles.
            // Tighten this policy progressively in later phases as CSP nonces or hashes are introduced.
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; " +
                "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; " +
                "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " +
                "font-src 'self' https://cdn.jsdelivr.net; " +
                "img-src 'self' data:; " +
                "connect-src 'self' https://cdn.jsdelivr.net; " +
                "frame-ancestors 'none'; " +
                "base-uri 'self'; " +
                "form-action 'self';";

            // HTTP Strict Transport Security — only set in non-development environments
            // to avoid blocking local HTTP development.
            if (!_env.IsDevelopment())
            {
                context.Response.Headers["Strict-Transport-Security"] =
                    "max-age=31536000; includeSubDomains";
            }

            await _next(context);
        }
    }

    /// <summary>
    /// Extension method for registering <see cref="SecurityHeadersMiddleware"/> in the pipeline.
    /// </summary>
    public static class SecurityHeadersMiddlewareExtensions
    {
        public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
            => app.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
