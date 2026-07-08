using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VulneraScan.Helpers;
using VulneraScan.Models;

namespace VulneraScan.Data
{
    public static class IdentityDataSeeder
    {
        /// <summary>
        /// Seeds required roles and default users (admin, security analyst) if they do not exist.
        /// This method is idempotent and safe to run multiple times.
        /// </summary>
        /// <param name="serviceProvider">
        /// The already-scoped <see cref="IServiceProvider"/> created by the caller in Program.cs.
        /// Do NOT create an inner scope here; that causes a double-scope anti-pattern where the
        /// inner scope's lifetime becomes independent of the outer scope's EF Core transaction.
        /// </param>
        public static async Task SeedAsync(IServiceProvider serviceProvider)
        {
            // Resolve directly from the scoped provider supplied by Program.cs.
            // Program.cs already wraps this call in: using (var scope = app.Services.CreateScope())
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger("IdentityDataSeeder");

            try
            {
                // Ensure roles exist. Use the constants so role names are never duplicated.
                var roles = new[] { Constants.Roles.Administrator, Constants.Roles.SecurityAnalyst };
                foreach (var roleName in roles)
                {
                    if (!await roleManager.RoleExistsAsync(roleName))
                    {
                        var createRoleResult = await roleManager.CreateAsync(new IdentityRole(roleName));
                        if (!createRoleResult.Succeeded)
                        {
                            logger.LogError("Failed to create role {Role}: {Errors}", roleName,
                                string.Join(',', createRoleResult.Errors.Select(e => e.Description)));
                        }
                        else
                        {
                            logger.LogInformation("Created role {Role}", roleName);
                        }
                    }
                }

                // Seed Administrator user
                var adminEmail = "admin@gmail.com";
                var adminUser = await userManager.FindByEmailAsync(adminEmail);
                if (adminUser == null)
                {
                    adminUser = new ApplicationUser
                    {
                        UserName = adminEmail,
                        Email = adminEmail,
                        FullName = "Administrator",
                        EmailConfirmed = true,
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    var createAdmin = await userManager.CreateAsync(adminUser, "Admin@123");
                    if (createAdmin.Succeeded)
                    {
                        if (!await userManager.IsInRoleAsync(adminUser, Constants.Roles.Administrator))
                        {
                            await userManager.AddToRoleAsync(adminUser, Constants.Roles.Administrator);
                            logger.LogInformation("Assigned role {Role} to {Email}",
                                Constants.Roles.Administrator, adminEmail);
                        }

                        logger.LogInformation("Created default administrator account: {Email}", adminEmail);
                    }
                    else
                    {
                        logger.LogError("Failed to create admin user {Email}: {Errors}", adminEmail,
                            string.Join(',', createAdmin.Errors.Select(e => e.Description)));
                    }
                }
                else
                {
                    // Re-save FullName and Email to re-encrypt them with the current key just in case it's broken
                    adminUser.FullName = "Administrator";
                    adminUser.Email = adminEmail;
                    await userManager.UpdateAsync(adminUser);
                }

                // Seed Security Analyst user
                var analystEmail = "analyst@gmail.com";
                var analystUser = await userManager.FindByEmailAsync(analystEmail);
                if (analystUser == null)
                {
                    analystUser = new ApplicationUser
                    {
                        UserName = analystEmail,
                        Email = analystEmail,
                        FullName = "Security Analyst",
                        EmailConfirmed = true,
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    var createAnalyst = await userManager.CreateAsync(analystUser, "Analyst@123");
                    if (createAnalyst.Succeeded)
                    {
                        if (!await userManager.IsInRoleAsync(analystUser, Constants.Roles.SecurityAnalyst))
                        {
                            await userManager.AddToRoleAsync(analystUser, Constants.Roles.SecurityAnalyst);
                            logger.LogInformation("Assigned role {Role} to {Email}",
                                Constants.Roles.SecurityAnalyst, analystEmail);
                        }

                        logger.LogInformation("Created default security analyst account: {Email}", analystEmail);
                    }
                    else
                    {
                        logger.LogError("Failed to create analyst user {Email}: {Errors}", analystEmail,
                            string.Join(',', createAnalyst.Errors.Select(e => e.Description)));
                    }
                }
                else
                {
                    // Re-save FullName and Email to re-encrypt them with the current key just in case it's broken
                    analystUser.FullName = "Security Analyst";
                    analystUser.Email = analystEmail;
                    await userManager.UpdateAsync(analystUser);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while seeding identity data.");
            }
        }
    }
}
