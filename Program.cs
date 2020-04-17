using System.Threading.Tasks;
using JWTAuthAPI.Models.ApplicationRole;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace JWTAuthAPI
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var host = CreateWebHostBuilder(args).Build();

            using (var serviceScope = host.Services.CreateScope())
            {
                var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                if (!await roleManager.RoleExistsAsync(ApplicationRole.Admin))
                {
                    var adminRole = new IdentityRole(ApplicationRole.Admin);
                    await roleManager.CreateAsync(adminRole);
                }

                if (!await roleManager.RoleExistsAsync(ApplicationRole.User))
                {
                    var userRole = new IdentityRole(ApplicationRole.User);
                    await roleManager.CreateAsync(userRole);
                }
            }

            await host.RunAsync();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args).UseStartup<Startup>();
    }
}
