using Microsoft.AspNetCore.Identity;

namespace Core_RBS_Tokens.Services
{
    /// <summary>
    /// The Following class createa an Administrator Role and User
    /// </summary>
    public static class AdminCreatorService
    {
        public static async Task CreateApplicationAdministrator(IServiceProvider serviceProvider)
        {
            try
            {
                // retrive instances of the RoleManager and UserManager 
                //from the Dependency Container
                var roleManager = serviceProvider
                	.GetRequiredService<RoleManager<IdentityRole>>();
                var userManager = serviceProvider
                	.GetRequiredService<UserManager<IdentityUser>>();

                IdentityResult result;
                // add a new Administrator role for the application
                var isRoleExist = await roleManager
                	.RoleExistsAsync("Administrator");
                if (!isRoleExist)
                {
                    // create Administrator Role and add it in Database
                    result = await roleManager
                    	.CreateAsync(new IdentityRole("Administrator"));
                }

                // code to create a default user and add it to Administrator Role
                var user = await userManager
                	.FindByEmailAsync("admin@myapp.com");
                if (user == null)
                {
                    var defaultUser = new IdentityUser() 
                    {
                    	UserName = "admin@myapp.com",
                        Email = "admin@myapp.com" 
                    };
                    var regUser = await userManager
                    	.CreateAsync(defaultUser, "P@ssw0rd_");
                    await userManager
                    	.AddToRoleAsync(defaultUser, "Administrator");
                }
            }
            catch (Exception ex)
            {
                var str = ex.Message;
            }

        }
    }
}
