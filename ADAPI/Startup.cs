using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin;
using Owin;
using ADAPI.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity;

[assembly: OwinStartup(typeof(ADAPI.Startup))]

namespace ADAPI
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
            ConfigureRoles();
        }

        /// <summary>
        /// Configures User roles, if non existent then roles are generated.
        /// </summary>
        private void ConfigureRoles()
        {
            ApplicationDbContext context = new ApplicationDbContext();

            RoleManager<IdentityRole> roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(context));
            UserManager<ApplicationUser> userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(context));

            if (!roleManager.RoleExists("Admin"))
            {
                IdentityRole role = new IdentityRole();
                role.Name = "Admin";
                roleManager.Create(role);

                //Username and email must match. OAUTH 2.0 login validation check.
                ApplicationUser user = new ApplicationUser();
                user.UserName = "s3watch@summithealthcare.com";
                user.Email = "s3watch@summithealthcare.com";
                user.EmailConfirmed = true;
                string userPassword = "Summit99$";

                IdentityResult userCreation = userManager.Create(user, userPassword);

                if (userCreation.Succeeded)
                {
                    IdentityResult result = userManager.AddToRole(user.Id, "Admin");
                }
            }

            if (!roleManager.RoleExists("Employee"))
            {
                IdentityRole role = new IdentityRole();
                role.Name = "Employee";
                roleManager.Create(role);
            }
        }
    }
}
