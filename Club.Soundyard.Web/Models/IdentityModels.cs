using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Club.Soundyard.Web.Migrations;

namespace Club.Soundyard.Web.Models
{
    public class ApplicationUser : IdentityUser
    {
        //Adding New Properties FirstName, LastName
        [MaxLength(256)]
        public string FirstName { get; set; }

        [MaxLength(256)]
        public string LastName { get; set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }

        public string UserAgreement
        {
            get
            {
                string status = string.Empty;
                if (Roles.Any())
                {
                    ApplicationUserRole uRole = Roles.FirstOrDefault() as ApplicationUserRole;
                    if (uRole != null)
                        status = uRole.Agreement;
                }
                return status;
            }
        }

        public override string ToString()
        {
            return string.Format("{0} {1}!", FirstName, LastName);
        }
    }

    public class ApplicationUserRole : IdentityUserRole
    {
        // Adding New Property Agreement
        [MaxLength(50)]
        public string Agreement { get; set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
            Database.SetInitializer(new
                MigrateDatabaseToLatestVersion<ApplicationDbContext, Configuration>());
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
    }
}