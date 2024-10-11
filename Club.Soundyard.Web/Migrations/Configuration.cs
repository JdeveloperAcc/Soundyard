using System.Data.Entity.Migrations;

namespace Club.Soundyard.Web.Migrations
{
    internal sealed class Configuration : DbMigrationsConfiguration<Club.Soundyard.Web.Models.ApplicationDbContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = true;
            ContextKey = "Club.Soundyard.Web.Models.ApplicationDbContext";
        }

        protected override void Seed(Club.Soundyard.Web.Models.ApplicationDbContext context)
        {
            //  This method will be called after migrating to the latest version.

            //  You can use the DbSet<T>.AddOrUpdate() helper extension method
            //  to avoid creating duplicate seed data.
        }
    }
}
