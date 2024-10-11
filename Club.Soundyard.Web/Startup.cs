using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Club.Soundyard.Web.Startup))]
namespace Club.Soundyard.Web
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
