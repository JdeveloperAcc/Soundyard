using System.Web.Mvc;

namespace Club.Soundyard.Web.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
    }
}