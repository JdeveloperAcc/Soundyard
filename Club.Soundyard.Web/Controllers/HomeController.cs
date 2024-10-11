using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Club.Soundyard.Web.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Message = UserStatus;

            return View();
        }

        //Only Authorize User Can Access the Action Methods of this Controller
        [Authorize]
        public ActionResult Dashboard()
        {
            ViewBag.Message = UserStatus;
            ViewBag.Info = UserAgreement;

            return View();
        }

        [Authorize]
        public ActionResult Report()
        {
            ViewBag.Message = UserStatus;

            return View();
        }

        [Authorize(Roles = "Administrator")]
        public ActionResult Administration()
        {
            ViewBag.Message = UserStatus;

            return View();
        }

        private string UserAgreement
        {
            get
            {
                var mng = HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
                if (mng != null)
                {
                    string id = User?.Identity?.GetUserId();
                    if (!string.IsNullOrEmpty(id))
                    {
                        var userInfo = mng.Users.FirstOrDefault(x => x.Id == id);
                        if (userInfo != null)
                        {
                            return userInfo.UserAgreement;
                        }
                    }
                }

                return string.Empty;
            }
        }

        private string UserStatus
        {
            get
            {
                var mng = HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
                if (mng != null)
                {
                    string id = User?.Identity?.GetUserId();
                    if (!string.IsNullOrEmpty(id))
                    {
                        var userInfo = mng.Users.FirstOrDefault(x => x.Id == id);
                        if (userInfo != null)
                        {
                            return userInfo.ToString();
                        }
                    }
                }

                return string.Empty;
            }
        }
    }
}