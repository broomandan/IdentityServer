using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Mvc;

namespace MVCClient.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize(Order = 1, Roles = "Developer")] // Authorization option 1- using Authorize
        [HandleForbidden]
        public ActionResult About()
        {
            ViewBag.Message = "About";

            var user = User as ClaimsPrincipal;
            var token = user.FindFirst("access_token");

            if (token != null)
            {
                ViewData["access_token"] = token.Value;
            }

            return View();

        }
        [ResourceAuthorize("Read", "ContactDetails")] // Authorization option 2- using ResourceAuthorize
        [HandleForbidden]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
        [ResourceAuthorize("Write", "ContactDetails")] // Authorization option 2- using ResourceAuthorize
        [HandleForbidden]
        public ActionResult UpdateContact()
        {
            ViewBag.Message = "Your UpdateContact page.";

            return View();
        }

        public ActionResult Logout()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }
    }
}