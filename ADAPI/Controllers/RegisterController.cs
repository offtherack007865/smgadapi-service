using ADAPI.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace ADAPI.Controllers
{
    [Authorize]
    public class RegisterController : Controller
    {
        private ApplicationDbContext _context;

        public RegisterController()
        {
            _context = new ApplicationDbContext();
        }

        // GET: Register
        [HttpGet]
        public ActionResult Index()
        {
            ViewBag.Name = new SelectList(_context.Roles.Where(x => !x.Name.Contains("Admin"))
                                            .ToList(), "Name", "Name");

            return View();
        }
    }
}