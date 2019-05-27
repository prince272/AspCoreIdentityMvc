using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Controllers
{
    [Area("IdentityMvc")]
    [Authorize]
    public class ManageController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}