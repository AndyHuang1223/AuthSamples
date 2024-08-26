using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace CookieBasedAuthenticationSample.Controllers
{
    public class RoleController : Controller
    {
        [Authorize]
        public IActionResult Basic() =>
        Content("Basic");

        [Authorize(Roles = "Admin")]
        public IActionResult Admin() =>
            Content("Admin");

        // 也可以授權多個角色
        [Authorize(Roles = "HRManager,Finance")]
        public IActionResult Payslip() =>
                Content("HRManager || Finance");

        // 限制必須符合所有對應的角色(分別掛)
        [Authorize(Roles = "PowerUser")]
        [Authorize(Roles = "ControlPanelUser")]
        public IActionResult ControlPanel() =>
            Content("PowerUser && ControlPanelUser");
    }
}
