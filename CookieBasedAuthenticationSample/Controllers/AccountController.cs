using CookieBasedAuthenticationSample.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CookieBasedAuthenticationSample.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl)
        {
            LoginViewModel loginViewModel = new LoginViewModel
            {
                ReturnUrl = returnUrl
            };
            return View(loginViewModel);
        }

        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> Login([FromForm] LoginViewModel request)
        {
            // 驗證帳號密碼.
            // 暫時有輸入都當作可以登入
            if (!ModelState.IsValid)
            {
                return View(request);
            }

            // 登入成功，設定 Cookie.
            var claims = new List<Claim>
            {
                // 解析Cookie後 會存入 HttpContext.User.Identity.Name 屬性內
                new Claim(ClaimTypes.Name, request.Account),

                //以下角色為角色授權的範例使用，可以自行定義
                //new Claim(ClaimTypes.Role, "Admin"),
                //new Claim(ClaimTypes.Role, "HRManager"),
                //new Claim(ClaimTypes.Role, "PowerUser"),
                //new Claim(ClaimTypes.Role, "ControlPanelUser"),


            };
            //可以設定 Cookie 的其他屬性 (https://learn.microsoft.com/zh-tw/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties)
            var authProperties = new AuthenticationProperties
            {
                //AllowRefresh = <bool>,
                // Refreshing the authentication session should be allowed.

                //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                // The time at which the authentication ticket expires. A 
                // value set here overrides the ExpireTimeSpan option of 
                // CookieAuthenticationOptions set with AddCookie.

                //IsPersistent = true,
                // Whether the authentication session is persisted across 
                // multiple requests. When used with cookies, controls
                // whether the cookie's lifetime is absolute (matching the
                // lifetime of the authentication ticket) or session-based.

                //IssuedUtc = <DateTimeOffset>,
                // The time at which the authentication ticket was issued.

                //RedirectUri = <string>
                // The full path or absolute URI to be used as an http 
                // redirect response value.
            };

            // 建立 ClaimsIdentity.
            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            // 建立 ClaimsPrincipal.
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            // 網站登入.(寫入cookie, response 回傳後生效)
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal,
                authProperties);

            //導向處理
            if (string.IsNullOrEmpty(request.ReturnUrl))
            {
                request.ReturnUrl = "/";
            }
            return Redirect(request.ReturnUrl);
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {

            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Redirect("/");
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
