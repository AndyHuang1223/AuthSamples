# AuthSamples
## 網站登入註冊模組-簡易版
[參考講義筆記](https://hackmd.io/@andyhuang1223/S1v1I02xo)

## 建立專案
Temolate: `ASP.NET Core Web應用程式(Model-View-Controller)`
專案及方案要分開放，不要放在同個目錄底下(也就是預設的設定)。

## 驗證授權實作
### 驗證與授權的概念
- 驗證：判斷你是不是這個網站的使用者（會員）。
- 授權：決定你可不可以訪問資源。
- 舉個例子
    - 進電影院買了門票，這時你就是電影院的顧客(驗證)
    - 拿著門票到指定的廳及坐在指定的位置，不可以到別的廳或坐到別的位置(授權)

### 不使用Identity的Cookie驗證
[參考資料-ASP.NET Core 驗證的概觀](https://learn.microsoft.com/zh-tw/aspnet/core/security/authentication/?view=aspnetcore-8.0)

`Program.cs`
```csharp=
//Program.cs
using Microsoft.AspNetCore.Authentication.Cookies;

public static void Main(string[] args)
{
    var builder = WebApplication.CreateBuilder(args);

    
    builder.Services.AddControllersWithViews();
    
    //加入 Cookie 驗證服務 
    builder.Services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
    
    var app = builder.Build();

    //原本的程式碼...
}

```
如果有要設定驗證服務的組態時：[CookieAuthenticationOptions 類別](https://docs.microsoft.com/zh-tw/dotnet/api/microsoft.aspnetcore.authentication.cookies.cookieauthenticationoptions)

```csharp=
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
        {
            // 登入用路徑
            options.LoginPath = "/Account/Login";
            // 沒有權限時的導向(HTTP Status Code: 403)
            options.AccessDeniedPath ="/Account/AccessDenied";
        });
```

加入Middleware(先驗證再授權)

```csharp=
//加入MiddleWare，順序很重要

// 先驗證再授權.
app.UseAuthentication();
app.UseAuthorization();

//下面的原本就有了不要貼!!!!
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapRazorPages();
    //...
});
```
### 登入實作

1. 在`Models` 目錄內新增`LoginViewModel.cs`
```csharp=
public class LoginViewModel
{
    [Display(Name = "帳號")]
    [Required(ErrorMessage = "帳號為必填")]
    public string? Account { get; set; }

    [Display(Name = "密碼")]
    [Required(ErrorMessage = "密碼為必填")]
    public string? Password { get; set; }

    [Display(Name = "登入後導向(框架處理，該欄位通常會藏起來)")]
    public string? ReturnUrl { get; set; }
}
```

2. 在`Controllers`目錄內新增`AccountController.cs`並且新增 `[HttpGet]`的`Login`及`HttpPost`的`Login` 以及 `[HttpGet]`的`Logout`。

```csharp=
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
            //// 有其他角色時可以加入
            //new Claim(ClaimTypes.Role, "Admin")
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
```

3. 在`Views/Account`目錄內新增`Login.cshtml`
```csharp=
@model LoginViewModel

@{
    ViewData["Title"] = "登入頁範例";
}

<h2>@ViewData["Title"]</h2>

<form asp-controller="Account" asp-action="Login" method="post">
    <div asp-validation-summary="ModelOnly" class="text-danger"></div>
    <div class="form-group">
        <label asp-for="Account"></label>
        <input asp-for="Account" class="form-control" />
        <span asp-validation-for="Account" class="text-danger"></span>
    </div>
    <div class="form-group">
        <label asp-for="Password"></label>
        <input asp-for="Password" class="form-control" />
        <span asp-validation-for="Password" class="text-danger"></span>
    </div>
    <div class="form-group">
    @* 實際上要隱藏起來 只要能提交資料到後端即可 *@
    @* <div class="form-group" hidden> *@
        <label asp-for="ReturnUrl"></label>
        <input asp-for="ReturnUrl" class="form-control" />
    </div>
    <button type="submit" class="btn btn-primary">登入</button>
</form>
```

4. 在`_Layout.cshtml`頁面上新增登入/登出按鈕邏輯
```csharp=
<header>
    <nav class="navbar navbar-expand-sm navbar-toggleable-sm navbar-light bg-white border-bottom box-shadow mb-3">
        <div class="container-fluid">
            <a class="navbar-brand" asp-area="" asp-controller="Home" asp-action="Index">CookieBasedAuthenticationSample</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target=".navbar-collapse" aria-controls="navbarSupportedContent"
                    aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="navbar-collapse collapse d-sm-inline-flex justify-content-between">
                <ul class="navbar-nav flex-grow-1">
                    <li class="nav-item">
                        <a class="nav-link text-dark" asp-area="" asp-controller="Home" asp-action="Index">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-dark" asp-area="" asp-controller="Home" asp-action="Privacy">Privacy</a>
                    </li>
                </ul>
            </div>
             @* 此區塊為登入登出按鈕區塊 登入後會顯示Claim:Name及登出按鈕 *@
             <div class="d-flex align-items-center">
             @if (Context.User?.Identity?.IsAuthenticated ?? false)
             {
                 <span class="text-dark mx-2">@Context.User.Identity.Name</span>
                 <a class="btn btn-outline-info" asp-controller="Account" asp-action="Logout">登出</a>
             }
             else
             {
                 <a class="btn btn-outline-success" asp-controller="Account" asp-action="Login">登入</a>
             }
             </div>
        </div>
    </nav>
</header>
```
5. 在`HomeController`內的`Privacy` Action上 加入`[Authorize]`
```csharp=
public class HomeController : Controller
{
    //上面為原本的程式碼不要刪除...
    
    
    [Authorize]
    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
```


### 驗證流程小結：如何證明我是這個網站的會員呢?
1. 剪票口(`[Authorize]`)會檢查是否有Token（Challenge流程）(HTTP Status Code: 401)。
2. 沒有驗證資訊時會導向登入頁。
3. 輸入帳號及密碼（或其他方式）來驗證使用者的會員身份。
4. 確認身分後給你門票或者蓋印章(Token)，目前會把Token存入Cookie內。
5. 拿著Token代表你就是網站的會員。
6. 返回原本的剪票口就可以進入訪問資源了。

### Cookie是甚麼
- 在瀏覽器與Server之間，每次的Request及Response都會夾帶的小玩意。
- 因為HTTP本身是**無狀態**的，也就是說即便是同一個人對著相同的資源(網址)連續發起請求時，基本上他不知道是同一個人。
- 為了要識別不同的請求中，那些請求是同一個使用者用，會把Token存放到Cookie內。
- 通常會設定到期時間，到期後Cookie就會消失。
- 與localStorage的差別：
    - localStorage不會送到Server端，只有Cookie會往返Client端及Server端。
    - localStorage沒有時間限制，Cookie有失效時間。
- 看更多：[HTTP的基本性質](https://hackmd.io/xjFXj_kHQY2cEElvUNAkyw#HTTP%E7%9A%84%E5%9F%BA%E6%9C%AC%E6%80%A7%E8%B3%AA)



### 簡單授權
[參考資料 - ASP.NET Core 中的簡單授權](https://docs.microsoft.com/zh-tw/aspnet/core/security/authorization/simple)

`ASP.NET Core`中的授權是由 及其各種參數所控制 `AuthorizeAttribute` 。 在最基本的形式中，將 `[Authorize]` 屬性套用至Controller、Action 或 Razor Page，會限制對該元件的存取權給已驗證的使用者。
`[AllowAnonymous]`可以讓沒有驗證的使用者訪問，他可以忽略掉有掛`[Authorize]`的驗證。
```csharp=
[Authorize]
public class AccountController : Controller
{
    [AllowAnonymous]
    public ActionResult Login()
    {
        //因為有[AllowAnonymous]不需要驗證就可以訪問
    }

    public ActionResult Logout()
    {
        //因為Controller上有[Authorize]，沒有驗證過的使用者將會執行 challenge 流程（沒驗證的會跳登入頁）
    }
}
```
### 角色型授權

[參考資料 - ASP.NET Core 中的角色型授權](https://docs.microsoft.com/zh-tw/aspnet/core/security/authorization/roles)

#### 在Controller或Action上加入對應的Attribute
1. 在`Controllers`目錄內新增`RoleController.cs`

```csharp=
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
```

2. 加入 forbidden (HTTP Status Code: 403)相關流程
調整`program.cs` 加入 AccessDeniedPath
```csharp=
 builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
     .AddCookie(options =>
     {
         options.LoginPath = "/Account/Login";
         //forbidden 403 跳轉的頁面
         options.AccessDeniedPath = "/Account/AccessDenied";
     });
```
3. 在`AccountController.cs`內新增在對應的 Action

```csharp=
 [HttpGet]
 public IActionResult AccessDenied()
 {
     return View();
 }

```
4. 在`Views/Account`目錄內新增`AccessDenied.cshtml`
```csharp=
@{
    ViewData["Title"] = "Access Denied";
}
<h2>Opps.... 沒有授權的頁面!</h2>

```

5. 測試一下 分別呼叫 `/Role/Basic`, `/Role/Admin`, `/Role/Payslip`, `/Role/ControlPanel` 查看結果。
6. 調整登入的流程，分別新增對應的`Claim`
```csharp=
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

```

### 小結
1. 驗證與授權的概念：
    1. 驗證僅為確認使用者身份
    2. 授權為是否有權限訪問資源
2. `ASP.NET Core` 驗證與登出的實作
    1. 不使用Identoty的Cookie驗證
    2. `Claim`
    3. `ClaimIdentity`
    4. `AuthenticationProperties`
3. `ASP.NET Core` 簡單授權
    1. `[Authorize]`: 如何使用AuthoriseAttribute。
4. `ASP.NET Core` 角色型授權（`[Authorize(Roles="")]`）
    1. 符合的角色設定：其中一種角色符合就授權。
    2. 需符合所有的角色：所有角色都須符合才授權。
6. Cookie-Based Authentication
    1. 使用者輸入帳號及密碼向 Server 驗證身份。
    2. Server 確認身份後將 Token 存入`Cookie`後回傳 Response。
    3. 使用者（Client）下次發起請求時，因 Cookie 內有 Token 資訊，Server 從 Cookie 內取得 Token 後進行身份驗證以及確認是否有權限瀏覽資源。




## 參考資料
- [不透過 ASP.NET Core Identity 使用 cookie 驗證](https://learn.microsoft.com/zh-tw/aspnet/core/security/authentication/cookie)