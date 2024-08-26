# AuthSamples
## �����n�J���U�Ҳ�-²����
[�Ѧ����q���O](https://hackmd.io/@andyhuang1223/S1v1I02xo)

## �إ߱M��
Temolate: `ASP.NET Core Web���ε{��(Model-View-Controller)`
�M�פΤ�׭n���}��A���n��b�P�ӥؿ����U(�]�N�O�w�]���]�w)�C

## ���ұ��v��@
### ���һP���v������
- ���ҡG�P�_�A�O���O�o�Ӻ������ϥΪ̡]�|���^�C
- ���v�G�M�w�A�i���i�H�X�ݸ귽�C
- �|�ӨҤl
    - �i�q�v�|�R�F�����A�o�ɧA�N�O�q�v�|���U��(����)
    - ���۪�������w���U�Χ��b���w����m�A���i�H��O���U�Χ���O����m(���v)

### ���ϥ�Identity��Cookie����
[�ѦҸ��-ASP.NET Core ���Ҫ����[](https://learn.microsoft.com/zh-tw/aspnet/core/security/authentication/?view=aspnetcore-8.0)

`Program.cs`
```csharp=
//Program.cs
using Microsoft.AspNetCore.Authentication.Cookies;

public static void Main(string[] args)
{
    var builder = WebApplication.CreateBuilder(args);

    
    builder.Services.AddControllersWithViews();
    
    //�[�J Cookie ���ҪA�� 
    builder.Services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
    
    var app = builder.Build();

    //�쥻���{���X...
}

```
�p�G���n�]�w���ҪA�Ȫ��պA�ɡG[CookieAuthenticationOptions ���O](https://docs.microsoft.com/zh-tw/dotnet/api/microsoft.aspnetcore.authentication.cookies.cookieauthenticationoptions)

```csharp=
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
        {
            // �n�J�θ��|
            options.LoginPath = "/Account/Login";
            // �S���v���ɪ��ɦV(HTTP Status Code: 403)
            options.AccessDeniedPath ="/Account/AccessDenied";
        });
```

�[�JMiddleware(�����ҦA���v)

```csharp=
//�[�JMiddleWare�A���ǫܭ��n

// �����ҦA���v.
app.UseAuthentication();
app.UseAuthorization();

//�U�����쥻�N���F���n�K!!!!
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapRazorPages();
    //...
});
```
### �n�J��@

1. �b`Models` �ؿ����s�W`LoginViewModel.cs`
```csharp=
public class LoginViewModel
{
    [Display(Name = "�b��")]
    [Required(ErrorMessage = "�b��������")]
    public string? Account { get; set; }

    [Display(Name = "�K�X")]
    [Required(ErrorMessage = "�K�X������")]
    public string? Password { get; set; }

    [Display(Name = "�n�J��ɦV(�ج[�B�z�A�����q�`�|�ð_��)")]
    public string? ReturnUrl { get; set; }
}
```

2. �b`Controllers`�ؿ����s�W`AccountController.cs`�åB�s�W `[HttpGet]`��`Login`��`HttpPost`��`Login` �H�� `[HttpGet]`��`Logout`�C

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
        // ���ұb���K�X.
        // �Ȯɦ���J����@�i�H�n�J
        if (!ModelState.IsValid)
        {
            return View(request);
        }

        // �n�J���\�A�]�w Cookie.
        var claims = new List<Claim>
        {
            // �ѪRCookie�� �|�s�J HttpContext.User.Identity.Name �ݩʤ�
            new Claim(ClaimTypes.Name, request.Account),
            //// ����L����ɥi�H�[�J
            //new Claim(ClaimTypes.Role, "Admin")
        };
        //�i�H�]�w Cookie ����L�ݩ� (https://learn.microsoft.com/zh-tw/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties)
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
        
        // �إ� ClaimsIdentity.
        var claimsIdentity = new ClaimsIdentity(
            claims, CookieAuthenticationDefaults.AuthenticationScheme);

        // �إ� ClaimsPrincipal.
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        // �����n�J.(�g�Jcookie, response �^�ǫ�ͮ�)
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

3. �b`Views/Account`�ؿ����s�W`Login.cshtml`
```csharp=
@model LoginViewModel

@{
    ViewData["Title"] = "�n�J���d��";
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
    @* ��ڤW�n���ð_�� �u�n�ണ���ƨ��ݧY�i *@
    @* <div class="form-group" hidden> *@
        <label asp-for="ReturnUrl"></label>
        <input asp-for="ReturnUrl" class="form-control" />
    </div>
    <button type="submit" class="btn btn-primary">�n�J</button>
</form>
```

4. �b`_Layout.cshtml`�����W�s�W�n�J/�n�X���s�޿�
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
             @* ���϶����n�J�n�X���s�϶� �n�J��|���Claim:Name�εn�X���s *@
             <div class="d-flex align-items-center">
             @if (Context.User?.Identity?.IsAuthenticated ?? false)
             {
                 <span class="text-dark mx-2">@Context.User.Identity.Name</span>
                 <a class="btn btn-outline-info" asp-controller="Account" asp-action="Logout">�n�X</a>
             }
             else
             {
                 <a class="btn btn-outline-success" asp-controller="Account" asp-action="Login">�n�J</a>
             }
             </div>
        </div>
    </nav>
</header>
```
5. �b`HomeController`����`Privacy` Action�W �[�J`[Authorize]`
```csharp=
public class HomeController : Controller
{
    //�W�����쥻���{���X���n�R��...
    
    
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


### ���Ҭy�{�p���G�p���ҩ��ڬO�o�Ӻ������|���O?
1. �Ų��f(`[Authorize]`)�|�ˬd�O�_��Token�]Challenge�y�{�^(HTTP Status Code: 401)�C
2. �S�����Ҹ�T�ɷ|�ɦV�n�J���C
3. ��J�b���αK�X�]�Ψ�L�覡�^�����ҨϥΪ̪��|�������C
4. �T�{�����ᵹ�A�����Ϊ̻\�L��(Token)�A�ثe�|��Token�s�JCookie���C
5. ����Token�N��A�N�O�������|���C
6. ��^�쥻���Ų��f�N�i�H�i�J�X�ݸ귽�F�C

### Cookie�O�ƻ�
- �b�s�����PServer�����A�C����Request��Response���|���a���p���N�C
- �]��HTTP�����O**�L���A**���A�]�N�O���Y�K�O�P�@�ӤH��۬ۦP���귽(���})�s��o�_�ШD�ɡA�򥻤W�L�����D�O�P�@�ӤH�C
- ���F�n�ѧO���P���ШD���A���ǽШD�O�P�@�ӨϥΪ̥ΡA�|��Token�s���Cookie���C
- �q�`�|�]�w����ɶ��A�����Cookie�N�|�����C
- �PlocalStorage���t�O�G
    - localStorage���|�e��Server�ݡA�u��Cookie�|����Client�ݤ�Server�ݡC
    - localStorage�S���ɶ�����ACookie�����Įɶ��C
- �ݧ�h�G[HTTP���򥻩ʽ�](https://hackmd.io/xjFXj_kHQY2cEElvUNAkyw#HTTP%E7%9A%84%E5%9F%BA%E6%9C%AC%E6%80%A7%E8%B3%AA)



### ²����v
[�ѦҸ�� - ASP.NET Core ����²����v](https://docs.microsoft.com/zh-tw/aspnet/core/security/authorization/simple)

`ASP.NET Core`�������v�O�� �Ψ�U�ذѼƩұ��� `AuthorizeAttribute` �C �b�̰򥻪��Φ����A�N `[Authorize]` �ݩʮM�Φ�Controller�BAction �� Razor Page�A�|�����Ӥ��󪺦s���v���w���Ҫ��ϥΪ̡C
`[AllowAnonymous]`�i�H���S�����Ҫ��ϥΪ̳X�ݡA�L�i�H����������`[Authorize]`�����ҡC
```csharp=
[Authorize]
public class AccountController : Controller
{
    [AllowAnonymous]
    public ActionResult Login()
    {
        //�]����[AllowAnonymous]���ݭn���ҴN�i�H�X��
    }

    public ActionResult Logout()
    {
        //�]��Controller�W��[Authorize]�A�S�����ҹL���ϥΪ̱N�|���� challenge �y�{�]�S���Ҫ��|���n�J���^
    }
}
```
### ���⫬���v

[�ѦҸ�� - ASP.NET Core �������⫬���v](https://docs.microsoft.com/zh-tw/aspnet/core/security/authorization/roles)

#### �bController��Action�W�[�J������Attribute
1. �b`Controllers`�ؿ����s�W`RoleController.cs`

```csharp=
public class RoleController : Controller
{
    [Authorize]
    public IActionResult Basic() =>
    Content("Basic");

    [Authorize(Roles = "Admin")]
    public IActionResult Admin() =>
        Content("Admin");

    // �]�i�H���v�h�Ө���
    [Authorize(Roles = "HRManager,Finance")]
    public IActionResult Payslip() =>
            Content("HRManager || Finance");

    // ������ŦX�Ҧ�����������(���O��)
    [Authorize(Roles = "PowerUser")]
    [Authorize(Roles = "ControlPanelUser")]
    public IActionResult ControlPanel() =>
        Content("PowerUser && ControlPanelUser");
}
```

2. �[�J forbidden (HTTP Status Code: 403)�����y�{
�վ�`program.cs` �[�J AccessDeniedPath
```csharp=
 builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
     .AddCookie(options =>
     {
         options.LoginPath = "/Account/Login";
         //forbidden 403 ���઺����
         options.AccessDeniedPath = "/Account/AccessDenied";
     });
```
3. �b`AccountController.cs`���s�W�b������ Action

```csharp=
 [HttpGet]
 public IActionResult AccessDenied()
 {
     return View();
 }

```
4. �b`Views/Account`�ؿ����s�W`AccessDenied.cshtml`
```csharp=
@{
    ViewData["Title"] = "Access Denied";
}
<h2>Opps.... �S�����v������!</h2>

```

5. ���դ@�U ���O�I�s `/Role/Basic`, `/Role/Admin`, `/Role/Payslip`, `/Role/ControlPanel` �d�ݵ��G�C
6. �վ�n�J���y�{�A���O�s�W������`Claim`
```csharp=
 // �n�J���\�A�]�w Cookie.
 var claims = new List<Claim>
 {
     // �ѪRCookie�� �|�s�J HttpContext.User.Identity.Name �ݩʤ�
     new Claim(ClaimTypes.Name, request.Account),

     //�H�U���⬰������v���d�ҨϥΡA�i�H�ۦ�w�q
     //new Claim(ClaimTypes.Role, "Admin"),
     //new Claim(ClaimTypes.Role, "HRManager"),
     //new Claim(ClaimTypes.Role, "PowerUser"),
     //new Claim(ClaimTypes.Role, "ControlPanelUser"),


 };

```

### �p��
1. ���һP���v�������G
    1. ���ҶȬ��T�{�ϥΪ̨���
    2. ���v���O�_���v���X�ݸ귽
2. `ASP.NET Core` ���һP�n�X����@
    1. ���ϥ�Identoty��Cookie����
    2. `Claim`
    3. `ClaimIdentity`
    4. `AuthenticationProperties`
3. `ASP.NET Core` ²����v
    1. `[Authorize]`: �p��ϥ�AuthoriseAttribute�C
4. `ASP.NET Core` ���⫬���v�]`[Authorize(Roles="")]`�^
    1. �ŦX������]�w�G�䤤�@�ب���ŦX�N���v�C
    2. �ݲŦX�Ҧ�������G�Ҧ����ⳣ���ŦX�~���v�C
6. Cookie-Based Authentication
    1. �ϥΪ̿�J�b���αK�X�V Server ���Ҩ����C
    2. Server �T�{������N Token �s�J`Cookie`��^�� Response�C
    3. �ϥΪ̡]Client�^�U���o�_�ШD�ɡA�] Cookie ���� Token ��T�AServer �q Cookie �����o Token ��i�樭�����ҥH�νT�{�O�_���v���s���귽�C




## �ѦҸ��
- [���z�L ASP.NET Core Identity �ϥ� cookie ����](https://learn.microsoft.com/zh-tw/aspnet/core/security/authentication/cookie)