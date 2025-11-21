using coverLetter.AuthService.api.Data;
using coverLetter.AuthService.api.DTOs;
using coverLetter.AuthService.api.Models;
using coverLetter.AuthService.api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Collections;
using System.Net;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Read allowed CORS origins from configuration (appsettings / env vars)
var allowedOrigins = builder.Configuration
    .GetSection("Cors:AllowedOrigins")
    .Get<string[]>() ?? Array.Empty<string>();

var apiBaseUrl = builder.Configuration["Api:BaseUrl"]
    ?? Environment.GetEnvironmentVariable("API_BASE_URL")
    ?? ""; // if empty, relative callback paths are used

var frontendPopupUrl = builder.Configuration["Frontend:PopupCompleteUrl"]
    ?? Environment.GetEnvironmentVariable("FRONTEND_POPUP_COMPLETE_URL")
    ?? "http://localhost:4200/auth/popup-complete";

Console.WriteLine($"apiBaseUrl {apiBaseUrl}");
Console.WriteLine($"frontendPopupUrl {frontendPopupUrl}");

builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        if (allowedOrigins.Length == 0)
        {
            // No origins configured => allow any origin (convenient for local/dev).
            // Cookies / credentials won't work reliably with AllowAnyOrigin.
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        }
        else if (allowedOrigins.Length == 1 && allowedOrigins[0] == "*")
        {
            // Explicit wildcard => same as AnyOrigin
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        }
        else
        {
            // Use explicit origins and allow credentials so the browser will send cookies.
            // Important: When AllowCredentials() is used, you cannot call AllowAnyOrigin().
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        }
    });
});

// Connection string helper (supports Railway DATABASE_URL)
string GetConnectionString()
{
    var env = Environment.GetEnvironmentVariable("DATABASE_URL");
    if (!string.IsNullOrEmpty(env))
    {
        var uri = new Uri(env);
        var userInfo = uri.UserInfo.Split(':');
        var host = uri.Host;
        var port = uri.Port;
        var database = uri.AbsolutePath.TrimStart('/');
        var username = userInfo[0];
        var password = userInfo.Length > 1 ? userInfo[1] : "";
        return $"Host={host};Port={port};Username={username};Password={password};Database={database};Ssl Mode=Require;Trust Server Certificate=true";
    }
    return builder.Configuration.GetConnectionString("DefaultConnection")!;
}

// EF Core + Identity
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(GetConnectionString()));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequiredLength = 6;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();


var jwtKey =
    Environment.GetEnvironmentVariable("JWT_KEY")           
    ?? Environment.GetEnvironmentVariable("Jwt__Key")       
    ?? builder.Configuration["Jwt:Key"];                    

if (string.IsNullOrWhiteSpace(jwtKey))
    throw new Exception("JWT_KEY env var, Jwt__Key env var, or Jwt:Key config is required (tried JWT_KEY, Jwt__Key, appsettings.json)");

var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
builder.Services.AddAuthentication(options =>
{
    // JWT is still the default for protecting API endpoints
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
// JWT for normal API calls
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidateLifetime = true
    };
})
// Cookie used ONLY during Google OAuth flow
.AddCookie("ExternalCookie", options =>
{
    options.Cookie.Name = "external.auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;                 // good for localhost
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // http on localhost
    options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
    options.SlidingExpiration = false;
})
// Google OAuth
.AddGoogle("Google", options =>
{
    var googleSection = builder.Configuration.GetSection("Authentication:Google");
    var googleClientId = googleSection["ClientId"] ?? Environment.GetEnvironmentVariable("Authentication__Google__ClientId");
    var googleClientSecret = googleSection["ClientSecret"] ?? Environment.GetEnvironmentVariable("Authentication__Google__ClientSecret");

    if (string.IsNullOrWhiteSpace(googleClientId) || string.IsNullOrWhiteSpace(googleClientSecret))
    {
        throw new Exception("Google OAuth client id/secret not configured. Set Authentication__Google__ClientId and Authentication__Google__ClientSecret as environment variables or in appsettings.");
    }

    options.ClientId = googleSection["ClientId"];
    options.ClientSecret = googleSection["ClientSecret"];

    options.SignInScheme = "ExternalCookie";

    options.SaveTokens = true;

    // IMPORTANT:
    // This path is owned by the Google middleware ONLY.
    // We will NOT map an endpoint on this path.
    options.CallbackPath = "/signin-google";
});



builder.Services.AddAuthorization();
builder.Services.AddScoped<ITokenService, TokenService>();

var app = builder.Build();

// Ensure DB migrated on startup
using (var scope = app.Services.CreateScope())
{
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    try
    {
        db.Database.Migrate();
    }
    catch (InvalidOperationException ex) when (ex.Message.Contains("PendingModelChangesWarning"))
    {
        // Log detailed diagnostics and continue (temporary)
        logger.LogError(ex, "Pending EF Core model changes detected. Create a migration and apply it. See dotnet ef migrations add ...");
        // Optionally rethrow in non-development environments:
        if (!app.Environment.IsDevelopment())
            throw;
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Use CORS before authentication/authorization so preflight responses include CORS headers
app.UseCors("CorsPolicy");

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/register", async (RegisterDto dto, UserManager<ApplicationUser> userManager, ITokenService tokenService) =>
{
    if (await userManager.FindByEmailAsync(dto.Email) != null)
        return Results.BadRequest(new { error = "Email already in use" });

    var user = new ApplicationUser
    {
        UserName = dto.Email,
        Email = dto.Email,
        DisplayName = dto.DisplayName
    };

    var result = await userManager.CreateAsync(user, dto.Password);
    if (!result.Succeeded) return Results.BadRequest(result.Errors);

    var token = await tokenService.CreateTokenAsync(user);
    return Results.Ok(new { token });
})
.WithName("Register");

app.MapPost("/api/auth/login", async (LoginDto dto, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ITokenService tokenService) =>
{
    var user = await userManager.FindByEmailAsync(dto.Email);
    if (user == null) return Results.Unauthorized();

    var check = await signInManager.CheckPasswordSignInAsync(user, dto.Password, lockoutOnFailure: false);
    if (!check.Succeeded) return Results.Unauthorized();

    var token = await tokenService.CreateTokenAsync(user);
    return Results.Ok(new { token });
})
.WithName("Login");

app.MapGet("/api/auth/me", [Authorize] async (ClaimsPrincipal userPrincipal, UserManager<ApplicationUser> userManager) =>
{
    var id = userPrincipal.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
    if (string.IsNullOrEmpty(id)) return Results.Unauthorized();

    var user = await userManager.FindByIdAsync(id);
    if (user == null) return Results.NotFound();

    return Results.Ok(new { user.Id, user.Email, user.UserName, user.DisplayName });
})
.WithName("Me");

// Initiate Google OAuth2 login (redirects to Google)
app.MapGet("/api/auth/google-login", async (HttpContext httpContext) =>
{
    var redirectUri = httpContext.Request.Query["redirectUri"].ToString();
    if (string.IsNullOrEmpty(redirectUri))
        redirectUri = frontendPopupUrl;

    var props = new AuthenticationProperties
    {
        RedirectUri = $"/api/auth/google-callback?redirectUri={Uri.EscapeDataString(redirectUri)}"
    };

    await httpContext.ChallengeAsync("Google", props);
});



// Callback endpoint that Google will redirect to after authentication.
// This endpoint reads the external identity, creates or finds a local user, and returns a JWT.
app.MapGet("/api/auth/google-callback",
async (HttpContext httpContext, UserManager<ApplicationUser> userManager, ITokenService tokenService) =>
{
    var redirectUri = httpContext.Request.Query["redirectUri"].ToString();
    if (string.IsNullOrEmpty(redirectUri))
        redirectUri = frontendPopupUrl;

    var result = await httpContext.AuthenticateAsync("ExternalCookie");
    if (!result.Succeeded || result.Principal == null)
        return Results.Unauthorized();

    var email = result.Principal.FindFirst(ClaimTypes.Email)?.Value;

    var user = await userManager.FindByEmailAsync(email) ??
        new ApplicationUser { Email = email, UserName = email, EmailConfirmed = true };

    if (user == null)
    {
        user = new ApplicationUser
        {
            Email = email,
            UserName = email,
            DisplayName = result.Principal.FindFirst(ClaimTypes.Name)?.Value,
            EmailConfirmed = true
        };
        var createResult = await userManager.CreateAsync(user);
        if (!createResult.Succeeded)
            return Results.BadRequest(createResult.Errors);
    }

    // Clear the external cookie
    await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);

    // Issue JWT for the user
    var token = await tokenService.CreateTokenAsync(user);

    var finalUrl = $"{redirectUri}?token={WebUtility.UrlEncode(token)}";
    return Results.Redirect(finalUrl);
})
.WithName("GoogleCallback");


app.MapGet("/", () => "Auth API is running");

app.Run();
