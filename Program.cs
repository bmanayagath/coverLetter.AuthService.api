using coverLetter.AuthService.api.Data;
using coverLetter.AuthService.api.DTOs;
using coverLetter.AuthService.api.Models;
using coverLetter.AuthService.api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Collections;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidateLifetime = true
    };
});

builder.Services.AddAuthorization();
builder.Services.AddScoped<ITokenService, TokenService>();

var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

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

app.Run();
