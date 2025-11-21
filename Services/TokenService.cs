using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using coverLetter.AuthService.api.Models;

namespace coverLetter.AuthService.api.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _config;
    private readonly UserManager<ApplicationUser> _userManager;

    public TokenService(IConfiguration config, UserManager<ApplicationUser> userManager)
    {
        _config = config;
        _userManager = userManager;
    }

    public async Task<string> CreateTokenAsync(ApplicationUser user, IList<string>? roles = null)
    {
        var key = Environment.GetEnvironmentVariable("JWT_KEY") ?? _config["Jwt:Key"];
        if (string.IsNullOrEmpty(key)) throw new Exception("JWT key not configured");

        var claims = new List<Claim>
        {
            // IdentityUser.Id is used as the primary subject (usually a GUID string)
            new Claim(JwtRegisteredClaimNames.Sub, user.Id ?? ""),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? "")
        };

        // Add explicit GUID claim based on ASP.NET Identity Id
        if (!string.IsNullOrEmpty(user.Id))
        {
            if (Guid.TryParse(user.Id, out var parsedGuid))
                claims.Add(new Claim("user_guid", parsedGuid.ToString()));
            else
                claims.Add(new Claim("user_guid", user.Id));
        }

        roles ??= await _userManager.GetRolesAsync(user);
        foreach (var r in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, r));
        }

        var creds = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(12),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}