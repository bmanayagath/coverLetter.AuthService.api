using Microsoft.AspNetCore.Identity;

namespace coverLetter.AuthService.api.Models;

public class ApplicationUser : IdentityUser
{
    // Add custom properties if needed
    public string? DisplayName { get; set; }
}