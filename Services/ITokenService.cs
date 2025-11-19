using coverLetter.AuthService.api.Models;

namespace coverLetter.AuthService.api.Services;

public interface ITokenService
{
    Task<string> CreateTokenAsync(ApplicationUser user, IList<string>? roles = null);
}