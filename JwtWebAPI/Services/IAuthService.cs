using JwtWebAPI.Models;

namespace JwtWebAPI.Services
{
    public interface IAuthService
    {
        User Register(UserDto request);
        string Login(UserDto request);
        RefreshToken GenerateRefreshToken();
        void SetRefreshToken(RefreshToken newRefreshToken);
        string? RefreshToken();
    }
}
