using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using JwtWebAPI.Models;
using JwtWebAPI.Services;
using Microsoft.AspNetCore.Authorization;

namespace JwtWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var result = _authService.Register(request);
            return Ok(result);
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var token = _authService.Login(request);
            var refreshToken = _authService.GenerateRefreshToken();
            _authService.SetRefreshToken(refreshToken);
            return Ok(token);
        }
        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var token = _authService.RefreshToken();
            if (string.IsNullOrEmpty(token))
                return Unauthorized("Invalid Refresh Token");
            return Ok(token);
        }
    }
}
