using JwtWebAPI.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web.Http;

namespace JwtWebAPI.Services
{
    public class AuthService : IAuthService
    {
        private static User user = new();
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _contextAccessor;
        public AuthService(IConfiguration configuration, IHttpContextAccessor contextAccessor)
        {
            _configuration = configuration;
            _contextAccessor = contextAccessor;
        }
        public User Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            return user;
        }
        public string Login(UserDto request)
        {
            if (user.UserName != request.UserName)
                return "User not found";
            if (!VerifyPasswordHash(request.Password, user.PasswordHash))
                return "Wrong password";
            string token = CreateToken(user);
            return token;
        }
        public RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };
            return refreshToken;
        }
        public string? RefreshToken()
        {
            var refreshToken = _contextAccessor.HttpContext?.Request.Cookies["refreshToken"];
            if (!user.RefreshToken.Equals(refreshToken) || user.TokenExpires < DateTime.Now)
            {
                return null;
            }
            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);
            return token;
        }
        public void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            _contextAccessor.HttpContext?.Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
        private bool VerifyPasswordHash(string password, byte[] passwordHash)
        {
            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual(passwordHash);
            }
        }
    }
}
