using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ValidateJwtToken.Dto;
using ValidateJwtToken.Model;

namespace ValidateJwtToken
{
    public class JwtTokenGenerate
    {
        private const int ExpirationMinutes = 30;
        private readonly ILogger<JwtTokenGenerate> _logger;
        private readonly IConfiguration _configuration;

        public JwtTokenGenerate(ILogger<JwtTokenGenerate> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public TokenDto CreateToken(User user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var expiration = DateTime.UtcNow.AddMinutes(ExpirationMinutes);
            var token = CreateJwtToken(
                CreateClaims(user),
                CreateSigningCredentials(),
                expiration
            );
            _logger.LogInformation("JWT Token created");

            TokenDto tokenGenerate = new TokenDto
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token)
            };
            Console.WriteLine("Token: " + tokenGenerate.Token);
            return tokenGenerate;
        }

        private JwtSecurityToken CreateJwtToken(List<Claim> claims, SigningCredentials credentials, DateTime expiration) =>
            new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: expiration,
                signingCredentials: credentials
            );

        private List<Claim> CreateClaims(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id ?? throw new ArgumentNullException(nameof(user.Id))),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id ?? throw new ArgumentNullException(nameof(user.Id))),
                new Claim(ClaimTypes.Name, user.UserName ?? throw new ArgumentNullException(nameof(user.UserName))),
                new Claim(ClaimTypes.Email, user.Email ?? throw new ArgumentNullException(nameof(user.Email))),
                new Claim(ClaimTypes.Role, user.User_type ?? throw new ArgumentNullException(nameof(user.User_type)))
            };

            return claims;
        }

        private SigningCredentials CreateSigningCredentials()
        {
            var key = _configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(key))
            {
                throw new InvalidOperationException("Chave simétrica não encontrada nas configurações.");
            }

            return new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                SecurityAlgorithms.HmacSha256
            );
        }
    }
}
