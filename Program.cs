using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ValidateJwtToken;
using ValidateJwtToken.Model;

namespace ConsoleJwtValidation
{
    class Program
    {
        private static JwtTokenGenerate _jwtTokenGenerate;

        static void Main(string[] args)
        {
            var configuration = BuildConfiguration();
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<JwtTokenGenerate>(); // Use o tipo correto aqui

            _jwtTokenGenerate = new JwtTokenGenerate(logger, configuration);

            User user = new User
            {
                Id = Guid.NewGuid().ToString(),
                UserName = "Denis da Silva",
                Email = "denispapaap1232@gmail.com",
                User_type = "Admin"
            };


            var token = _jwtTokenGenerate.CreateToken(user).Token;

            var key = configuration["Jwt:Key"];
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = configuration["Jwt:Issuer"],
                ValidAudience = configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
            };

            if (ValidateToken(token, tokenValidationParameters))
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtSecurityToken = handler.ReadJwtToken(token);
                var claims = jwtSecurityToken.Claims.ToList();

                var TokenInfo = new Dictionary<string, string>();
                foreach (var claim in claims)
                {
                    TokenInfo[claim.Type] = claim.Value;
                }

                TokenInfo.TryGetValue(ClaimTypes.Name, out string perfilNome);
                TokenInfo.TryGetValue(ClaimTypes.Email, out string login);
                TokenInfo.TryGetValue(ClaimTypes.Role, out string usuarioNome);
                Console.WriteLine("Perfil Nome: " + perfilNome);
                Console.WriteLine("Login: " + login);
                Console.WriteLine("Usuário Nome: " + usuarioNome);
            }
            else
            {
                Console.WriteLine("Token inválido.");
            }
            Console.ReadLine();
        }

        private static IConfiguration BuildConfiguration()
        {
            var configurationBuilder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

            return configurationBuilder.Build();
        }

        private static bool ValidateToken(string token, TokenValidationParameters tvp)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                SecurityToken securityToken;
                ClaimsPrincipal principal = handler.ValidateToken(token, tvp, out securityToken);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro na validação do token: " + ex.Message);
                return false;
            }
        }
    }
}
