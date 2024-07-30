# Projeto: Validação e Geração de Tokens JWT
## Este projeto é uma aplicação de console que demonstra como gerar e validar tokens JWT (JSON Web Token) utilizando o .NET. O código inclui a geração de tokens e a validação desses tokens, utilizando a biblioteca System.IdentityModel.Tokens.Jwt para manipular tokens JWT.

## Estrutura do Projeto
- O projeto é dividido em três principais namespaces:
    - *ValidateJwtToken.Dto*: Contém classes de Data Transfer Object (DTO) usadas para transportar dados de tokens.
    - *ConsoleJwtValidation*: Contém a aplicação de console principal que demonstra a geração e validação de tokens JWT.
    - *ValidateJwtToken*: Contém a lógica para gerar tokens JWT, incluindo a criação de claims e assinatura do token.
    ### Arquivos:
    - *Program.cs*: Contém a lógica principal do console application.
    - *JwtTokenGenerate.cs*: Contém a classe responsável pela geração de tokens JWT.
    - *TokenDto.cs*: Contém a definição da classe TokenDto usada para retornar o token gerado.
    ### Configuração:
    - O projeto usa um arquivo appsettings.json para armazenar configurações de JWT:

-       **json**
        {
            "Logging": {
                "LogLevel": {
                    "Default": "Information",
                    "Microsoft.AspNetCore": "Warning"
                    }
                },
                "Jwt": {
                    "Key": "chave privada",
                    "Issuer": "www.consoleapp.com/321",
                    "Audience": "www.consoleapp.com/431"
                },
                "AllowedHosts": "*"
        }
    ### Dependências
    - O projeto utiliza os seguintes pacotes NuGet:

        *1*.Microsoft.Extensions.Configuration
        *2*.Microsoft.Extensions.Logging
        *3*.Microsoft.IdentityModel.Tokens
        *4*.System.IdentityModel.Tokens.Jwt
        - Uso
            - Geração de Token
                A classe JwtTokenGenerate é responsável pela geração do token JWT. O método CreateToken(User user) recebe um objeto User e gera um token JWT baseado nas informações fornecidas.

-       public TokenDto CreateToken(User user)
        {
            // Lógica para gerar token JWT
        }

### Validação de Token
- O método ValidateToken(string token, TokenValidationParameters tvp) valida o token JWT utilizando os parâmetros de validação configurados.

**Exemplo de Uso**
### Configuração do Logger e da Instância de JwtTokenGenerate:

    var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
    var logger = loggerFactory.CreateLogger<JwtTokenGenerate>();
    _jwtTokenGenerate = new JwtTokenGenerate(logger, configuration);

### Geração e Validação do Token:
    var token = _jwtTokenGenerate.CreateToken(user).Token;
    if (ValidateToken(token, tokenValidationParameters))
    {
        // Processar informações do token
    }
    else
    {
        Console.WriteLine("Token inválido.");
    }

**Exemplo de Implementação**
-       *Classe TokenDto*
        namespace ValidateJwtToken.Dto
            {
            public class TokenDto
            {
                public string Token { get; set; }
            }
        }

*Classe JwtTokenGenerate*
-       namespace ValidateJwtToken
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
                    // Lógica para gerar token JWT
                }

                private JwtSecurityToken CreateJwtToken(List<Claim> claims, SigningCredentials credentials, DateTime expiration)
                {
                    // Lógica para criar o token JWT
                }

                private List<Claim> CreateClaims(User user)
                {
                    // Lógica para criar claims
                }

                private SigningCredentials CreateSigningCredentials()
                {
                    // Lógica para criar credenciais de assinatura
                }
            }
        }
*Classe Program*

-       namespace ConsoleJwtValidation
        {
            class Program
            {
                private static JwtTokenGenerate _jwtTokenGenerate;

                static void Main(string[] args)
                {
                    // Lógica principal do console application
                }

                private static IConfiguration BuildConfiguration()
                {
                    // Lógica para construir a configuração
                }

                private static bool ValidateToken(string token, TokenValidationParameters tvp)
                {
                    // Lógica para validar o token JWT
                }
            }
        }
