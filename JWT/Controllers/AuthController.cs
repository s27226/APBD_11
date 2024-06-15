using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using WebApp.Services;

/*
 * TODO w pracy domowej
 * Koncowki do logowania, rejestracji oraz refreshowania sesji umiescic w kontrolerze AuthController
 * 
 * 1. Logowanie api/auth/login
 * Input: username (email), password
 * - Sprawdzenie poprawnosci danych uzytkownika
 * - if(true) => generujemy token z krotkim czasem zycia + refresh token z dlugim czasem zycia => 200
 * - if(false) => 401 niepoprny login lub haslo
 * Output: tokeny
 *
 * 2. Refreshowanie sesji api/auth/refresh
 * Input: refresh token
 * - Sprawdzenie czy refresh token czy jest poprawny
 * - if(true) -> generujemy token z krotkim czasem zycia + refresh token z dlugim czasem zycia => 200
 * - if(false) => 401 Invalid token
 * Output: tokeny
 *
 * 3. Rejestacja uzytkownika api/auth/register
 * - Input: username, password
 * - Sprawdzamy czy nazwa uzytkownika jest unikalna
 * - Walidujemy zapytanie
 * - Hashujemy haslo
 * - Tworzymy nowy rekord dla uzytkownika w bazie ktory bedzie zawieral jego username oraz hash ktory wygenerowalismy w ramach hasla
 *
 * 4. Zabezpiecznie jednej koncowki
 */

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IDatabaseService _dbService;
        private readonly IConfiguration _config;
        public AuthController(IDatabaseService dbService, IConfiguration config)
        {
            _dbService = dbService;
            _config = config;

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequestModel model) 
        {
            var passwordHasher = new PasswordHasher<User>();
            var hash = await _dbService.GetUserHash(model.UserName);
            if(!(!await _dbService.IsUnique(model.UserName) && passwordHasher.VerifyHashedPassword(new User(), hash, model.Password) == PasswordVerificationResult.Success))
            {
                return Unauthorized("Wrong username or password");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescription = new SecurityTokenDescriptor
            {
                Issuer = _config["JWT:Issuer"],
                Audience = _config["JWT:Audience"],
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]!)),
                        SecurityAlgorithms.HmacSha256
                )
            };
            var token = tokenHandler.CreateToken(tokenDescription);
            var stringToken = tokenHandler.WriteToken(token);

            var refTokenDescription = new SecurityTokenDescriptor
            {
                Issuer = _config["JWT:RefIssuer"],
                Audience = _config["JWT:RefAudience"],
                Expires = DateTime.UtcNow.AddDays(3),
                SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:RefKey"]!)),
                        SecurityAlgorithms.HmacSha256
                )
            };
            var refToken = tokenHandler.CreateToken(refTokenDescription);
            var stringRefToken = tokenHandler.WriteToken(refToken);
            
            return Ok(new LoginResponseModel
            {
                Token = stringToken,
                RefreshToken = stringRefToken
            });
        }

        [HttpPost("refresh")]
        public IActionResult RefreshToken(RefreshTokenRequestModel requestModel)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(requestModel.RefreshToken, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _config["JWT:RefIssuer"],
                    ValidAudience = _config["JWT:RefAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:RefKey"]!))
                }, out SecurityToken validatedToken);
            }
            catch
            {
                return Unauthorized("Invalid token");
            }

            var tokenDescription = new SecurityTokenDescriptor
            {
                Issuer = _config["JWT:Issuer"],
                Audience = _config["JWT:Audience"],
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]!)),
                        SecurityAlgorithms.HmacSha256
                )
            };
            var token = tokenHandler.CreateToken(tokenDescription);
            var stringToken = tokenHandler.WriteToken(token);

            var refTokenDescription = new SecurityTokenDescriptor
            {
                Issuer = _config["JWT:RefIssuer"],
                Audience = _config["JWT:RefAudience"],
                Expires = DateTime.UtcNow.AddDays(3),
                SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:RefKey"]!)),
                        SecurityAlgorithms.HmacSha256
                )
            };
            var refToken = tokenHandler.CreateToken(refTokenDescription);
            var stringRefToken = tokenHandler.WriteToken(refToken);
            
            return Ok(new LoginResponseModel
            {
                Token = stringToken,
                RefreshToken = stringRefToken
            });

        }

        //Generated password does not work with /verify-password endpoint!
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(LoginRequestModel login)
        {
            if(!await _dbService.IsUnique(login.UserName))
            {
                return BadRequest("Username already exists");
            }

            var passwordHasher = new PasswordHasher<User>();
            await _dbService.InsertNewUser(new Controllers.User
            {
                Name = login.UserName,
                Password = passwordHasher.HashPassword(new User(), login.Password)
            });

            return Ok();
        }
    }

    public class RefreshTokenRequestModel
    {
        public string RefreshToken { get; set; } = null!;
    }

    public class VerifyPasswordRequestModel
    {
        public string Password { get; set; } = null!;
        public string Hash { get; set; } = null!;
    }
    
    public class LoginRequestModel
    {
        [Required]
        public string UserName { get; set; } = null!;
        [Required]
        public string Password { get; set; } = null!;
    }

    public class LoginResponseModel
    {
        public string Token { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
    }

    public class User
    {
        public string Name { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}
