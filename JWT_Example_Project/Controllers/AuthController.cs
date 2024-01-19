using JWT_Example_Project.Settings;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Example_Project.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtSettings _jwtSettings;

        public AuthController(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }


        [HttpGet]
        public string Get(string userName, string password)
        {
            var myClaims = new[]
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(JwtRegisteredClaimNames.Email, userName)
            };

            

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SigninKey));
            var credential = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer : _jwtSettings.Issuer,
                audience : _jwtSettings.Audience,
                claims  :  myClaims,
                expires : DateTime.Now.AddDays(1),
                notBefore : DateTime.Now,
                signingCredentials : credential
                );

            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            
            return token;
        }

        [HttpGet("ValidateToken")]
        public bool ValidateToken(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SigninKey));
            try
            {
                JwtSecurityTokenHandler handler = new();
                handler.ValidateToken(token, new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidIssuer = "https://www.zekeriyasarica.com.tr/"
                }, out SecurityToken validatedToken);
                

                var jwtToken = (JwtSecurityToken)validatedToken;
                var claims =  jwtToken.Claims.ToList();
                return true;
            }
            catch (Exception)
            {

                return false;
            }

            
        }
    }
}
