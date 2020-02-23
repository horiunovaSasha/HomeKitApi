using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using HomeKitApi.Helpers;
using HomeKitApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace HomeKitApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost]
        [Route("token")]
        public IActionResult Token([FromBody] AuthenticateModel model)
        {
            var identity = GetIdentity(model.Username, model.Password);
            if (identity == null)
            {
                return BadRequest(new { errorText = "Invalid username or password." });
            }

            var jwt = GetJwtToken(identity.Claims);
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                access_token = encodedJwt,
                username = identity.Name,
                message = "Login success!"
            };

            return Ok(response);
        }

        private ClaimsIdentity GetIdentity(string username, string password)
        {
            var person = _userManager.FindByNameAsync(username).Result;
            if (person != null)
            {
                var claim = new Claim(ClaimTypes.Name, person.UserName);
                var claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, person.UserName),
                    new Claim(ClaimTypes.Hash, username.GetHashCode().ToString()),
                };
                var claimsIdentity =
                    new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType);
                return claimsIdentity;
            }

            return null;
        }
        [Route("register")]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] AuthenticateModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new IdentityUser { UserName = model.Username };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, false);

                    var identity = GetIdentity(model.Username, model.Password);
                    var jwt = GetJwtToken(identity.Claims);
                    var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                    var response = new
                    {
                        access_token = encodedJwt,
                        username = identity.Name,
                        message = "Registration and login success!"
                    };
                    return Ok(response);
                }
                else
                {
                    return BadRequest(new
                    {
                        errorText = "Registration failed",
                        errors = result.Errors
                    });
                }
            }
            return BadRequest(new { errorText = "Registration failed" });
        }

        public JwtSecurityToken GetJwtToken(IEnumerable<Claim> claims)
        {
            return new JwtSecurityToken(
                issuer: AuthOptions.ISSUER,
                audience: AuthOptions.AUDIENCE,
                notBefore: DateTime.UtcNow,
                claims: claims,
                expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
        }
        [HttpGet]
        [Route("test")]
        public List<string> Test()
        {
            return new List<string>() { "Plak - plak" };
        }
    }
}