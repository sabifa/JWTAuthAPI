using JWTAuthAPI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using JWTAuthAPI.Models.Authentication;
using JWTAuthAPI.Services.IdentityService;

namespace JWTAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        private readonly IIdentityService _identityService;

        public IdentityController(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(x => x.Errors.Select(xx => xx.ErrorMessage)));
            }

            var authResponse = await _identityService.RegisterAsync(request.Email, request.Password);

            if (!authResponse.Success)
            {
                return Unauthorized(authResponse.Errors);
            }

            return Ok(new AuthResponse
            {
                AccessToken = authResponse.AccessToken,
                RefreshToken = authResponse.RefreshToken
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
        {
            var authResponse = await _identityService.LoginAsync(request.Email, request.Password);

            if (!authResponse.Success)
            {
                return Unauthorized(authResponse.Errors);
            }

            return Ok(new AuthResponse
            {
                AccessToken = authResponse.AccessToken,
                RefreshToken = authResponse.RefreshToken
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
        {
            var refreshResponse = await _identityService.RefreshTokenAsync(request.AccessToken, request.RefreshToken);

            if (!refreshResponse.Success)
            {
                return Unauthorized(refreshResponse.Errors);
            }

            return Ok(new AuthResponse
            {
                AccessToken = refreshResponse.AccessToken,
                RefreshToken = refreshResponse.RefreshToken
            });
        }
    }
}
