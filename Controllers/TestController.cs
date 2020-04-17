using JWTAuthAPI.Models.ApplicationRole;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new { value = "API started" });
        }

        [HttpGet("admin")]
        [Authorize(Roles = ApplicationRole.Admin)]
        public IActionResult GetOnlyForAdmins()
        {
            return Ok(new { value = "API started, my Admin" });
        }
    }
}
