using System.ComponentModel.DataAnnotations;

namespace JWTAuthAPI.Models
{
    public class UserRegistrationRequest
    {
        [EmailAddress]
        public string Email { get; set; }

        public string Password { get; set; }
    }
}
