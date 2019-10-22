using System.ComponentModel.DataAnnotations;

namespace JWTAuthAPI.Models.Authentication
{
    public class UserRegistrationRequest
    {
        [EmailAddress]
        public string Email { get; set; }

        public string Password { get; set; }
    }
}
