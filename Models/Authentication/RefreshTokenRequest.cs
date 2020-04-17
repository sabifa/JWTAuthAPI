using System.ComponentModel.DataAnnotations;

namespace JWTAuthAPI.Models.Authentication
{
    public class RefreshTokenRequest
    {
        [Required]
        public string AccessToken { get; set; }

        [Required]
        public string RefreshToken { get; set; }
    }
}
