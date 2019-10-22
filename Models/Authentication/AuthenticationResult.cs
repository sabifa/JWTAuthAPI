using System.Collections.Generic;

namespace JWTAuthAPI.Models.Authentication
{
    public class AuthenticationResult
    {
        public string AccessToken { get; set; }

        public string RefreshToken { get; set; }

        public bool Success { get; set; }

        public IEnumerable<string> Errors { get; set; }
    }
}
