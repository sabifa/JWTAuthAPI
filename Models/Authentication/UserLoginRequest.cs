namespace JWTAuthAPI.Models.Authentication
{
    public class UserLoginRequest
    {
        public string Email { get; set; }

        public string Password { get; set; }
    }
}
