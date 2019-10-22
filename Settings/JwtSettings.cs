namespace JWTAuthAPI.Settings
{
    public class JwtSettings
    {
        public string Secret { get; set; }

        public double AccessTokenLifetime { get; set; }

        public double RefreshTokenLifetime { get; set; }
    }
}
