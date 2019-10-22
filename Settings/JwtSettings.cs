namespace JWTAuthAPI.Settings
{
    public class JwtSettings
    {
        public string Secret { get; set; }

        public double AccessTokenLifetimeMinutes { get; set; }

        public double RefreshTokenLifetimeDays { get; set; }
    }
}
