﻿using System.Threading.Tasks;
using JWTAuthAPI.Models.Authentication;

namespace JWTAuthAPI.Services
{
    public interface IIdentityService
    {
        Task<AuthenticationResult> RegisterAsync(string email, string password);
        Task<AuthenticationResult> LoginAsync(string email, string password);
        Task<AuthenticationResult> RefreshTokenAsync(string acessToken, string requestRefreshToken);
    }
}
