using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JWTAuthAPI.Models.Authentication;
using Microsoft.AspNetCore.Identity;

namespace JWTAuthAPI.Services.TokenService
{
    public interface ITokenService
    {       
        Task<AuthenticationResult> GenerateTokenAndAuthenticationResultForUser(IdentityUser user);

        ClaimsPrincipal GetPrincipalFromAccessToken(string token);
    }
}
