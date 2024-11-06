using Microsoft.AspNetCore.Mvc;
using Saml;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

[Route("auth")]
public class AuthController : Controller
{
    private readonly string _jwtKey = "YourSecretKeyForJWT";
    private readonly string _jwtIssuer = "https://4c53-112-134-222-74.ngrok-free.app";

    [HttpGet("login")]
    public IActionResult Login()
    {
        var samlRequest = new AuthRequest(
            "https://4c53-112-134-222-74.ngrok-free.app", // Service Provider Entity ID
            "https://4c53-112-134-222-74.ngrok-free.app/auth/assertionConsumerService" // Assertion Consumer Service URL
        );

        string redirectUrl = samlRequest.GetRedirectUrl(SamlConfig.IdpSsoTargetUrl);
        return Redirect(redirectUrl);
    }

    [HttpGet("assertionConsumerService")]
    public async Task<IActionResult> AssertionConsumerService()
    {
        var samlResponse = new Response(SamlConfig.Certificate, Request.Form["SAMLResponse"]);

        if (samlResponse.IsValid())
        {
            var userId = samlResponse.GetNameID();
            var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, userId) };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties();

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties
            );

            var token = JwtTokenGenerator.GenerateToken(userId, _jwtKey, _jwtIssuer);
            return Ok(new { token });
        }

        return Unauthorized();
    }

    [HttpGet("check-session")]
    public IActionResult CheckSession()
    {
        if (User.Identity.IsAuthenticated)
        {
            return Ok(new { message = "User is authenticated" });
        }
        return Unauthorized(new { message = "User is not authenticated" });
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }
}
