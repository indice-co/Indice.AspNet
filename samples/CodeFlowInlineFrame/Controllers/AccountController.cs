﻿using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CodeFlowInlineFrame.Configuration;
using CodeFlowInlineFrame.Models;
using CodeFlowInlineFrame.Settings;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace CodeFlowInlineFrame.Controllers;

[Route("account")]
public class AccountController : Controller
{
    private readonly ClientSettings _clientSettings;
    private readonly GeneralSettings _generalSettings;
    private readonly IHttpClientFactory _httpClientFactory;
    public const string Name = "Account";

    public AccountController(IOptions<ClientSettings> clientSettings, IOptions<GeneralSettings> generalSettings, IHttpClientFactory httpClientFactory) {
        _clientSettings = clientSettings?.Value ?? throw new ArgumentNullException(nameof(clientSettings));
        _generalSettings = generalSettings?.Value ?? throw new ArgumentNullException(nameof(generalSettings));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    }

    [HttpGet("login")]
    public ViewResult Login([FromQuery]string returnUrl) {
        var authorizeEndpoint = $"{_generalSettings.Authority}/connect/authorize";
        var requestUrl = new RequestUrl(authorizeEndpoint);
        var codeVerifier = CryptoRandom.CreateUniqueId(32);
        if (TempData.ContainsKey(OidcConstants.TokenRequest.CodeVerifier)) {
            TempData.Remove(OidcConstants.TokenRequest.CodeVerifier);
        }
        TempData.Add(OidcConstants.TokenRequest.CodeVerifier, codeVerifier);
        string codeChallenge;
        using (var sha256 = SHA256.Create()) {
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            codeChallenge = Base64Url.Encode(challengeBytes);
        }
        var authorizeUrl = requestUrl.CreateAuthorizeUrl(
            clientId: _clientSettings.Id,
            responseType: OidcConstants.ResponseTypes.CodeIdToken,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256,
            codeChallenge: codeChallenge,
            responseMode: OidcConstants.ResponseModes.FormPost,
            redirectUri: $"{_generalSettings.Host}/account/auth-callback",
            nonce: Guid.NewGuid().ToString(),
            scope: string.Join(" ", _clientSettings.Scopes),
            state: !string.IsNullOrEmpty(returnUrl) ? Convert.ToBase64String(Encoding.UTF8.GetBytes(returnUrl)) : null
        );
        return View(new LoginViewModel {
            AuthorizeUrl = authorizeUrl
        });
    }

    [HttpPost("auth-callback")]
    public async Task<ViewResult> AuthCallback() {
        var authorizationResponse = new AuthorizationResponse();
        authorizationResponse.PopulateFrom(HttpContext.Request.Form);
        if (string.IsNullOrEmpty(authorizationResponse.Code)) {
            throw new Exception("Authorization code is not present in the response.");
        }
        var tokenEndpoint = $"{_generalSettings.Authority}/connect/token";
        TempData.TryGetValue(OidcConstants.TokenRequest.CodeVerifier, out var codeVerifier);
        var httpClient = _httpClientFactory.CreateClient(HttpClientNames.IdentityServer);
        var tokenResponse = await httpClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest {
            Address = tokenEndpoint,
            ClientId = _clientSettings.Id,
            Code = authorizationResponse.Code,
            RedirectUri = $"{_generalSettings.Host}/account/auth-callback",
            CodeVerifier = codeVerifier?.ToString()
        });
        if (tokenResponse.IsError) {
            throw new Exception("There was an error retrieving the access token.", tokenResponse.Exception);
        }
        var userInfoResponse = await httpClient.GetUserInfoAsync(new UserInfoRequest {
            Address = $"{_generalSettings.Authority}/connect/userinfo",
            Token = tokenResponse.AccessToken
        });
        if (userInfoResponse.IsError) {
            throw new Exception("There was an error retrieving user information from authority.", userInfoResponse.Exception);
        }
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(userInfoResponse.Claims, "Cookies", JwtClaimTypes.Name, JwtClaimTypes.Role));
        var authenticationProperties = new AuthenticationProperties();
        authenticationProperties.StoreTokens(new List<AuthenticationToken> {
            new AuthenticationToken {
                Name = OidcConstants.TokenTypes.AccessToken,
                Value = tokenResponse.AccessToken
            },
            new AuthenticationToken {
                Name = OidcConstants.TokenTypes.RefreshToken,
                Value = tokenResponse.RefreshToken
            },
            new AuthenticationToken {
                Name = OidcConstants.TokenTypes.IdentityToken,
                Value = tokenResponse.IdentityToken
            },
            new AuthenticationToken {
                Name = "expires_at",
                Value = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn).ToString("o", CultureInfo.InvariantCulture)
            }
        });
        await HttpContext.SignInAsync(Startup.CookieScheme, claimsPrincipal, authenticationProperties);
        var returnUrl = "/";
        if (!string.IsNullOrEmpty(authorizationResponse.State)) {
            returnUrl = Encoding.UTF8.GetString(Convert.FromBase64String(authorizationResponse.State));
        }
        return View("Redirect", new RedirectViewModel {
            Url = returnUrl
        });
    }

    [HttpGet("access-denied")]
    public ViewResult AccessDenied() {
        return View();
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout() {
        await HttpContext.SignOutAsync(Startup.CookieScheme);
        var endsessionEndpoint = $"{_generalSettings.Authority}/connect/endsession";
        var requestUrl = new RequestUrl(endsessionEndpoint);
        var idToken = await HttpContext.GetTokenAsync(OidcConstants.ResponseTypes.IdToken);
        var endSessionUrl = requestUrl.CreateEndSessionUrl(
            idTokenHint: idToken,
            postLogoutRedirectUri: $"{_generalSettings.Host}{Url.Action(nameof(LoggedOut), Name)}"
        );
        return View(new LogoutViewModel {
            Url = endSessionUrl
        });
    }

    [HttpGet("logged-out")]
    public ViewResult LoggedOut() {
        return View("Redirect", new RedirectViewModel { 
            Url = _generalSettings.Host
        });
    }
}
