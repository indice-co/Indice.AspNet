using IdentityModel;
using IdentityServer4;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Indice.AspNetCore.Filters;
using Indice.Features.Identity.Core;
using Indice.Features.Identity.Core.Data.Models;
using Indice.Features.Identity.UI.Models;
using Indice.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Indice.Features.Identity.UI.Pages;

/// <summary>Page model for the registration screen.</summary>
[AllowAnonymous]
[IdentityUI(typeof(RegisterModel))]
[SecurityHeaders]
[ValidateAntiForgeryToken]
public abstract class BaseRegisterModel : BasePageModel
{
    private readonly ExtendedUserManager<User> _userManager;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IClientStore _clientStore;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly ILogger<BaseRegisterModel> _logger;
    private readonly IdentityUIOptions _options;

    /// <summary></summary>
    /// <param name="userManager">Provides the APIs for managing users and their related data in a persistence store.</param>
    /// <param name="schemeProvider">Responsible for managing what authentication schemes are supported.</param>
    /// <param name="clientStore">Retrieval of client configuration.</param>
    /// <param name="interaction">Provide services be used by the user interface to communicate with IdentityServer.</param>
    /// <param name="logger">A generic interface for logging.</param>
    /// <param name="options">UI options</param>
    /// <exception cref="ArgumentNullException"></exception>
    public BaseRegisterModel(
        ExtendedUserManager<User> userManager,
        IAuthenticationSchemeProvider schemeProvider,
        IClientStore clientStore,
        IIdentityServerInteractionService interaction,
        ILogger<BaseRegisterModel> logger,
        IOptions<IdentityUIOptions> options
    ) {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _schemeProvider = schemeProvider ?? throw new ArgumentNullException(nameof(schemeProvider));
        _clientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
        _interaction = interaction ?? throw new ArgumentNullException(nameof(interaction));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? new IdentityUIOptions();
    }

    /// <summary>The view model for registration page.</summary>
    public RegisterViewModel View { get; set; } = new RegisterViewModel();

    /// <summary>Registration input model data.</summary>
    [BindProperty]
    public RegisterInputModel Input { get; set; } = new RegisterInputModel();

    /// <summary>Registration page GET handler.</summary>
    /// <param name="returnUrl">The return URL.</param>
    public virtual async Task<IActionResult> OnGetAsync(string? returnUrl = null) {
        if (!_options.EnableRegisterPage) {
            return Redirect("/404");
        }
        View = await BuildRegisterViewModelAsync(returnUrl);
        if (View.IsExternalRegistrationOnly) {
            return RedirectToPage("External", new {
                provider = View.ExternalRegistrationScheme,
                returnUrl
            });
        }
        return Page();
    }

    /// <summary>Registration page POST handler.</summary>
    public virtual async Task<IActionResult> OnPostAsync() {
        if (!_options.EnableRegisterPage) {
            return Redirect("/404");
        }
        if (!ModelState.IsValid) {
            return Page();
        }
        var user = CreateUserFromInput(Input);
        var result = await _userManager.CreateAsync(user, Input.Password ?? throw new InvalidOperationException("User password cannot be null."));
        if (!result.Succeeded) {
            View = await BuildRegisterViewModelAsync(Input.ReturnUrl);
            AddModelErrors(result);
            return Page();
        }
        await SendConfirmationEmail(user, Input.ReturnUrl);
        _logger.LogInformation(3, "User created a new account with password.");
        if (_interaction.IsValidReturnUrl(Input.ReturnUrl) || Url.IsLocalUrl(Input.ReturnUrl)) {
            return RedirectToPage("Login", new { returnUrl = Input.ReturnUrl });
        }
        return RedirectToPage("Login");
    }

    private async Task<RegisterViewModel> BuildRegisterViewModelAsync(string? returnUrl) {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP is not null && await _schemeProvider.GetSchemeAsync(context.IdP) is not null) {
            var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;
            // This is meant to short circuit the UI and only trigger the one external IdP.
            var viewModel = new RegisterViewModel {
                ReturnUrl = returnUrl,
                UserName = context.LoginHint,
            };
            if (!local) {
                viewModel.ExternalProviders = new[] {
                    new ExternalProviderModel {
                        AuthenticationScheme = context.IdP
                    }
                };
            }
            return viewModel;
        }
        var schemes = await _schemeProvider.GetAllSchemesAsync();
        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProviderModel {
                DisplayName = x.DisplayName ?? x.Name,
                AuthenticationScheme = x.Name
            })
            .ToList();
        var allowLocal = AccountOptions.AllowLocalLogin;
        if (context?.Client.ClientId is not null) {
            var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
            if (client is not null) {
                allowLocal = client.EnableLocalLogin;
                if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any()) {
                    providers = providers.Where(provider => !client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                }
            }
        }
        return new RegisterViewModel {
            ReturnUrl = returnUrl,
            UserName = context?.LoginHint ?? string.Empty,
            ExternalProviders = providers.ToArray(),
            ClientId = context?.Client?.ClientId
        };
    }

    private User CreateUserFromInput(RegisterInputModel input) {
        var user = new User {
            UserName = input.UserName,
            Email = input.Email,
            PhoneNumber = input.PhoneNumber
        };
        if (!string.IsNullOrWhiteSpace(input.FirstName)) {
            user.Claims.Add(new() {
                ClaimType = JwtClaimTypes.GivenName,
                ClaimValue = input.FirstName,
                UserId = user.Id
            });
        }
        if (!string.IsNullOrWhiteSpace(input.LastName)) {
            user.Claims.Add(new() {
                ClaimType = JwtClaimTypes.FamilyName,
                ClaimValue = input.LastName,
                UserId = user.Id
            });
        }
        user.Claims.Add(new() {
            ClaimType = BasicClaimTypes.ConsentCommencial,
            ClaimValue = input.HasAcceptedTerms ? bool.TrueString.ToLower() : bool.FalseString.ToLower(),
            UserId = user.Id
        });
        user.Claims.Add(new() {
            ClaimType = BasicClaimTypes.ConsentTerms,
            ClaimValue = input.HasReadPrivacyPolicy ? bool.TrueString.ToLower() : bool.FalseString.ToLower(),
            UserId = user.Id
        });
        user.Claims.Add(new() {
            ClaimType = BasicClaimTypes.ConsentTermsDate,
            ClaimValue = $"{DateTime.UtcNow:O}",
            UserId = user.Id
        });
        user.Claims.Add(new() {
            ClaimType = BasicClaimTypes.ConsentCommencialDate,
            ClaimValue = $"{DateTime.UtcNow:O}",
            UserId = user.Id
        });
        foreach (var attribute in Input.Claims) {
            if (string.IsNullOrWhiteSpace(attribute.Value)) {
                continue;
            }
            user.Claims.Add(new() {
                ClaimType = attribute.Name,
                ClaimValue = attribute.Value,
                UserId = user.Id
            });
        }
        return user;
    }
}

internal class RegisterModel : BaseRegisterModel
{
    public RegisterModel(
        ExtendedUserManager<User> userManager,
        IAuthenticationSchemeProvider schemeProvider,
        IClientStore clientStore,
        IIdentityServerInteractionService interaction,
        ILogger<RegisterModel> logger,
        IOptions<IdentityUIOptions> options
    ) : base(userManager, schemeProvider, clientStore, interaction, logger, options) { }
}
