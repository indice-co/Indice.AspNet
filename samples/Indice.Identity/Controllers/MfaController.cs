﻿using IdentityServer4.Services;
using Indice.AspNetCore.Filters;
using Indice.AspNetCore.Identity;
using Indice.AspNetCore.Identity.Models;
using Indice.Features.Identity.Core;
using Indice.Features.Identity.Core.Data.Models;
using Indice.Features.Identity.Core.Totp;
using Indice.Identity.Hubs;
using Indice.Identity.Models;
using Indice.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Localization;

namespace Indice.Identity.Controllers;

[ApiExplorerSettings(IgnoreApi = true)]
[SecurityHeaders]
public class MfaController : Controller
{
    private readonly IAccountService _accountService;
    private readonly TotpServiceFactory _totpServiceFactory;
    private readonly ExtendedUserManager<DbUser> _userManager;
    private readonly IStringLocalizer<MfaController> _localizer;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly ExtendedSignInManager<DbUser> _signInManager;
    private readonly ILogger<MfaController> _logger;
    private readonly IHubContext<MultiFactorAuthenticationHub> _hubContext;
    public const string Name = "Mfa";

    public MfaController(
        IAccountService accountService,
        TotpServiceFactory totpServiceFactory,
        ExtendedUserManager<DbUser> userManager,
        IStringLocalizer<MfaController> localizer,
        IIdentityServerInteractionService interaction,
        ExtendedSignInManager<DbUser> signInManager,
        ILogger<MfaController> logger,
        IHubContext<MultiFactorAuthenticationHub> hubContext
    ) {
        _accountService = accountService ?? throw new ArgumentNullException(nameof(accountService));
        _totpServiceFactory = totpServiceFactory ?? throw new ArgumentNullException(nameof(totpServiceFactory));
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _localizer = localizer ?? throw new ArgumentNullException(nameof(localizer));
        _interaction = interaction ?? throw new ArgumentNullException(nameof(interaction));
        _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _hubContext = hubContext ?? throw new ArgumentNullException(nameof(hubContext));
    }

    [Authorize(AuthenticationSchemes = ExtendedIdentityConstants.TwoFactorUserIdScheme)]
    [HttpGet("login/mfa")]
    public async Task<IActionResult> Index([FromQuery] string returnUrl) {
        var viewModel = await _accountService.BuildMfaLoginViewModelAsync(returnUrl);
        if (viewModel is null) {
            throw new InvalidOperationException();
        }
        var totpService = _totpServiceFactory.Create<DbUser>();
        if (viewModel.DeliveryChannel == TotpDeliveryChannel.Sms) {
            await totpService.SendAsync(message =>
                message.ToUser(viewModel.User)
                       .WithMessage(_localizer["Your OTP code for login is: {0}"])
                       .UsingSms()
                       .WithSubject(_localizer["OTP login"])
                       .WithPurpose(TotpConstants.TokenGenerationPurpose.MultiFactorAuthentication)
            );
        }
        return View(viewModel);
    }

    [Authorize(AuthenticationSchemes = ExtendedIdentityConstants.TwoFactorUserIdScheme)]
    [HttpPost("login/mfa")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index([FromForm] MfaLoginInputModel model) {
        var totpService = _totpServiceFactory.Create<DbUser>();
        var signInResult = await _signInManager.TwoFactorSignInAsync(totpService.TokenProvider, model.OtpCode, model.RememberMe, model.RememberClient);
        if (!signInResult.Succeeded) {
            ModelState.AddModelError(string.Empty, _localizer["The OTP code is not valid."]);
            var viewModel = await _accountService.BuildMfaLoginViewModelAsync(model);
            return View(viewModel);
        }
        if (string.IsNullOrEmpty(model.ReturnUrl)) {
            return Redirect("~/");
        } else if (_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl)) {
            return Redirect(model.ReturnUrl);
        } else {
            throw new Exception("Invalid return URL.");
        }
    }

    [Authorize(AuthenticationSchemes = ExtendedIdentityConstants.TwoFactorUserIdScheme)]
    [HttpPost("login/mfa/notify")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendPushNotification([FromBody] MfaLoginPushNotificationRequest request) {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null) {
            throw new InvalidOperationException();
        }
        var totpService = _totpServiceFactory.Create<DbUser>();
        await totpService.SendAsync(message =>
            message.ToUser(user)
                   .WithMessage(_localizer["Your OTP code for login is: {0}"])
                   .UsingPushNotification()
                   .WithSubject(_localizer["OTP login"])
                   .WithData(new { request.ConnectionId })
                   .WithPurpose(TotpConstants.TokenGenerationPurpose.MultiFactorAuthentication)
                   .WithClassification("MFA-Approval")
        );
        _logger.LogInformation("Sending push notification to connection: '{ConnectionId}'.", request.ConnectionId);
        return NoContent();
    }

    [Authorize(Policy = "BeDeviceAuthenticated")]
    [HttpPost("api/login/approve")]
    public async Task<IActionResult> ApproveLogin([FromBody] ApproveLoginRequest request) {
        await _hubContext.Clients.Client(request.ConnectionId).SendAsync(nameof(MultiFactorAuthenticationHub.LoginApproved), request.Otp);
        return NoContent();
    }

    [Authorize(Policy = "BeDeviceAuthenticated")]
    [HttpPost("api/login/reject")]
    public async Task<IActionResult> RejectLogin([FromBody] RejectLoginRequest request) {
        await _hubContext.Clients.Client(request.ConnectionId).SendAsync(nameof(MultiFactorAuthenticationHub.LoginApproved));
        return NoContent();
    }
}
