﻿using System.Security.Claims;
using Indice.Features.Identity.Core;
using Indice.Features.Identity.Core.Data.Models;
using Indice.Security;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Indice.Identity.Security;

public class MicrosoftGraphUserClaimsPrincipalFactory : ExtendedUserClaimsPrincipalFactory<DbUser, DbRole>
{
    private readonly UserManager<DbUser> _userManager;

    public MicrosoftGraphUserClaimsPrincipalFactory(UserManager<DbUser> userManager, RoleManager<DbRole> roleManager, IOptions<IdentityOptions> options) : base(userManager, roleManager, options) {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
    }

    protected async override Task<ClaimsIdentity> GenerateClaimsAsync(DbUser user) {
        var identity = await base.GenerateClaimsAsync(user);
        var msGraphToken = await _userManager.GetAuthenticationTokenAsync(user, MicrosoftAccountDefaults.AuthenticationScheme, OpenIdConnectParameterNames.AccessToken);
        if (!string.IsNullOrEmpty(msGraphToken)) {
            identity.AddClaim(new Claim(BasicClaimTypes.MsGraphToken, msGraphToken));
        }
        return identity;
    }
}
