﻿using System.Collections.Generic;
using IdentityServer4.Models;
using Indice.Types;

namespace Indice.Features.Identity.Server.Manager.Models;

/// <summary>Models a system client.</summary>
public class ClientInfo
{
    /// <summary>The unique identifier for this application.</summary>
    public string? ClientId { get; set; }
    /// <summary>Application name that will be seen on consent screens.</summary>
    public string? ClientName { get; set; }
    /// <summary>Application description.</summary>
    public string? Description { get; set; }
    /// <summary>Determines whether this application is enabled or not.</summary>
    public bool? Enabled { get; set; }
    /// <summary>Specifies whether a consent screen is required.</summary>
    public bool? RequireConsent { get; set; }
    /// <summary>Specifies whether consent screen is remembered after having been given.</summary>
    public bool? AllowRememberConsent { get; set; }
    /// <summary>Application logo that will be seen on consent screens.</summary>
    public string? LogoUri { get; set; }
    /// <summary>Application URL that will be seen on consent screens.</summary>
    public string? ClientUri { get; set; }
    /// <summary>Specifies whether the client can be edited or not.</summary>
    public bool NonEditable { get; set; }

    /// <summary>Creates a new instance of <see cref="ClientInfo"/> from a <see cref="IdentityServer4.EntityFramework.Entities.Client"/> object.</summary>
    /// <param name="client">The client instance.</param>
    public static ClientInfo FromClient(IdentityServer4.EntityFramework.Entities.Client client) => new() {
        ClientId = client.ClientId,
        ClientName = client.ClientName,
        ClientUri = client.ClientUri,
        Description = client.Description,
        AllowRememberConsent = client.AllowRememberConsent,
        Enabled = client.Enabled,
        LogoUri = client.LogoUri,
        RequireConsent = client.RequireConsent
    };
}

/// <summary>Models a system client when API provides info for a single client.</summary>
public class SingleClientInfo : ClientInfo
{
    /// <summary>Lifetime of identity token in seconds.</summary>
    public int? IdentityTokenLifetime { get; set; }
    /// <summary>Lifetime of access token in seconds.</summary>
    public int? AccessTokenLifetime { get; set; }
    /// <summary>Maximum lifetime of a refresh token in seconds.</summary>
    public int? AbsoluteRefreshTokenLifetime { get; set; }
    /// <summary>Lifetime of a user consent in seconds.</summary>
    public int? ConsentLifetime { get; set; }
    /// <summary>The maximum duration (in seconds) since the last time the user authenticated.</summary>
    public int? UserSsoLifetime { get; set; }
    /// <summary>Specifies logout URI at client for HTTP front-channel based logout.</summary>
    public string? FrontChannelLogoutUri { get; set; }
    /// <summary>Gets or sets a salt value used in pair-wise subjectId generation for users of this client.</summary>
    public string? PairWiseSubjectSalt { get; set; }
    /// <summary>Specifies whether the access token is a reference token or a self contained JWT token.</summary>
    public AccessTokenType? AccessTokenType { get; set; }
    /// <summary>
    /// ReUse: the refresh token handle will stay the same when refreshing tokens. 
    /// OneTime: the refresh token handle will be updated when refreshing tokens.
    /// </summary>
    public TokenUsage RefreshTokenUsage { get; set; }
    /// <summary>
    /// Absolute: the refresh token will expire on a fixed point in time (specified by the AbsoluteRefreshTokenLifetime) 
    /// Sliding: when refreshing the token, the lifetime of the refresh token will be renewed (by the amount specified in SlidingRefreshTokenLifetime).
    /// The lifetime will not exceed AbsoluteRefreshTokenLifetime.
    /// </summary>
    public TokenExpiration RefreshTokenExpiration { get; set; }
    /// <summary>Gets or sets a value indicating whether to allow offline access.</summary>
    public bool? AllowOfflineAccess { get; set; }
    /// <summary>Gets or sets a value indicating whether the access token (and its claims) should be updated on a refresh token request.</summary>
    public bool? UpdateAccessTokenClaimsOnRefresh { get; set; }
    /// <summary>Specifies if the user's session id should be sent to the FrontChannelLogoutUri.</summary>
    public bool? FrontChannelLogoutSessionRequired { get; set; }
    /// <summary>Gets or sets a value indicating whether JWT access tokens should include an identifier.</summary>
    public bool? IncludeJwtId { get; set; }
    /// <summary>Controls whether access tokens are transmitted via the browser for this client. This can prevent accidental leakage of access tokens when multiple response types are allowed.</summary>
    public bool? AllowAccessTokensViaBrowser { get; set; }
    /// <summary>When requesting both an id token and access token, should the user claims always be added to the id token instead of requiring the client to use the user-info endpoint.</summary>
    public bool? AlwaysIncludeUserClaimsInIdToken { get; set; }
    /// <summary>Gets or sets a value indicating whether client claims should be always included in the access tokens - or only for client credentials flow.</summary>
    public bool? AlwaysSendClientClaims { get; set; }
    /// <summary>Lifetime of authorization code in seconds.</summary>
    public int? AuthorizationCodeLifetime { get; set; }
    /// <summary>Specifies whether a proof key is required for authorization code based token requests.</summary>
    public bool? RequirePkce { get; set; }
    /// <summary>Specifies whether a proof key can be sent using plain method.</summary>
    public bool? AllowPlainTextPkce { get; set; }
    /// <summary>Gets or sets a value to prefix it on client claim types.</summary>
    public string? ClientClaimsPrefix { get; set; }
    /// <summary>Specifies logout URI at client for HTTP back-channel based logout.</summary>
    public string? BackChannelLogoutUri { get; set; }
    /// <summary>If the user's session id should be sent to the <see cref="FrontChannelLogoutUri"/>. Defaults to true</summary>
    public bool BackChannelLogoutSessionRequired { get; set; }
    /// <summary>Gets or sets the type of the device flow user code.</summary>
    public string? UserCodeType { get; set; }
    /// <summary>Sliding lifetime of a refresh token in seconds. Defaults to 1296000 seconds / 15 days.</summary>
    public int SlidingRefreshTokenLifetime { get; set; }
    /// <summary>Gets or sets the device code lifetime.</summary>
    public int? DeviceCodeLifetime { get; set; }
    /// <summary>List of client claims.</summary>
    public IEnumerable<ClaimInfo>? Claims { get; set; }
    /// <summary>List of configured grant types.</summary>
    public IEnumerable<string>? GrantTypes { get; set; }
    /// <summary>List of available client secrets.</summary>
    public IEnumerable<ClientSecretInfo>? Secrets { get; set; }
    /// <summary>CORS origins allowed.</summary>
    public IEnumerable<string>? AllowedCorsOrigins { get; set; }
    /// <summary>Allowed URIs to redirect after logout.</summary>
    public IEnumerable<string>? PostLogoutRedirectUris { get; set; }
    /// <summary>Allowed URIs to redirect after successful login.</summary>
    public IEnumerable<string>? RedirectUris { get; set; }
    /// <summary>The API resources that the client has access to.</summary>
    public IEnumerable<string>? ApiResources { get; set; }
    /// <summary>The identity resources that the client has access to.</summary>
    public IEnumerable<string>? IdentityResources { get; set; }
    /// <summary>Translations.</summary>
    public TranslationDictionary<ClientTranslation>? Translations { get; set; }
    /// <summary>Determines whether login using a local account is allowed for this client.</summary>
    public bool EnableLocalLogin { get; set; }
    /// <summary>List of identity providers that are not allowed for this client.</summary>
    public IEnumerable<string>? IdentityProviderRestrictions { get; set; }
}

/// <summary>Translation object for type <see cref="SingleClientInfo"/>.</summary>
public class ClientTranslation
{
    /// <summary>The name of the client.</summary>
    public string? ClientName { get; set; }
    /// <summary>The description of the client.</summary>
    public string? Description { get; set; }
}
