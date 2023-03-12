﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Indice.AspNetCore.Authentication.GovGr;

/// <summary>Extension methods to configure GovGr OAuth authentication.</summary>
public static class GovGrExtensions
{
    /// <summary>
    /// Adds GovGr OAuth-based authentication to <see cref="AuthenticationBuilder"/> using the default scheme. The default scheme is specified by <see cref="GovGrDefaults.AuthenticationScheme"/>.
    /// <para>
    /// GovGr authentication allows application users to sign in with their GovGr account.
    /// </para>
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="OpenIdConnectOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddGovGr(this AuthenticationBuilder builder, Action<GovGrOptions> configureOptions) => builder.AddGovGr(GovGrDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds GovGr OAuth-based authentication to <see cref="AuthenticationBuilder"/> using the default scheme. The default scheme is specified by <see cref="GovGrDefaults.AuthenticationScheme"/>.
    /// <para>
    /// GovGr authentication allows application users to sign in with their GovGr account.
    /// </para>
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="OpenIdConnectOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddGovGr(this AuthenticationBuilder builder, string authenticationScheme, Action<GovGrOptions> configureOptions) => builder.AddGovGr(authenticationScheme, GovGrDefaults.DisplayName, configureOptions);

    /// <summary>
    /// Adds GovGr OAuth-based authentication to <see cref="AuthenticationBuilder"/> using the default scheme. The default scheme is specified by <see cref="GovGrDefaults.AuthenticationScheme"/>.
    /// <para>
    /// GovGr authentication allows application users to sign in with their GovGr account.
    /// </para>
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for the authentication handler.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="OpenIdConnectOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddGovGr(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<GovGrOptions> configureOptions)
        => builder.AddOpenIdConnect(authenticationScheme, displayName, (options) => {
            var govGrOptions = new GovGrOptions();
            configureOptions?.Invoke(govGrOptions);
            if (string.IsNullOrWhiteSpace(govGrOptions.ClientId)) {
                throw new ArgumentOutOfRangeException(nameof(govGrOptions.ClientId), "GovGr Id. The '{0}' option must be provided.");
            }
            if (string.IsNullOrWhiteSpace(govGrOptions.ClientSecret)) {
                throw new ArgumentOutOfRangeException(nameof(govGrOptions.ClientSecret), "GovGr Id. The '{0}' option must be provided.");
            }
            // Manually set these two endpoint since there is not a well known configuration endpoint.
            options.Configuration = new OpenIdConnectConfiguration {
                TokenEndpoint = govGrOptions.TokenEndpoint,
                AuthorizationEndpoint = govGrOptions.AuthorizationEndpoint
            };
            options.SaveTokens = true;
            options.Authority = govGrOptions.Authority;
            options.CallbackPath = govGrOptions.CallbackPath ?? new PathString("/signin-govgr");
            options.SignInScheme = govGrOptions.SignInScheme ?? CookieAuthenticationDefaults.AuthenticationScheme;
            options.ResponseType = "code";
            options.DisableTelemetry = true;
            options.SaveTokens = true;
            options.Scope.Clear();
            foreach (var scope in govGrOptions.Scopes) {
                options.Scope.Add(scope);
            }
            options.ClientId = govGrOptions.ClientId;
            options.ClientSecret = govGrOptions.ClientSecret;
            options.UsePkce = false;
        });
}
