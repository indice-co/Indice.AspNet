﻿#nullable enable
using System.Net.Mime;
using Indice.AspNetCore.Middleware;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Http;

/// <summary>Extension methods on <see cref="HttpContext"/> regarding the application of <see cref="SecurityHeadersPolicy"/>.</summary>
public static class SecurityHeadersHttpContextExtensions
{
    /// <summary>Applies the security headers policy for the current request.</summary>
    /// <param name="httpContext"></param>
    /// <param name="requestPolicy"></param>
    public static HttpContext ApplySecurityHeaders(this HttpContext httpContext, SecurityHeadersPolicy? requestPolicy = null) {
        requestPolicy ??= httpContext.RequestServices.GetRequiredService<SecurityHeadersPolicy>();
        httpContext.Response.OnStarting(() => {
            if (requestPolicy.HasXContentTypeOptions && !httpContext.Response.Headers.ContainsKey("X-Content-Type-Options")) {
                httpContext.Response.Headers.Add("X-Content-Type-Options", requestPolicy.XContentTypeOptions);
            }
            if (requestPolicy.HasXFrameOptions && !httpContext.Response.Headers.ContainsKey("X-Frame-Options")) {
                httpContext.Response.Headers.Add("X-Frame-Options", requestPolicy.XFrameOptions);
            }
            var isHtmlDocument = httpContext.Response.ContentType?.StartsWith(MediaTypeNames.Text.Html);
            if (isHtmlDocument == true) {
                var cspPolicy = requestPolicy.ContentSecurityPolicy?.Clone() ?? CSP.DefaultPolicy.Clone();
                if (httpContext.Items.ContainsKey(CSP.CSP_SCRIPT_NONCE_HTTPCONTEXT_KEY)) {
                    var nonceList = (List<string>)httpContext.Items[CSP.CSP_SCRIPT_NONCE_HTTPCONTEXT_KEY]!;
                    foreach (var nonce in nonceList) {
                        cspPolicy.AddScriptSrc($"'nonce-{nonce}'");
                    }
                }
                if (httpContext.Items.ContainsKey(CSP.CSP_STYLE_NONCE_HTTPCONTEXT_KEY)) {
                    var nonceList = (List<string>)httpContext.Items[CSP.CSP_STYLE_NONCE_HTTPCONTEXT_KEY]!;
                    foreach (var nonce in nonceList) {
                        cspPolicy.AddStyleSrc($"'nonce-{nonce}'");
                    }
                }
                // Once for standards compliant browsers.
                if (requestPolicy.HasContentSecurityPolicy && !httpContext.Response.Headers.ContainsKey("Content-Security-Policy")) {
                    httpContext.Response.Headers.Add("Content-Security-Policy", cspPolicy.ToString());
                }
                // And once again for IE.
                if (requestPolicy.HasContentSecurityPolicy && !httpContext.Response.Headers.ContainsKey("X-Content-Security-Policy")) {
                    httpContext.Response.Headers.Add("X-Content-Security-Policy", cspPolicy.ToString());
                }
            }
            if (requestPolicy.HasReferrerPolicy && !httpContext.Response.Headers.ContainsKey("Referrer-Policy")) {
                httpContext.Response.Headers.Add("Referrer-Policy", requestPolicy.ReferrerPolicy);
            }
            return Task.CompletedTask;
        });
        return httpContext;
    }
}
#nullable disable