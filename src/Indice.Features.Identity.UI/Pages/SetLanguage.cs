using System.Globalization;
using System.Text.RegularExpressions;
using Indice.AspNetCore.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Indice.Features.Identity.UI.Pages;

/// <summary>Page model for the set language screen.</summary>
[IdentityUI(typeof(SetLanguageModel))]
[SecurityHeaders]
public abstract class BaseSetLanguageModel : BasePageModel
{
    private readonly RequestLocalizationOptions _requestLocalizationOptions;

    /// <summary>Creates a new instance of <see cref="BaseSetLanguageModel"/> class.</summary>
    public BaseSetLanguageModel(IOptions<RequestLocalizationOptions> requestLocalizationOptions) : base() {
        _requestLocalizationOptions = requestLocalizationOptions.Value;
    }

    /// <summary>The submitted culture to change.</summary>
    [BindProperty]
    public string? Culture { get; set; }

    /// <summary>Set language page POST handler.</summary>
    public virtual IActionResult OnPost(string? returnUrl, string? culture) => OnSetLangageInternal(returnUrl, Culture ?? culture);

    /// <summary>Set language page GET handler.</summary>
    public virtual IActionResult OnGet(string? returnUrl, string? culture) => OnSetLangageInternal(returnUrl, culture);
    

    /// <summary>Set language page POST handler.</summary>
    private IActionResult OnSetLangageInternal(string? returnUrl, string? culture) {
        var supportedCultures = (_requestLocalizationOptions.SupportedCultures ?? new List<CultureInfo>()).Select(x => x.TwoLetterISOLanguageName).ToHashSet();
        if (string.IsNullOrWhiteSpace(culture) || !supportedCultures.Contains(culture)) {
            culture = _requestLocalizationOptions.DefaultRequestCulture.Culture.TwoLetterISOLanguageName;
        }
        Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)), new CookieOptions {
                Expires = DateTimeOffset.UtcNow.AddYears(1),
                IsEssential = true, // Critical setting to apply new culture.
                Path = "/",
                HttpOnly = false
            }
        );
        return LocalRedirect(returnUrl ?? "/");
    }
}

internal class SetLanguageModel : BaseSetLanguageModel
{
    public SetLanguageModel(IOptions<RequestLocalizationOptions> requestLocalizationOptions) : base(requestLocalizationOptions) { }
}
