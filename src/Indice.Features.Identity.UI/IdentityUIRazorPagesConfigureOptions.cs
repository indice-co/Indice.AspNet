﻿using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Indice.Features.Identity.UI;

internal class IdentityUIRazorPagesConfigureOptions : IPostConfigureOptions<RazorPagesOptions>
{
    public void PostConfigure(string? name, RazorPagesOptions options) {
        options = options ?? throw new ArgumentNullException(nameof(options));
        options.Conventions.Add(new IdentityUIPageModelConvention());
        options.Conventions.Add(new IdentityUIPageRouteModelConvention());
        options.Conventions.Add(new OrderPageRouteModelConvention(int.MaxValue));
    }
}
