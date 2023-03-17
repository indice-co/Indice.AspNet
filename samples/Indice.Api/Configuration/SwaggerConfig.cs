﻿using System.Reflection;
using Indice.Configuration;
using Indice.Features.Messages.Core;

namespace Microsoft.Extensions.DependencyInjection;

public static class SwaggerConfig
{
    public static IServiceCollection AddSwaggerConfig(this IServiceCollection services, GeneralSettings generalSettings) {
        services.AddSwaggerGen(options => {
            options.IndiceDefaults(generalSettings);
            options.AddFluentValidationSupport();
            options.AddOAuth2AuthorizationCodeFlow(generalSettings);
            options.AddFormFileSupport();
            options.IncludeXmlComments(Assembly.GetAssembly(typeof(MessageFeatureExtensions)));
            options.IncludeXmlComments(Assembly.GetAssembly(typeof(MessageEndpointOptions)));
            options.AddDoc(MessagesApi.Scope, "Campaigns API", "API for managing campaigns in the backoffice tool.");
            options.AddDoc("lookups", "Lookups API", "API for various lookups.");
            options.AddDoc("workers", "Workers API", "API for triggering various background jobs.");
        });
        return services;
    }
}
