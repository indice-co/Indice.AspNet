﻿using System;
using Indice.Features.Kyc.GovGr.Configuration;
using Indice.Features.Kyc.GovGr.Interfaces;
using Indice.Features.Kyc.GovGr.Services;
using Microsoft.Extensions.Configuration;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Configuration extensions regarding eKYC for gov GR
    /// </summary>
    public static class KycConfig
    {
        /// <summary>
        /// Add GovGr Kyc service.
        /// </summary>
        public static void AddKycGovGr(this IServiceCollection services, Action<KycSettings> configure = null) {
            var serviceProvider = services.BuildServiceProvider();
            var configuration = serviceProvider.GetRequiredService<IConfiguration>();
            // Initialize empty options.
            var options = new KycSettings();
            // Bind 'EGovKycSettings' section from application settings to 'options' object.
            configuration.Bind(KycSettings.Name, options);
            // Invoke provided action from caller and override 'options' object.
            configure?.Invoke(options);
            // Register options in the DI container.
            services.Configure<KycSettings>(settings => {
                settings.TokenEndpoint = options.TokenEndpoint;
                settings.ResourceServerEndpoint = options.ResourceServerEndpoint;
                settings.UseMockServices = options.UseMockServices;
                settings.Clients = options.Clients;
                settings.SkipCheckTin = options.SkipCheckTin;
            });
            // Register custom services.
            if (!options.UseMockServices) {
                services.AddHttpClient(nameof(KycService));
                services.AddTransient<IKycService, KycService>();
            } else {
                services.AddTransient<IKycService, MockKycService>();
            }
            services.AddTransient<IKycScopeService, KycScopeService>();
        }
    }
}