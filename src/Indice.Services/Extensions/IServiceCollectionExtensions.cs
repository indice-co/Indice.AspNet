﻿using System;
using System.Collections;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using Indice.Configuration;
using Indice.Services;
using Indice.Services.Yuboto;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions on the <see cref="IServiceCollection"/>.
    /// </summary>
    public static class IndiceServicesServiceCollectionExtensions
    {
        /// <summary>
        /// Add a decorator pattern implementation.
        /// </summary>
        /// <typeparam name="TService">The service type to decorate.</typeparam>
        /// <typeparam name="TDecorator">The decorator.</typeparam>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        public static IServiceCollection AddDecorator<TService, TDecorator>(this IServiceCollection services)
            where TService : class
            where TDecorator : class, TService {
            var serviceDescriptor = services.Where(x => x.ServiceType == typeof(TService)).LastOrDefault();
            if (serviceDescriptor is null) {
                services.AddTransient<TService, TDecorator>();
                return services;
            }
            services.TryAddTransient(serviceDescriptor.ImplementationType);
            return services.AddTransient<TService, TDecorator>(serviceProvider => {
                var parameters = typeof(TDecorator).GetConstructors(BindingFlags.Public | BindingFlags.Instance).First().GetParameters();
                var arguments = parameters.Select(x => x.ParameterType.Equals(typeof(TService))
                    ? serviceProvider.GetRequiredService(serviceDescriptor.ImplementationType)
                    : serviceProvider.GetService(x.ParameterType)).ToArray();
                return (TDecorator)Activator.CreateInstance(typeof(TDecorator), arguments);
            });
        }

        /// <summary>
        /// Adds Indice's common services.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configuration">Represents a set of key/value application configuration properties.</param>
        public static IServiceCollection AddGeneralSettings(this IServiceCollection services, IConfiguration configuration) {
            services.Configure<GeneralSettings>(configuration.GetSection(GeneralSettings.Name));
            services.TryAddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<GeneralSettings>>().Value);
            return services;
        }

        /// <summary>
        /// Adds a fugazi implementation of <see cref="IPushNotificationService"/> that does nothing.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        public static IServiceCollection AddPushNotificationServiceNoOp(this IServiceCollection services) {
            services.TryAddTransient<IPushNotificationService, NoOpPushNotificationService>();
            return services;
        }

        /// <summary>
        /// Adds an implementation of <see cref="IPushNotificationService"/> for sending push notifications.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configure">Configure the available options for push notifications. Null to use defaults.</param>
        public static IServiceCollection AddPushNotificationServiceAzure(this IServiceCollection services, Action<PushNotificationAzureOptions> configure = null) {
            var configuration = services.BuildServiceProvider().GetRequiredService<IConfiguration>();
            var options = new PushNotificationAzureOptions {
                ConnectionString = configuration.GetConnectionString(PushNotificationServiceAzure.ConnectionStringName) ??
                                       configuration.GetSection(PushNotificationAzureOptions.Name).GetValue<string>(nameof(PushNotificationAzureOptions.ConnectionString)),
                NotificationHubPath = configuration.GetSection(PushNotificationAzureOptions.Name).GetValue<string>(nameof(PushNotificationAzureOptions.NotificationHubPath)) ??
                                          configuration.GetValue<string>(PushNotificationServiceAzure.NotificationsHubPath)
            };
            options.Services = services;
            configure?.Invoke(options);
            options.Services = null;
            services.Configure<PushNotificationAzureOptions>(config => {
                config.ConnectionString = options.ConnectionString;
                config.NotificationHubPath = options.NotificationHubPath;
                config.MessageHandler = options.MessageHandler;
            });
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<PushNotificationAzureOptions>>().Value);
            services.AddTransient<IPushNotificationService, PushNotificationServiceAzure>();
            return services;
        }

        /// <summary>
        /// Reads the <see cref="PushNotificationAzureOptions"/> directly from configuration.
        /// </summary>
        /// <param name="options">Push notification service options.</param>
        /// <param name="section">The section to use in search for settings. Default section used is <see cref="PushNotificationAzureOptions.Name"/>.</param>
        public static PushNotificationAzureOptions FromConfiguration(this PushNotificationAzureOptions options, string section = null) {
            var serviceProvider = options.Services.BuildServiceProvider();
            var configuration = serviceProvider.GetRequiredService<IConfiguration>();
            configuration.Bind(section ?? PushNotificationAzureOptions.Name, options);
            return options;
        }

        /// <summary>
        /// Adds an instance of <see cref="IEmailService"/> using SMTP settings in configuration.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configuration">Represents a set of key/value application configuration properties.</param>
        public static IServiceCollection AddEmailService(this IServiceCollection services, IConfiguration configuration) {
            services.Configure<EmailServiceSettings>(configuration.GetSection(EmailServiceSettings.Name));
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<EmailServiceSettings>>().Value);
            services.AddTransient<IEmailService, EmailServiceSmtp>();
            return services;
        }

        /// <summary>
        /// Adds an instance of <see cref="ISmsService"/> using Youboto.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configuration">Represents a set of key/value application configuration properties.</param>
        public static IServiceCollection AddSmsServiceYuboto(this IServiceCollection services, IConfiguration configuration) {
            services.Configure<SmsServiceSettings>(configuration.GetSection(SmsServiceSettings.Name));
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<SmsServiceSettings>>().Value);
            services.TryAddTransient<ISmsServiceFactory, DefaultSmsServiceFactory>();
            services.AddHttpClient<ISmsService, SmsServiceYuboto>().SetHandlerLifetime(TimeSpan.FromMinutes(5));
            return services;
        }

        /// <summary>
        /// Adds an instance of <see cref="ISmsService"/> using Apifon.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configuration">Represents a set of key/value application configuration properties.</param>
        /// <param name="configure">Configure the available options. Null to use defaults.</param>
        public static IServiceCollection AddSmsServiceApifon(this IServiceCollection services, IConfiguration configuration, Action<SmsServiceApifonOptions> configure = null) {
            services.Configure<SmsServiceApifonSettings>(configuration.GetSection(SmsServiceSettings.Name));
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<SmsServiceApifonSettings>>().Value);
            services.TryAddTransient<ISmsServiceFactory, DefaultSmsServiceFactory>();
            var options = new SmsServiceApifonOptions();
            configure?.Invoke(options);
            var httpClientBuilder = services.AddHttpClient<ISmsService, SmsServiceApifon>()
                                            .ConfigureHttpClient(httpClient => {
                                                httpClient.BaseAddress = new Uri("https://ars.apifon.com/services/api/v1/sms/");
                                            });
            if (options.ConfigurePrimaryHttpMessageHandler != null) {
                httpClientBuilder.ConfigurePrimaryHttpMessageHandler(options.ConfigurePrimaryHttpMessageHandler);
            }
            return services;
        }

        /// <summary>
        /// Adds an instance of <see cref="ISmsService"/> using Youboto.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configuration">Represents a set of key/value application configuration properties.</param>
        public static IServiceCollection AddSmsServiceViber(this IServiceCollection services, IConfiguration configuration) {
            services.Configure<SmsServiceViberSettings>(configuration.GetSection(SmsServiceViberSettings.Name));
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<SmsServiceViberSettings>>().Value);
            services.TryAddTransient<ISmsServiceFactory, DefaultSmsServiceFactory>();
            services.AddHttpClient<ISmsService, SmsServiceViber>().SetHandlerLifetime(TimeSpan.FromMinutes(5));
            return services;
        }

        /// <summary>
        /// Adds an instance of <see cref="ISmsService"/> using Youboto Omni from sending regular SMS messages.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configuration">Represents a set of key/value application configuration properties.</param>
        public static IServiceCollection AddSmsServiceYubotoOmni(this IServiceCollection services, IConfiguration configuration) {
            services.Configure<SmsServiceSettings>(configuration.GetSection(SmsServiceSettings.Name));
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<SmsServiceSettings>>().Value);
            services.TryAddTransient<ISmsServiceFactory, DefaultSmsServiceFactory>();
            services.AddHttpClient<ISmsService, SmsYubotoOmniService>().SetHandlerLifetime(TimeSpan.FromMinutes(5));
            return services;
        }

        /// <summary>
        /// Adds an instance of <see cref="ISmsService"/> using Youboto Omni for sending Viber messages.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configuration">Represents a set of key/value application configuration properties.</param>
        public static IServiceCollection AddViberServiceYubotoOmni(this IServiceCollection services, IConfiguration configuration) {
            services.Configure<SmsServiceSettings>(configuration.GetSection(SmsServiceSettings.Name));
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IOptions<SmsServiceSettings>>().Value);
            services.TryAddTransient<ISmsServiceFactory, DefaultSmsServiceFactory>();
            services.AddHttpClient<ISmsService, ViberYubotoOmniService>().SetHandlerLifetime(TimeSpan.FromMinutes(5));
            return services;
        }

        /// <summary>
        /// Adds <see cref="IEventDispatcher"/> using Azure Storage as a queuing mechanism.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configure">Configure the available options. Null to use defaults.</param>
        public static IServiceCollection AddEventDispatcherAzure(this IServiceCollection services, Action<IServiceProvider, EventDispatcherOptions> configure = null) {
            services.AddTransient<IEventDispatcher, EventDispatcherAzure>(serviceProvider => {
                var options = new EventDispatcherOptions {
                    ConnectionString = serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString(EventDispatcherAzure.CONNECTION_STRING_NAME),
                    Enabled = true,
                    EnvironmentName = serviceProvider.GetRequiredService<IHostEnvironment>().EnvironmentName,
                    ClaimsPrincipalSelector = ClaimsPrincipal.ClaimsPrincipalSelector ?? (() => ClaimsPrincipal.Current)
                };
                configure?.Invoke(serviceProvider, options);
                return new EventDispatcherAzure(options.ConnectionString, options.EnvironmentName, options.Enabled, options.MessageEncoding, options.ClaimsPrincipalSelector, options.TenantIdSelector);
            });
            return services;
        }

        /// <summary>
        /// Adds <see cref="IEventDispatcher"/> using an in-memory <seealso cref="Queue"/> as a backing store.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        public static IServiceCollection AddEventDispatcherInMemory(this IServiceCollection services) {
            services.AddTransient<IEventDispatcher, EventDispatcherInMemory>();
            return services;
        }

        /// <summary>
        /// Registers an implementation of <see cref="ILockManager"/> that uses Microsoft Azure Blob Storage as a backing store.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configure">Configure the available options. Null to use defaults.</param>
        public static IServiceCollection AddLockManagerAzure(this IServiceCollection services, Action<IServiceProvider, LockManagerAzureOptions> configure = null) {
            services.AddTransient<ILockManager, LockManagerAzure>(serviceProvider => {
                var options = new LockManagerAzureOptions {
                    ConnectionString = serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString(LockManagerAzure.CONNECTION_STRING_NAME),
                    EnvironmentName = serviceProvider.GetRequiredService<IHostEnvironment>().EnvironmentName
                };
                configure?.Invoke(serviceProvider, options);
                return new LockManagerAzure(options);
            });
            return services;
        }

        /// <summary>
        /// Registers an implementation of <see cref="IPlatformEventHandler{TEvent}"/> for the specified event type.
        /// </summary>
        /// <typeparam name="TEvent">The type of the event to handler.</typeparam>
        /// <typeparam name="TEventHandler">The handler to user for the specified event.</typeparam>
        /// <param name="services">The services available in the application.</param>
        public static IServiceCollection AddPlatformEventHandler<TEvent, TEventHandler>(this IServiceCollection services)
            where TEvent : IPlatformEvent
            where TEventHandler : class, IPlatformEventHandler<TEvent> {
            services.TryAddTransient(typeof(IPlatformEventHandler<TEvent>), typeof(TEventHandler));
            return services;
        }
    }
}
