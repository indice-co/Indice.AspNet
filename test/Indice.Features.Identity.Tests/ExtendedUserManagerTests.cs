using System.Security.Claims;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using Indice.Events;
using Indice.Features.Identity.Core;
using Indice.Features.Identity.Core.Data;
using Indice.Features.Identity.Core.Data.Models;
using Indice.Features.Identity.Core.Data.Stores;
using Indice.Features.Identity.Core.Events;
using Indice.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Indice.Features.Identity.Tests;

public class ExtendedUserManagerTests
{
    private IServiceProvider _serviceProvider;
    private const string IDENTITY_DATABASE_NAME = "IdentityDb";
    private const string CLIENT_ID = "ppk-client";
    private const string CLIENT_SECRET = "JUEKX2XugFv5XrX3";
    private const string MOCK_USER_ID = "713EBE91-8720-45C5-BBE6-CFABB6E58E31";

    private Mock<IPlatformEventService> _mockPlatformEventService;

    public ExtendedUserManagerTests() {
        var builder = new WebHostBuilder();

        // setup Mock IPlatformEventService
        _mockPlatformEventService = new Mock<IPlatformEventService>();

        _mockPlatformEventService
            .Setup(x => x.Publish(It.IsAny<EmailChangedEvent>()))
            .Returns(Task.CompletedTask);

        _mockPlatformEventService
            .Setup(x => x.Publish(It.IsAny<PhoneNumberChangedEvent>()))
            .Returns(Task.CompletedTask);

        builder.ConfigureAppConfiguration(builder => {
            builder.AddInMemoryCollection(new Dictionary<string, string> {
                ["IdentityOptions:User:Devices:DefaultAllowedRegisteredDevices"] = "1",
                ["IdentityOptions:User:Devices:MaxAllowedRegisteredDevices"] = "3",
                ["IdentityOptions:User:Devices:RequirePasswordAfterUserUpdate"] = "false",
            });
        });
        builder.ConfigureServices((ctx, services) => {
            services.AddDbContext<ExtendedIdentityDbContext<User, Role>>(builder => builder.UseInMemoryDatabase($"IDENTITY_DATABASE_NAME-{Guid.NewGuid()}"));
            services.AddTransient<IUserStateProvider<User>, UserStateProviderNoop>();
            services.AddTransient<IPlatformEventService>(_ => _mockPlatformEventService.Object);
            services.AddIdentity<User, Role>()
                    .AddExtendedUserManager()
                    .AddUserStore<ExtendedUserStore<ExtendedIdentityDbContext<User, Role>, User, Role>>()
                    .AddEntityFrameworkStores<ExtendedIdentityDbContext<User, Role>>();
            services.AddIdentityServer(options => {
                options.EmitStaticAudienceClaim = true;
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
            .AddInMemoryClients(GetClients())
            .AddInMemoryApiResources(GetApiResources())
            .AddDeviceAuthentication(options => options.AddUserDeviceStoreEntityFrameworkCore())
            .AddAspNetIdentity<User>();
        });
        builder.Configure(app => {
            app.IdentityStoreSetup();
        });

        var server = new TestServer(builder);
        var handler = server.CreateHandler();
        _serviceProvider = server.Services;
    }

    [Fact]
    public async Task EmailChangedEventPublished() {
        await CreateMockUser();
        var userManager = _serviceProvider.GetRequiredService<ExtendedUserManager<User>>();
        var expectedInvocations = Times.Once;

        var newEmail = "company@indice.gr";

        var user = await userManager.FindByIdAsync(MOCK_USER_ID);
        await userManager.SetEmailAsync(user, newEmail);

        _mockPlatformEventService.Verify(x => x.Publish(It.IsAny<EmailChangedEvent>()), expectedInvocations);
    }

    [Fact]
    public async Task PhoneNumberChangedEventPublished() {
        await CreateMockUser();
        var userManager = _serviceProvider.GetRequiredService<ExtendedUserManager<User>>();
        var expectedInvocations = Times.Once;

        var newPhone = "6990000000";

        var user = await userManager.FindByIdAsync(MOCK_USER_ID);
        await userManager.SetPhoneNumberAsync(user, newPhone);

        _mockPlatformEventService.Verify(x => x.Publish(It.IsAny<PhoneNumberChangedEvent>()), expectedInvocations);
    }

    private async Task CreateMockUser() {
        var userManager = _serviceProvider.GetRequiredService<ExtendedUserManager<User>>();

        var user = new User {
            CreateDate = DateTimeOffset.UtcNow,
            Email = "testuser@indice.gr",
            EmailConfirmed = true,
            Id = MOCK_USER_ID,
            PhoneNumber = "69XXXXXXXX",
            PhoneNumberConfirmed = true,
            UserName = "testuser"
        };

        await userManager.CreateAsync(user, password: "123abc!", validatePassword: false);
    }

    private static List<Client> GetClients() => new() {
        new Client {
            ClientId = CLIENT_ID,
            ClientName = "Public/Private key client",
            AccessTokenType = AccessTokenType.Jwt,
            AllowAccessTokensViaBrowser = false,
            AllowedGrantTypes = {
                CustomGrantTypes.DeviceAuthentication,
                GrantType.ClientCredentials,
                GrantType.ResourceOwnerPassword
            },
            ClientSecrets = {
                new Secret(CLIENT_SECRET.ToSha256())
            },
            AllowedScopes = {
                IdentityServerConstants.StandardScopes.OpenId,
                IdentityServerConstants.StandardScopes.Phone,
                "scope1"
            },
            RequireConsent = false,
            RequirePkce = false,
            RequireClientSecret = true,
            AllowOfflineAccess = true,
            AlwaysSendClientClaims = true,
            Claims = {
                new ClientClaim(BasicClaimTypes.TrustedDevice, "true", ClaimValueTypes.Boolean),
                new ClientClaim(BasicClaimTypes.MobileClient, "true", ClaimValueTypes.Boolean)
            }
        }
    };

    private static List<ApiResource> GetApiResources() => new() {
        new ApiResource(name: "api1", displayName: "API No. 1") {
            Scopes = { "scope1", "scope2" }
        }
    };
}
