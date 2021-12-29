using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using IdentityModel;
using Indice.Api.JobHandlers;
using Indice.AspNetCore.Features.Campaigns;
using Indice.AspNetCore.Swagger;
using Indice.Configuration;
using Indice.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Swashbuckle.AspNetCore.SwaggerUI;

namespace Indice.Api
{
    public class Startup
    {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
            Settings = Configuration.GetSection(GeneralSettings.Name).Get<GeneralSettings>();
        }

        public IConfiguration Configuration { get; }
        public GeneralSettings Settings { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
            // Configure MVC
            services.AddControllers()
                    .AddCampaignsApiEndpoints(options => {
                        options.ApiPrefix = "api";
                        options.ConfigureDbContext = builder => builder.UseSqlServer(Configuration.GetConnectionString("CampaignsDb"));
                        options.DatabaseSchema = "cmp";
                        options.ExpectedScope = $"backoffice:{CampaignsApi.Scope}";
                        options.UserClaimType = JwtClaimTypes.Subject;
                    })
                    .AddJsonOptions(options => {
                        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
                        options.JsonSerializerOptions.WriteIndented = true;
                    });
            // Configure default CORS policy
            services.AddCors(options => options.AddDefaultPolicy(builder => {
                builder.WithOrigins(Configuration.GetSection("AllowedOrigins").Get<string[]>())
                       .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                       .WithHeaders("Authorization", "Content-Type")
                       .WithExposedHeaders("Content-Disposition");
            }));
            // Configure Swagger
            services.AddSwaggerGen(options => {
                options.IndiceDefaults(Settings);
                options.AddFluentValidationSupport();
                options.AddOAuth2AuthorizationCodeFlow(Settings);
                options.AddFormFileSupport();
                options.IncludeXmlComments(Assembly.Load(CampaignsApi.AssemblyName));
                options.AddDoc(CampaignsApi.Scope, "Campaigns API", "API for managing campaigns in the backoffice tool.");
            });
            // Configure authentication
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            services.AddAuthentication(options => {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options => {
                options.Audience = Settings?.Api?.ResourceName;
                options.Authority = Settings?.Authority;
                options.ForwardDefaultSelector = BearerSelector.ForwardReferenceToken("Introspection");
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters.NameClaimType = JwtClaimTypes.Name;
                options.TokenValidationParameters.RoleClaimType = JwtClaimTypes.Role;
            })
            .AddOAuth2Introspection("Introspection", options => {
                options.Authority = Settings?.Authority;
                options.CacheDuration = TimeSpan.FromMinutes(5);
                options.ClientId = Settings?.Api?.ResourceName;
                options.ClientSecret = Settings?.Api?.Secrets["Introspection"];
                options.EnableCaching = true;
            });
            services.AddScopeTransformation();
            // Configure framework & custom services
            services.AddDistributedMemoryCache();
            services.AddFilesLocal(options => {
                options.Path = "uploads";
            });
            // Setup worker host for executing background tasks.
            services.AddWorkerHost(options => {
                options.JsonOptions.JsonSerializerOptions.WriteIndented = true;
                options.AddRelationalStore(builder => {
                    builder.UseSqlServer(Configuration.GetConnectionString("WorkerDb"));
                    //builder.UseNpgsql(Configuration.GetConnectionString("WorkerDb"));
                });
            })
            .AddJob<LoadAvailableAlertsJobHandler>()
            .WithScheduleTrigger<DemoCounterModel>("0 0/1 * * * ?", options => {
                options.Name = "load-available-alerts";
                options.Description = "Load alerts for the queue.";
                options.Group = "indice";
            })
            .AddJob<SendSmsJobHandler>()
            .WithQueueTrigger<SmsDto>(options => {
                options.QueueName = "send-user-sms";
                options.PollingInterval = 500;
                options.InstanceCount = 3;
            })
            .AddJob<LogSendSmsJobHandler>()
            .WithQueueTrigger<LogSmsDto>(options => {
                options.QueueName = "log-send-user-sms";
                options.PollingInterval = 500;
                options.InstanceCount = 1;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment environment) {
            if (environment.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            }
            app.UseHttpsRedirection();
            app.UseCors();
            app.UseRouting();
            app.UseResponseCaching();
            app.UseAuthentication();
            app.UseAuthorization();
            if (Configuration.EnableSwaggerUi()) {
                app.UseSwaggerUI(options => {
                    options.RoutePrefix = "docs";
                    options.SwaggerEndpoint($"/swagger/{CampaignsApi.Scope}/swagger.json", CampaignsApi.Scope);
                    options.OAuth2RedirectUrl($"{Settings.Host}/docs/oauth2-redirect.html");
                    options.OAuthClientId("swagger-ui");
                    options.OAuthAppName("Swagger UI");
                    options.DocExpansion(DocExpansion.List);
                    options.OAuthUsePkce();
                    options.OAuthScopeSeparator(" ");
                });
            }
            app.UseEndpoints(endpoints => {
                endpoints.MapSwagger();
                endpoints.MapControllers();
            });
        }
    }
}
