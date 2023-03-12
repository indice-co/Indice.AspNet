﻿using System.Net.Mime;
using Indice.AspNetCore.Features.Settings.Models;
using Indice.Extensions.Configuration.Database;
using Indice.Extensions.Configuration.Database.Data.Models;
using Indice.Types;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Hosting;

namespace Indice.AspNetCore.Features.Settings.Controllers;

/// <summary>Contains operations for managing application settings in the database.</summary>
/// <response code="400">Bad Request</response>
/// <response code="401">Unauthorized</response>
/// <response code="403">Forbidden</response>
/// <response code="500">Internal Server Error</response>
[ApiController]
[Authorize(Policy = SettingsApi.Policies.BeSettingsManager)]
[Consumes(MediaTypeNames.Application.Json)]
[Produces(MediaTypeNames.Application.Json)]
[ProducesResponseType(statusCode: 400, type: typeof(ValidationProblemDetails))]
[ProducesResponseType(statusCode: 401, type: typeof(ProblemDetails))]
[ProducesResponseType(statusCode: 403, type: typeof(ProblemDetails))]
[Route("[settingsApiPrefix]/app-settings")]
internal class SettingsController : ControllerBase
{
    private readonly IAppSettingsDbContext _appSettingsDbContext;
    private DbContext _dbContext => (DbContext)_appSettingsDbContext;
    private readonly IWebHostEnvironment _webHostEnvironment;
    /// <summary>The name of the controller.</summary>
    public const string Name = "Settings";

    /// <summary>Creates an instance of <see cref="SettingsController"/>.</summary>
    /// <param name="dbContext"><see cref="Microsoft.EntityFrameworkCore.DbContext"/> for the Identity Framework.</param>
    /// <param name="webHostEnvironment">Provides information about the web hosting environment an application is running in.</param>
    public SettingsController(IAppSettingsDbContext dbContext, IWebHostEnvironment webHostEnvironment) {
        _appSettingsDbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _webHostEnvironment = webHostEnvironment ?? throw new ArgumentNullException(nameof(webHostEnvironment));
    }

    /// <summary>Returns a list of <see cref="AppSettingInfo"/> objects containing the total number of application settings in the database and the data filtered according to the provided <see cref="ListOptions"/>.</summary>
    /// <param name="options">List parameters used to navigate through collections. Contains parameters such as sort, search, page number and page size.</param>
    /// <response code="200">OK</response>
    [HttpGet]
    [ProducesResponseType(statusCode: StatusCodes.Status200OK, type: typeof(ResultSet<AppSettingInfo>))]
    public async Task<IActionResult> GetSettings([FromQuery] ListOptions options) {
        var query = _appSettingsDbContext.AppSettings.AsNoTracking().AsQueryable();
        if (!string.IsNullOrEmpty(options.Search)) {
            var searchTerm = options.Search.ToLower();
            query = query.Where(x => x.Key.ToLower().Contains(searchTerm));
        }
        var settings = await query.Select(x => new AppSettingInfo {
            Key = x.Key,
            Value = x.Value
        })
        .ToResultSetAsync(options);
        return Ok(settings);
    }

    /// <summary>Loads the appsettings.json file and saves the configuration in the database.</summary>
    /// <param name="hardRefresh">If set, deletes the existing settings and imports from appsettings.json files.</param>
    /// <response code="204">No Content</response>
    [ApiExplorerSettings(IgnoreApi = true)]
    [HttpPost("load")]
    [ProducesResponseType(statusCode: StatusCodes.Status204NoContent, type: typeof(void))]
    public async Task<IActionResult> LoadFromAppSettings([FromQuery] bool hardRefresh = false) {
        if (!_webHostEnvironment.IsDevelopment()) {
            return NotFound();
        }
        var fileInfo = _webHostEnvironment.ContentRootFileProvider.GetFileInfo("appsettings.json");
        var settingsExist = await _appSettingsDbContext.AppSettings.AnyAsync();
        if (settingsExist && !hardRefresh) {
            return BadRequest(new ValidationProblemDetails {
                Detail = "App settings are already loaded in the database."
            });
        }
        IDictionary<string, string> settings;
        using (var stream = fileInfo.CreateReadStream()) {
            settings = JsonConfigurationFileParser.Parse(stream);
        }
        if (settingsExist) {
            await _dbContext.Database.ExecuteSqlRawAsync($"TRUNCATE TABLE [{AppSetting.TableSchema}].[{nameof(AppSetting)}];");
        }
        await _appSettingsDbContext.AppSettings.AddRangeAsync(settings.Select(x => new AppSetting {
            Key = x.Key,
            Value = x.Value
        }));
        await _dbContext.SaveChangesAsync();
        return NoContent();
    }

    /// <summary>Gets an application setting by it's key.</summary>
    /// <param name="key">The key of the setting.</param>
    /// <response code="200">OK</response>
    /// <response code="404">Not Found</response>
    [ProducesResponseType(statusCode: StatusCodes.Status200OK, type: typeof(AppSettingInfo))]
    [ProducesResponseType(statusCode: StatusCodes.Status404NotFound, type: typeof(ProblemDetails))]
    [HttpGet("{key}")]
    public async Task<IActionResult> GetSetting([FromRoute] string key) {
        var setting = await _appSettingsDbContext.AppSettings.AsNoTracking().Select(x => new AppSettingInfo {
            Key = x.Key,
            Value = x.Value
        })
        .SingleOrDefaultAsync(x => x.Key == key);
        if (setting == null) {
            return NotFound();
        }
        return Ok(setting);
    }

    /// <summary>Creates a new application setting.</summary>
    /// <param name="request">Contains info about the application setting to be created.</param>
    /// <response code="201">Created</response>
    [HttpPost]
    [ProducesResponseType(statusCode: StatusCodes.Status201Created, type: typeof(AppSettingInfo))]
    public async Task<IActionResult> CreateSetting([FromBody] CreateAppSettingRequest request) {
        var setting = new AppSetting {
            Key = request.Key,
            Value = request.Value
        };
        _appSettingsDbContext.AppSettings.Add(setting);
        await _dbContext.SaveChangesAsync();
        return CreatedAtAction(nameof(GetSetting), Name, new { key = setting.Key }, new AppSettingInfo {
            Key = setting.Key,
            Value = setting.Value
        });
    }

    /// <summary>Updates an existing application setting.</summary>
    /// <param name="key">The key of the setting to update.</param>
    /// <param name="request">Contains info about the application setting to update.</param>
    /// <response code="200">OK</response>
    /// <response code="404">Not Found</response>
    [HttpPut("{key}")]
    [ProducesResponseType(statusCode: StatusCodes.Status200OK, type: typeof(AppSettingInfo))]
    [ProducesResponseType(statusCode: StatusCodes.Status404NotFound, type: typeof(ProblemDetails))]
    public async Task<IActionResult> UpdateSetting([FromRoute] string key, [FromBody] UpdateAppSettingRequest request) {
        var setting = await _appSettingsDbContext.AppSettings.SingleOrDefaultAsync(x => x.Key == key);
        if (setting == null) {
            return NotFound();
        }
        setting.Value = request.Value;
        // Commit changes to database.
        await _dbContext.SaveChangesAsync();
        // Send the response.
        return Ok(new AppSettingInfo {
            Key = setting.Key,
            Value = setting.Value
        });
    }

    /// <summary>Permanently deletes an application setting.</summary>
    /// <param name="key">The key of the setting.</param>
    /// <response code="204">No Content</response>
    /// <response code="404">Not Found</response>
    [HttpDelete("{key}")]
    [ProducesResponseType(statusCode: StatusCodes.Status204NoContent, type: typeof(void))]
    [ProducesResponseType(statusCode: StatusCodes.Status404NotFound, type: typeof(ProblemDetails))]
    public async Task<IActionResult> DeleteSetting([FromRoute] string key) {
        var setting = await _appSettingsDbContext.AppSettings.AsNoTracking().SingleOrDefaultAsync(x => x.Key == key);
        if (setting == null) {
            return NotFound();
        }
        _appSettingsDbContext.AppSettings.Remove(setting);
        await _dbContext.SaveChangesAsync();
        return NoContent();
    }
}
